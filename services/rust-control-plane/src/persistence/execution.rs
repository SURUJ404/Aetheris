//! PostgreSQL implementation of [`ExecutionStore`].
//!
//! The SQL here is the durable half of the execution lifecycle:
//! - `insert` is idempotent on `(tenant_id, idempotency_key)`;
//! - `transition` is compare-and-set on the current status;
//! - every write also appends to `execution_events`, so how a row reached its
//!   status is auditable rather than inferred;
//! - `recover_interrupted` fails rows that outlived their process.
//!
//! Messages never include SQL, row values or connection strings.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::execution::{
    ArtifactRef, ExecutionLimits, ExecutionRecord, ExecutionStatus, ExecutionStore,
    ExecutionStoreError, NewExecution, RuntimeKind, TransitionPatch,
};
use crate::persistence::PgStore;

/// Full row projection. Kept as one literal so sqlx 0.9 can prove it is not
/// dynamically assembled; changing it is a deliberate schema change.
const SELECT_BY_ID: &str = "SELECT \
    id, tenant_id, principal_id, task_id, runtime, workload, status, \
    policy_version, limits, idempotency_key, created_at, started_at, \
    finished_at, exit_code, failure_kind, failure_message, \
    cancel_requested_at, duration_ms, fuel_consumed, memory_peak_bytes, \
    output_digest, stdout, stderr, artifacts \
    FROM executions WHERE tenant_id = $1 AND id = $2";

const SELECT_BY_KEY: &str = "SELECT \
    id, tenant_id, principal_id, task_id, runtime, workload, status, \
    policy_version, limits, idempotency_key, created_at, started_at, \
    finished_at, exit_code, failure_kind, failure_message, \
    cancel_requested_at, duration_ms, fuel_consumed, memory_peak_bytes, \
    output_digest, stdout, stderr, artifacts \
    FROM executions WHERE tenant_id = $1 AND idempotency_key = $2";

/// In-flight rows only. The status list mirrors the Rust state machine and the
/// partial index predicate.
const SELECT_INFLIGHT: &str = "SELECT id, tenant_id, status FROM executions \
    WHERE status NOT IN ('COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED') \
    FOR UPDATE";

#[derive(FromRow)]
struct ExecutionRow {
    id: Uuid,
    tenant_id: String,
    principal_id: Uuid,
    task_id: String,
    runtime: String,
    workload: String,
    status: String,
    policy_version: String,
    limits: serde_json::Value,
    idempotency_key: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    failure_kind: Option<String>,
    failure_message: Option<String>,
    cancel_requested_at: Option<DateTime<Utc>>,
    duration_ms: Option<i64>,
    fuel_consumed: Option<i64>,
    memory_peak_bytes: Option<i64>,
    output_digest: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    artifacts: serde_json::Value,
}

impl ExecutionRow {
    fn into_record(self) -> Result<ExecutionRecord, ExecutionStoreError> {
        let runtime = RuntimeKind::parse(&self.runtime).ok_or(ExecutionStoreError::Corrupt)?;
        let status = ExecutionStatus::parse(&self.status).ok_or(ExecutionStoreError::Corrupt)?;
        let limits: ExecutionLimits =
            serde_json::from_value(self.limits).map_err(|_| ExecutionStoreError::Corrupt)?;
        let artifacts: Vec<ArtifactRef> =
            serde_json::from_value(self.artifacts).map_err(|_| ExecutionStoreError::Corrupt)?;

        Ok(ExecutionRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            principal_id: self.principal_id,
            task_id: self.task_id,
            runtime,
            workload: self.workload,
            status,
            policy_version: self.policy_version,
            limits,
            idempotency_key: self.idempotency_key,
            created_at: self.created_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            exit_code: self.exit_code,
            failure_kind: self.failure_kind,
            failure_message: self.failure_message,
            cancel_requested_at: self.cancel_requested_at,
            duration_ms: self.duration_ms,
            fuel_consumed: self.fuel_consumed,
            memory_peak_bytes: self.memory_peak_bytes,
            output_digest: self.output_digest,
            stdout: self.stdout,
            stderr: self.stderr,
            artifacts,
        })
    }
}

async fn record_event<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    execution_id: Uuid,
    tenant_id: &str,
    from: Option<ExecutionStatus>,
    to: ExecutionStatus,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO execution_events \
         (execution_id, tenant_id, from_status, to_status, reason) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(execution_id)
    .bind(tenant_id)
    .bind(from.map(ExecutionStatus::as_str))
    .bind(to.as_str())
    .bind(reason)
    .execute(executor)
    .await
    .map(|_| ())
}

#[async_trait::async_trait]
impl ExecutionStore for PgStore {
    async fn insert(
        &self,
        new: NewExecution,
    ) -> Result<(ExecutionRecord, bool), ExecutionStoreError> {
        let limits = serde_json::to_value(new.limits).map_err(|_| ExecutionStoreError::Corrupt)?;
        let mut tx = self.pool().begin().await?;

        let inserted = sqlx::query(
            "INSERT INTO executions \
             (id, tenant_id, principal_id, task_id, runtime, workload, status, \
              policy_version, limits, idempotency_key) \
             VALUES ($1, $2, $3, $4, $5, $6, 'CREATED', $7, $8, $9) \
             ON CONFLICT DO NOTHING",
        )
        .bind(new.id)
        .bind(&new.tenant_id)
        .bind(new.principal_id)
        .bind(&new.task_id)
        .bind(new.runtime.as_str())
        .bind(&new.workload)
        .bind(&new.policy_version)
        .bind(limits)
        .bind(new.idempotency_key.as_deref())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;

        let row: Option<ExecutionRow> = if inserted {
            sqlx::query_as(SELECT_BY_ID)
                .bind(&new.tenant_id)
                .bind(new.id)
                .fetch_optional(&mut *tx)
                .await?
        } else {
            // Only a duplicate idempotency key can reach this branch for a
            // freshly generated execution id.
            sqlx::query_as(SELECT_BY_KEY)
                .bind(&new.tenant_id)
                .bind(new.idempotency_key.as_deref())
                .fetch_optional(&mut *tx)
                .await?
        };

        let row = row.ok_or(ExecutionStoreError::Corrupt)?;

        if inserted {
            record_event(
                &mut *tx,
                row.id,
                &row.tenant_id,
                None,
                ExecutionStatus::Created,
                Some("created"),
            )
            .await?;
        }

        tx.commit().await?;
        Ok((row.into_record()?, inserted))
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ExecutionRecord>, ExecutionStoreError> {
        let row: Option<ExecutionRow> = sqlx::query_as(SELECT_BY_ID)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await?;

        row.map(ExecutionRow::into_record).transpose()
    }

    async fn transition(
        &self,
        tenant_id: &str,
        id: Uuid,
        from: ExecutionStatus,
        to: ExecutionStatus,
        patch: TransitionPatch,
    ) -> Result<(), ExecutionStoreError> {
        if !from.can_transition_to(to) {
            return Err(ExecutionStoreError::InvalidTransition { from, to });
        }

        let artifacts = match patch.artifacts.as_ref() {
            Some(artifacts) => {
                Some(serde_json::to_value(artifacts).map_err(|_| ExecutionStoreError::Corrupt)?)
            }
            None => None,
        };

        let mut tx = self.pool().begin().await?;

        let updated = sqlx::query(
            "UPDATE executions SET \
                 status = $4, \
                 started_at = COALESCE($5, started_at), \
                 finished_at = COALESCE($6, finished_at), \
                 exit_code = COALESCE($7, exit_code), \
                 failure_kind = COALESCE($8, failure_kind), \
                 failure_message = COALESCE($9, failure_message), \
                 duration_ms = COALESCE($10, duration_ms), \
                 fuel_consumed = COALESCE($11, fuel_consumed), \
                 memory_peak_bytes = COALESCE($12, memory_peak_bytes), \
                 output_digest = COALESCE($13, output_digest), \
                 stdout = COALESCE($14, stdout), \
                 stderr = COALESCE($15, stderr), \
                 artifacts = COALESCE($16, artifacts) \
             WHERE tenant_id = $1 AND id = $2 AND status = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(from.as_str())
        .bind(to.as_str())
        .bind(patch.started_at)
        .bind(patch.finished_at)
        .bind(patch.exit_code)
        .bind(patch.failure_kind.as_deref())
        .bind(patch.failure_message.as_deref())
        .bind(patch.duration_ms)
        .bind(patch.fuel_consumed)
        .bind(patch.memory_peak_bytes)
        .bind(patch.output_digest.as_deref())
        .bind(patch.stdout.as_deref())
        .bind(patch.stderr.as_deref())
        .bind(artifacts)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if updated != 1 {
            // Roll back the (empty) transaction and report the race.
            tx.rollback().await?;
            return Err(ExecutionStoreError::StateConflict { id, expected: from });
        }

        record_event(
            &mut *tx,
            id,
            tenant_id,
            Some(from),
            to,
            patch.failure_kind.as_deref(),
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn request_cancel(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ExecutionStatus>, ExecutionStoreError> {
        let row: Option<(String,)> = sqlx::query_as(
            "UPDATE executions \
             SET cancel_requested_at = COALESCE(cancel_requested_at, now()) \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING status",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(self.pool())
        .await?;

        match row {
            Some((status,)) => ExecutionStatus::parse(&status)
                .map(Some)
                .ok_or(ExecutionStoreError::Corrupt),
            None => Ok(None),
        }
    }

    async fn recover_interrupted(&self) -> Result<Vec<Uuid>, ExecutionStoreError> {
        let mut tx = self.pool().begin().await?;

        let rows: Vec<(Uuid, String, String)> =
            sqlx::query_as(SELECT_INFLIGHT).fetch_all(&mut *tx).await?;

        for (id, tenant_id, status) in &rows {
            sqlx::query(
                "UPDATE executions SET \
                     status = 'FAILED', \
                     failure_kind = 'interrupted', \
                     failure_message = $3, \
                     finished_at = now() \
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(id)
            .bind(tenant_id)
            .bind("control plane restarted while the execution was in flight")
            .execute(&mut *tx)
            .await?;

            let from = ExecutionStatus::parse(status).ok_or(ExecutionStoreError::Corrupt)?;
            record_event(
                &mut *tx,
                *id,
                tenant_id,
                Some(from),
                ExecutionStatus::Failed,
                Some("interrupted"),
            )
            .await?;
        }

        tx.commit().await?;
        Ok(rows.into_iter().map(|(id, _, _)| id).collect())
    }
}
