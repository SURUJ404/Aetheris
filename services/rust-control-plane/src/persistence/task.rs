use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::persistence::PgStore;
use crate::task::{
    ApprovalRecord, ApprovalStatus, NewApproval, NewTask, TaskRecord, TaskStatus, TaskStore,
    TaskStoreError,
};

#[derive(FromRow)]
struct TaskRow {
    id: Uuid,
    tenant_id: String,
    principal_id: Uuid,
    title: String,
    input: String,
    status: String,
    policy_version: String,
    idempotency_key: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    failure: Option<String>,
}

impl TryFrom<TaskRow> for TaskRecord {
    type Error = TaskStoreError;

    fn try_from(row: TaskRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            principal_id: row.principal_id,
            title: row.title,
            input: row.input,
            status: TaskStatus::parse(&row.status).ok_or(TaskStoreError::Corrupt)?,
            policy_version: row.policy_version,
            idempotency_key: row.idempotency_key,
            created_at: row.created_at,
            updated_at: row.updated_at,
            finished_at: row.finished_at,
            failure: row.failure,
        })
    }
}

#[derive(FromRow)]
struct ApprovalRow {
    id: Uuid,
    task_id: Uuid,
    tenant_id: String,
    proposer_principal_id: Uuid,
    tool_name: String,
    arguments_json: String,
    action_hash: String,
    policy_version: String,
    nonce: Uuid,
    status: String,
    expires_at: DateTime<Utc>,
    approved_by: Option<Uuid>,
    approved_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    consumed_by: Option<Uuid>,
}

impl TryFrom<ApprovalRow> for ApprovalRecord {
    type Error = TaskStoreError;

    fn try_from(row: ApprovalRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            task_id: row.task_id,
            tenant_id: row.tenant_id,
            proposer_principal_id: row.proposer_principal_id,
            tool_name: row.tool_name,
            arguments_json: row.arguments_json,
            action_hash: row.action_hash,
            policy_version: row.policy_version,
            nonce: row.nonce,
            status: ApprovalStatus::parse(&row.status).ok_or(TaskStoreError::Corrupt)?,
            expires_at: row.expires_at,
            approved_by: row.approved_by,
            approved_at: row.approved_at,
            consumed_at: row.consumed_at,
            consumed_by: row.consumed_by,
        })
    }
}

#[async_trait::async_trait]
impl TaskStore for PgStore {
    async fn insert(&self, new: NewTask) -> Result<(TaskRecord, bool), TaskStoreError> {
        let mut tx = self.pool().begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO tasks \
             (id, tenant_id, principal_id, title, input, status, policy_version, idempotency_key) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        )
        .bind(new.id)
        .bind(&new.tenant_id)
        .bind(new.principal_id)
        .bind(&new.title)
        .bind(&new.input)
        .bind(new.status.as_str())
        .bind(&new.policy_version)
        .bind(new.idempotency_key.as_deref())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;

        let row: TaskRow = if inserted {
            sqlx::query_as::<_, TaskRow>(
                "SELECT id, tenant_id, principal_id, title, input, status, policy_version, \
                 idempotency_key, created_at, updated_at, finished_at, failure \
                 FROM tasks WHERE id = $1",
            )
            .bind(new.id)
            .fetch_one(&mut *tx)
            .await?
        } else {
            sqlx::query_as::<_, TaskRow>(
                "SELECT id, tenant_id, principal_id, title, input, status, policy_version, \
                 idempotency_key, created_at, updated_at, finished_at, failure \
                 FROM tasks WHERE tenant_id = $1 AND idempotency_key = $2",
            )
            .bind(&new.tenant_id)
            .bind(new.idempotency_key.as_deref())
            .fetch_one(&mut *tx)
            .await?
        };
        tx.commit().await?;
        Ok((row.try_into()?, inserted))
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<TaskRecord>, TaskStoreError> {
        sqlx::query_as::<_, TaskRow>(
            "SELECT id, tenant_id, principal_id, title, input, status, policy_version, \
             idempotency_key, created_at, updated_at, finished_at, failure \
             FROM tasks WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(self.pool())
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn get_approval(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
    ) -> Result<Option<ApprovalRecord>, TaskStoreError> {
        sqlx::query_as::<_, ApprovalRow>(
            "SELECT id, task_id, tenant_id, proposer_principal_id, tool_name, \
                  arguments_json, action_hash, policy_version, nonce, status, expires_at, \
                  approved_by, approved_at, consumed_at, consumed_by \
              FROM task_approvals WHERE tenant_id = $1 AND task_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(approval_id)
        .fetch_optional(self.pool())
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn transition(
        &self,
        tenant_id: &str,
        id: Uuid,
        from: TaskStatus,
        to: TaskStatus,
        failure: Option<String>,
    ) -> Result<TaskRecord, TaskStoreError> {
        if !from.can_transition_to(to) {
            return Err(TaskStoreError::StateConflict);
        }
        let row: Option<TaskRow> = sqlx::query_as(
            "UPDATE tasks SET status = $4, updated_at = now(), \
             finished_at = CASE WHEN $4 IN ('COMPLETED', 'FAILED', 'CANCELLED') \
                 THEN now() ELSE finished_at END, failure = $5 \
             WHERE tenant_id = $1 AND id = $2 AND status = $3 \
             RETURNING id, tenant_id, principal_id, title, input, status, policy_version, \
                 idempotency_key, created_at, updated_at, finished_at, failure",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(from.as_str())
        .bind(to.as_str())
        .bind(failure)
        .fetch_optional(self.pool())
        .await?;
        row.ok_or(TaskStoreError::StateConflict)?.try_into()
    }

    async fn add_approval(&self, approval: NewApproval) -> Result<ApprovalRecord, TaskStoreError> {
        let mut tx = self.pool().begin().await?;
        let task_status: Option<(String,)> =
            sqlx::query_as("SELECT status FROM tasks WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
                .bind(&approval.tenant_id)
                .bind(approval.task_id)
                .fetch_optional(&mut *tx)
                .await?;
        let status = task_status
            .as_ref()
            .and_then(|(status,)| TaskStatus::parse(status));
        if status != Some(TaskStatus::WaitingApproval) {
            return Err(TaskStoreError::StateConflict);
        }

        let row: ApprovalRow = sqlx::query_as(
            "INSERT INTO task_approvals \
             (id, task_id, tenant_id, proposer_principal_id, tool_name, arguments_json, \
              action_hash, policy_version, nonce, status, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'PENDING', $10) \
             RETURNING id, task_id, tenant_id, proposer_principal_id, tool_name, \
                 arguments_json, action_hash, policy_version, nonce, status, expires_at, \
                 approved_by, approved_at, consumed_at, consumed_by",
        )
        .bind(approval.id)
        .bind(approval.task_id)
        .bind(&approval.tenant_id)
        .bind(approval.proposer_principal_id)
        .bind(&approval.tool_name)
        .bind(&approval.arguments_json)
        .bind(&approval.action_hash)
        .bind(&approval.policy_version)
        .bind(approval.nonce)
        .bind(approval.expires_at)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        row.try_into()
    }

    async fn approve(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
        approver: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(ApprovalRecord, TaskRecord), TaskStoreError> {
        let mut tx = self.pool().begin().await?;
        let row: ApprovalRow = sqlx::query_as(
            "SELECT id, task_id, tenant_id, proposer_principal_id, tool_name, \
                 arguments_json, action_hash, policy_version, nonce, status, expires_at, \
                 approved_by, approved_at, consumed_at, consumed_by \
             FROM task_approvals WHERE tenant_id = $1 AND task_id = $2 AND id = $3 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(approval_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(TaskStoreError::NotFound)?;
        let current: ApprovalRecord = row.try_into()?;
        if current.proposer_principal_id == approver {
            return Err(TaskStoreError::SelfApproval);
        }
        if current.status != ApprovalStatus::Pending {
            return Err(TaskStoreError::ApprovalConflict);
        }
        if current.expires_at <= now {
            sqlx::query(
                "UPDATE task_approvals SET status = 'EXPIRED' \
                 WHERE tenant_id = $1 AND task_id = $2 AND id = $3",
            )
            .bind(tenant_id)
            .bind(task_id)
            .bind(approval_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(TaskStoreError::ApprovalExpired);
        }

        let approved: ApprovalRow = sqlx::query_as(
            "UPDATE task_approvals SET status = 'APPROVED', approved_by = $4, approved_at = $5 \
             WHERE tenant_id = $1 AND task_id = $2 AND id = $3 \
             RETURNING id, task_id, tenant_id, proposer_principal_id, tool_name, \
                 arguments_json, action_hash, policy_version, nonce, status, expires_at, \
                 approved_by, approved_at, consumed_at, consumed_by",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(approval_id)
        .bind(approver)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        let task: TaskRow = sqlx::query_as(
            "UPDATE tasks SET status = 'READY', updated_at = $3 \
             WHERE tenant_id = $1 AND id = $2 AND status = 'WAITING_APPROVAL' \
             RETURNING id, tenant_id, principal_id, title, input, status, policy_version, \
                 idempotency_key, created_at, updated_at, finished_at, failure",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(TaskStoreError::StateConflict)?;
        tx.commit().await?;
        Ok((approved.try_into()?, task.try_into()?))
    }

    async fn consume_approval(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
        consumer: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(ApprovalRecord, TaskRecord), TaskStoreError> {
        let mut tx = self.pool().begin().await?;
        let row: ApprovalRow = sqlx::query_as(
            "SELECT id, task_id, tenant_id, proposer_principal_id, tool_name, \
                 arguments_json, action_hash, policy_version, nonce, status, expires_at, \
                 approved_by, approved_at, consumed_at, consumed_by \
             FROM task_approvals WHERE tenant_id = $1 AND task_id = $2 AND id = $3 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(approval_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(TaskStoreError::NotFound)?;
        let current: ApprovalRecord = row.try_into()?;

        let task_policy: Option<(String, String)> = sqlx::query_as(
            "SELECT status, policy_version FROM tasks \
             WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(task_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (task_status, policy_version) = task_policy.ok_or(TaskStoreError::NotFound)?;
        if current.policy_version != policy_version {
            return Err(TaskStoreError::PolicyDrift);
        }
        match current.status {
            ApprovalStatus::Approved => {}
            ApprovalStatus::Consumed => return Err(TaskStoreError::ApprovalConsumed),
            ApprovalStatus::Expired => return Err(TaskStoreError::ApprovalExpired),
            ApprovalStatus::Pending | ApprovalStatus::Rejected => {
                return Err(TaskStoreError::ApprovalConflict);
            }
        }
        if current.expires_at <= now {
            sqlx::query(
                "UPDATE task_approvals SET status = 'EXPIRED' \
                 WHERE tenant_id = $1 AND task_id = $2 AND id = $3",
            )
            .bind(tenant_id)
            .bind(task_id)
            .bind(approval_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(TaskStoreError::ApprovalExpired);
        }
        let arguments: serde_json::Value =
            serde_json::from_str(&current.arguments_json).map_err(|_| TaskStoreError::Corrupt)?;
        let (canonical, action_hash) =
            crate::task::canonical_approval_hash(&current.tool_name, &arguments)
                .map_err(|_| TaskStoreError::Corrupt)?;
        if canonical != current.arguments_json || action_hash != current.action_hash {
            return Err(TaskStoreError::Corrupt);
        }
        if task_status != TaskStatus::Ready.as_str() {
            return Err(TaskStoreError::StateConflict);
        }

        let consumed: ApprovalRow = sqlx::query_as(
            "UPDATE task_approvals SET status = 'CONSUMED', consumed_at = $4, consumed_by = $5 \
             WHERE tenant_id = $1 AND task_id = $2 AND id = $3 AND status = 'APPROVED' \
             RETURNING id, task_id, tenant_id, proposer_principal_id, tool_name, \
                 arguments_json, action_hash, policy_version, nonce, status, expires_at, \
                 approved_by, approved_at, consumed_at, consumed_by",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(approval_id)
        .bind(now)
        .bind(consumer)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(TaskStoreError::ApprovalConflict)?;
        let task: TaskRow = sqlx::query_as(
            "UPDATE tasks SET status = 'RUNNING', updated_at = $3 \
             WHERE tenant_id = $1 AND id = $2 AND status = 'READY' \
             RETURNING id, tenant_id, principal_id, title, input, status, policy_version, \
                 idempotency_key, created_at, updated_at, finished_at, failure",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(TaskStoreError::StateConflict)?;
        tx.commit().await?;
        Ok((consumed.try_into()?, task.try_into()?))
    }
}
