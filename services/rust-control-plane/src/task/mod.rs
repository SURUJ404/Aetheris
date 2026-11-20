//! Durable task lifecycle and approval binding.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Created,
    WaitingApproval,
    Ready,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::WaitingApproval => "WAITING_APPROVAL",
            Self::Ready => "READY",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "CREATED" => Some(Self::Created),
            "WAITING_APPROVAL" => Some(Self::WaitingApproval),
            "READY" => Some(Self::Ready),
            "RUNNING" => Some(Self::Running),
            "COMPLETED" => Some(Self::Completed),
            "FAILED" => Some(Self::Failed),
            "CANCELLED" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::WaitingApproval)
                | (Self::Created, Self::Ready)
                | (Self::Created, Self::Cancelled)
                | (Self::WaitingApproval, Self::Ready)
                | (Self::WaitingApproval, Self::Cancelled)
                | (Self::Ready, Self::Running)
                | (Self::Ready, Self::Cancelled)
                | (Self::Running, Self::Completed)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::Cancelled)
        )
    }
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Consumed,
}

impl ApprovalStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Expired => "EXPIRED",
            Self::Consumed => "CONSUMED",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "PENDING" => Some(Self::Pending),
            "APPROVED" => Some(Self::Approved),
            "REJECTED" => Some(Self::Rejected),
            "EXPIRED" => Some(Self::Expired),
            "CONSUMED" => Some(Self::Consumed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub title: String,
    pub input: String,
    pub status: TaskStatus,
    pub policy_version: String,
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub failure: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub id: Uuid,
    pub task_id: Uuid,
    pub tenant_id: String,
    pub proposer_principal_id: Uuid,
    pub tool_name: String,
    pub arguments_json: String,
    pub action_hash: String,
    /// Policy version in force when the approval was created. An approval
    /// issued under different rules must not execute under the current ones.
    pub policy_version: String,
    /// Unique per approval: a replay cannot present a second usable record.
    pub nonce: Uuid,
    pub status: ApprovalStatus,
    pub expires_at: DateTime<Utc>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub consumed_by: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct NewTask {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub title: String,
    pub input: String,
    pub policy_version: String,
    pub idempotency_key: Option<String>,
    pub status: TaskStatus,
}

#[derive(Debug, Clone)]
pub struct NewApproval {
    pub id: Uuid,
    pub task_id: Uuid,
    pub tenant_id: String,
    pub proposer_principal_id: Uuid,
    pub tool_name: String,
    pub arguments_json: String,
    pub action_hash: String,
    pub policy_version: String,
    pub nonce: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum TaskStoreError {
    #[error("task not found")]
    NotFound,
    #[error("task state conflict")]
    StateConflict,
    #[error("approval is not pending")]
    ApprovalConflict,
    #[error("approval has already been consumed")]
    ApprovalConsumed,
    #[error("approval has expired")]
    ApprovalExpired,
    #[error("approval was issued under a different policy version")]
    PolicyDrift,
    #[error("approval arguments are not an approved action")]
    InvalidApprovalArguments,
    #[error("approver must differ from proposer")]
    SelfApproval,
    #[error("stored task state is corrupt")]
    Corrupt,
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
}

#[async_trait]
pub trait TaskStore: Send + Sync {
    async fn insert(&self, task: NewTask) -> Result<(TaskRecord, bool), TaskStoreError>;
    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<TaskRecord>, TaskStoreError>;
    /// Fetch one approval, scoped to both tenant and task.
    async fn get_approval(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
    ) -> Result<Option<ApprovalRecord>, TaskStoreError>;
    async fn transition(
        &self,
        tenant_id: &str,
        id: Uuid,
        from: TaskStatus,
        to: TaskStatus,
        failure: Option<String>,
    ) -> Result<TaskRecord, TaskStoreError>;
    async fn add_approval(&self, approval: NewApproval) -> Result<ApprovalRecord, TaskStoreError>;
    async fn approve(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
        approver: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(ApprovalRecord, TaskRecord), TaskStoreError>;
    /// Atomically consume an approved record and move its task from `READY` to
    /// `RUNNING`.
    ///
    /// Consumption happens exactly once. A second call for the same approval
    /// returns [`TaskStoreError::ApprovalConsumed`] whether or not the task has
    /// finished, so a replay can never dispatch a second execution.
    async fn consume_approval(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
        consumer: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(ApprovalRecord, TaskRecord), TaskStoreError>;
}

/// Largest stdin an approval may bind. Matches the default execution ceiling;
/// the broker still rejects a request whose limits are below the actual input.
pub const MAX_APPROVAL_STDIN_BYTES: usize = 1024 * 1024;

pub fn canonical_action_hash(
    tool_name: &str,
    arguments_json: &str,
) -> Result<(String, String), TaskStoreError> {
    if tool_name.is_empty() || tool_name.len() > 128 {
        return Err(TaskStoreError::Corrupt);
    }
    let value: serde_json::Value =
        serde_json::from_str(arguments_json).map_err(|_| TaskStoreError::Corrupt)?;
    if !value.is_object() {
        return Err(TaskStoreError::Corrupt);
    }
    let canonical = serde_json::to_string(&value).map_err(|_| TaskStoreError::Corrupt)?;
    let hash = action_hash(tool_name, &canonical);
    Ok((canonical, hash))
}

/// Canonicalise the action an approval binds.
///
/// The approved surface is deliberately tiny: the only argument a caller may
/// bind is `stdin`, a UTF-8 string. Anything else — a path, a command, an
/// environment variable — is rejected now rather than interpreted later. This
/// keeps the hash a faithful description of everything the sandbox will see.
pub fn canonical_approval_hash(
    tool_name: &str,
    arguments: &serde_json::Value,
) -> Result<(String, String), TaskStoreError> {
    if tool_name.is_empty() || tool_name.len() > 128 {
        return Err(TaskStoreError::InvalidApprovalArguments);
    }
    let object = arguments
        .as_object()
        .ok_or(TaskStoreError::InvalidApprovalArguments)?;
    if object.keys().any(|key| key != "stdin") {
        return Err(TaskStoreError::InvalidApprovalArguments);
    }
    if let Some(value) = object.get("stdin") {
        let text = value
            .as_str()
            .ok_or(TaskStoreError::InvalidApprovalArguments)?;
        if text.len() > MAX_APPROVAL_STDIN_BYTES {
            return Err(TaskStoreError::InvalidApprovalArguments);
        }
    }
    let canonical =
        serde_json::to_string(arguments).map_err(|_| TaskStoreError::InvalidApprovalArguments)?;
    let hash = action_hash(tool_name, &canonical);
    Ok((canonical, hash))
}

/// Extract the approved stdin from a canonical argument object.
pub fn approved_stdin(arguments_json: &str) -> Result<String, TaskStoreError> {
    let value: serde_json::Value =
        serde_json::from_str(arguments_json).map_err(|_| TaskStoreError::Corrupt)?;
    let object = value.as_object().ok_or(TaskStoreError::Corrupt)?;
    match object.get("stdin") {
        None => Ok(String::new()),
        Some(value) => value
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or(TaskStoreError::Corrupt),
    }
}

fn action_hash(tool_name: &str, canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update([0]);
    hasher.update(canonical.as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Default)]
pub struct MemoryTaskStore {
    tasks: Mutex<BTreeMap<Uuid, TaskRecord>>,
    approvals: Mutex<BTreeMap<Uuid, ApprovalRecord>>,
}

impl MemoryTaskStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TaskStore for MemoryTaskStore {
    async fn insert(&self, new: NewTask) -> Result<(TaskRecord, bool), TaskStoreError> {
        let mut tasks = self.tasks.lock().expect("task store lock");
        if let Some(existing) = tasks.values().find(|task| {
            task.tenant_id == new.tenant_id
                && new.idempotency_key.is_some()
                && task.idempotency_key == new.idempotency_key
        }) {
            return Ok((existing.clone(), false));
        }
        let now = Utc::now();
        let task = TaskRecord {
            id: new.id,
            tenant_id: new.tenant_id,
            principal_id: new.principal_id,
            title: new.title,
            input: new.input,
            status: new.status,
            policy_version: new.policy_version,
            idempotency_key: new.idempotency_key,
            created_at: now,
            updated_at: now,
            finished_at: None,
            failure: None,
        };
        tasks.insert(task.id, task.clone());
        Ok((task, true))
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<TaskRecord>, TaskStoreError> {
        Ok(self
            .tasks
            .lock()
            .expect("task store lock")
            .get(&id)
            .filter(|task| task.tenant_id == tenant_id)
            .cloned())
    }

    async fn get_approval(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
    ) -> Result<Option<ApprovalRecord>, TaskStoreError> {
        Ok(self
            .approvals
            .lock()
            .expect("approval store lock")
            .get(&approval_id)
            .filter(|approval| approval.tenant_id == tenant_id && approval.task_id == task_id)
            .cloned())
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
        let mut tasks = self.tasks.lock().expect("task store lock");
        let task = tasks.get_mut(&id).ok_or(TaskStoreError::NotFound)?;
        if task.tenant_id != tenant_id || task.status != from {
            return Err(TaskStoreError::StateConflict);
        }
        task.status = to;
        task.updated_at = Utc::now();
        task.failure = failure;
        if to.is_terminal() {
            task.finished_at = Some(task.updated_at);
        }
        Ok(task.clone())
    }

    async fn add_approval(&self, approval: NewApproval) -> Result<ApprovalRecord, TaskStoreError> {
        let task = self
            .get(&approval.tenant_id, approval.task_id)
            .await?
            .ok_or(TaskStoreError::NotFound)?;
        if task.status != TaskStatus::WaitingApproval {
            return Err(TaskStoreError::StateConflict);
        }
        let record = ApprovalRecord {
            id: approval.id,
            task_id: approval.task_id,
            tenant_id: approval.tenant_id,
            proposer_principal_id: approval.proposer_principal_id,
            tool_name: approval.tool_name,
            arguments_json: approval.arguments_json,
            action_hash: approval.action_hash,
            policy_version: approval.policy_version,
            nonce: approval.nonce,
            status: ApprovalStatus::Pending,
            expires_at: approval.expires_at,
            approved_by: None,
            approved_at: None,
            consumed_at: None,
            consumed_by: None,
        };
        let mut approvals = self.approvals.lock().expect("approval store lock");
        if approvals
            .values()
            .any(|existing| existing.nonce == record.nonce)
        {
            return Err(TaskStoreError::Corrupt);
        }
        approvals.insert(record.id, record.clone());
        Ok(record)
    }

    async fn approve(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
        approver: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(ApprovalRecord, TaskRecord), TaskStoreError> {
        let current = self
            .get(tenant_id, task_id)
            .await?
            .ok_or(TaskStoreError::NotFound)?;
        let approval = {
            let mut approvals = self.approvals.lock().expect("approval store lock");
            let approval = approvals
                .get_mut(&approval_id)
                .ok_or(TaskStoreError::NotFound)?;
            if approval.tenant_id != tenant_id || approval.task_id != task_id {
                return Err(TaskStoreError::NotFound);
            }
            if approval.proposer_principal_id == approver {
                return Err(TaskStoreError::SelfApproval);
            }
            if approval.status != ApprovalStatus::Pending {
                return Err(TaskStoreError::ApprovalConflict);
            }
            if approval.expires_at <= now {
                approval.status = ApprovalStatus::Expired;
                return Err(TaskStoreError::ApprovalExpired);
            }
            if current.status != TaskStatus::WaitingApproval {
                return Err(TaskStoreError::StateConflict);
            }
            approval.status = ApprovalStatus::Approved;
            approval.approved_by = Some(approver);
            approval.approved_at = Some(now);
            approval.clone()
        };
        let task = self
            .transition(
                tenant_id,
                task_id,
                TaskStatus::WaitingApproval,
                TaskStatus::Ready,
                None,
            )
            .await?;
        Ok((approval, task))
    }

    async fn consume_approval(
        &self,
        tenant_id: &str,
        task_id: Uuid,
        approval_id: Uuid,
        consumer: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(ApprovalRecord, TaskRecord), TaskStoreError> {
        // Policy drift is decided before the approval is burned: an approval
        // issued under different rules must stay APPROVED for audit, not be
        // silently discarded by a failed attempt under the current rules.
        let task = self
            .get(tenant_id, task_id)
            .await?
            .ok_or(TaskStoreError::NotFound)?;
        let approval = {
            let mut approvals = self.approvals.lock().expect("approval store lock");
            let approval = approvals
                .get_mut(&approval_id)
                .ok_or(TaskStoreError::NotFound)?;
            if approval.tenant_id != tenant_id || approval.task_id != task_id {
                return Err(TaskStoreError::NotFound);
            }
            if approval.policy_version != task.policy_version {
                return Err(TaskStoreError::PolicyDrift);
            }
            match approval.status {
                ApprovalStatus::Approved => {}
                ApprovalStatus::Consumed => return Err(TaskStoreError::ApprovalConsumed),
                ApprovalStatus::Expired => return Err(TaskStoreError::ApprovalExpired),
                ApprovalStatus::Pending | ApprovalStatus::Rejected => {
                    return Err(TaskStoreError::ApprovalConflict)
                }
            }
            if approval.expires_at <= now {
                approval.status = ApprovalStatus::Expired;
                return Err(TaskStoreError::ApprovalExpired);
            }
            if task.status != TaskStatus::Ready {
                return Err(TaskStoreError::StateConflict);
            }
            let arguments: serde_json::Value = serde_json::from_str(&approval.arguments_json)
                .map_err(|_| TaskStoreError::Corrupt)?;
            let (canonical, action_hash) = canonical_approval_hash(&approval.tool_name, &arguments)
                .map_err(|_| TaskStoreError::Corrupt)?;
            if canonical != approval.arguments_json || action_hash != approval.action_hash {
                return Err(TaskStoreError::Corrupt);
            }
            approval.status = ApprovalStatus::Consumed;
            approval.consumed_at = Some(now);
            approval.consumed_by = Some(consumer);
            approval.clone()
        };

        let task = self
            .transition(
                tenant_id,
                task_id,
                TaskStatus::Ready,
                TaskStatus::Running,
                None,
            )
            .await?;
        Ok((approval, task))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(tenant: &str, principal_id: Uuid, status: TaskStatus) -> NewTask {
        NewTask {
            id: Uuid::new_v4(),
            tenant_id: tenant.into(),
            principal_id,
            title: "test".into(),
            input: "{}".into(),
            policy_version: "test".into(),
            idempotency_key: Some("same-request".into()),
            status,
        }
    }

    #[test]
    fn canonical_hash_is_independent_of_object_key_order() {
        let left = canonical_action_hash("math.add", r#"{"b":2,"a":1}"#).unwrap();
        let right = canonical_action_hash("math.add", r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(left, right);
    }

    #[tokio::test]
    async fn idempotency_and_tenant_scoping_are_enforced() {
        let store = MemoryTaskStore::new();
        let principal = Uuid::new_v4();
        let first = store
            .insert(task("tenant-a", principal, TaskStatus::Ready))
            .await
            .unwrap();
        assert!(first.1);
        let duplicate = store
            .insert(task("tenant-a", principal, TaskStatus::Ready))
            .await
            .unwrap();
        assert!(!duplicate.1);
        assert_eq!(first.0.id, duplicate.0.id);
        assert!(store.get("tenant-b", first.0.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn approval_lookup_is_scoped_to_tenant_and_task() {
        let store = MemoryTaskStore::new();
        let principal = Uuid::new_v4();
        let created = store
            .insert(task("tenant-a", principal, TaskStatus::WaitingApproval))
            .await
            .unwrap()
            .0;
        let (arguments_json, action_hash) =
            canonical_approval_hash("echo", &serde_json::json!({"stdin": "hi"})).unwrap();
        let approval = store
            .add_approval(NewApproval {
                id: Uuid::new_v4(),
                task_id: created.id,
                tenant_id: "tenant-a".into(),
                proposer_principal_id: principal,
                tool_name: "echo".into(),
                arguments_json,
                action_hash,
                policy_version: "test".into(),
                nonce: Uuid::new_v4(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
            .await
            .unwrap();

        assert!(store
            .get_approval("tenant-a", created.id, approval.id)
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_approval("tenant-b", created.id, approval.id)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_approval("tenant-a", Uuid::new_v4(), approval.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn approval_is_single_use_and_rejects_self_approval() {
        let store = MemoryTaskStore::new();
        let proposer = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let created = store
            .insert(task("tenant-a", proposer, TaskStatus::WaitingApproval))
            .await
            .unwrap()
            .0;
        let (arguments_json, action_hash) =
            canonical_approval_hash("math.add", &serde_json::json!({"stdin": "1 2"})).unwrap();
        let approval = store
            .add_approval(NewApproval {
                id: Uuid::new_v4(),
                task_id: created.id,
                tenant_id: "tenant-a".into(),
                proposer_principal_id: proposer,
                tool_name: "math.add".into(),
                arguments_json,
                action_hash,
                policy_version: "test".into(),
                nonce: Uuid::new_v4(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
            .await
            .unwrap();

        assert!(matches!(
            store
                .approve("tenant-a", created.id, approval.id, proposer, Utc::now())
                .await,
            Err(TaskStoreError::SelfApproval)
        ));
        let (_, ready) = store
            .approve("tenant-a", created.id, approval.id, approver, Utc::now())
            .await
            .unwrap();
        assert_eq!(ready.status, TaskStatus::Ready);
        assert!(matches!(
            store
                .approve(
                    "tenant-a",
                    created.id,
                    approval.id,
                    Uuid::new_v4(),
                    Utc::now()
                )
                .await,
            Err(TaskStoreError::ApprovalConflict)
        ));
    }

    #[tokio::test]
    async fn consumed_approval_cannot_be_replayed() {
        let store = MemoryTaskStore::new();
        let proposer = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let consumer = Uuid::new_v4();
        let created = store
            .insert(task("tenant-a", proposer, TaskStatus::WaitingApproval))
            .await
            .unwrap()
            .0;
        let (arguments_json, action_hash) =
            canonical_approval_hash("math.add", &serde_json::json!({"stdin": "1 2"})).unwrap();
        let approval = store
            .add_approval(NewApproval {
                id: Uuid::new_v4(),
                task_id: created.id,
                tenant_id: "tenant-a".into(),
                proposer_principal_id: proposer,
                tool_name: "math.add".into(),
                arguments_json,
                action_hash,
                policy_version: "test".into(),
                nonce: Uuid::new_v4(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
            .await
            .unwrap();
        store
            .approve("tenant-a", created.id, approval.id, approver, Utc::now())
            .await
            .unwrap();

        let (consumed, running) = store
            .consume_approval("tenant-a", created.id, approval.id, consumer, Utc::now())
            .await
            .unwrap();
        assert_eq!(consumed.status, ApprovalStatus::Consumed);
        assert_eq!(consumed.consumed_by, Some(consumer));
        assert_eq!(running.status, TaskStatus::Running);

        assert!(matches!(
            store
                .consume_approval("tenant-a", created.id, approval.id, consumer, Utc::now())
                .await,
            Err(TaskStoreError::ApprovalConsumed)
        ));
    }

    #[tokio::test]
    async fn invalid_state_transition_is_rejected() {
        let store = MemoryTaskStore::new();
        let record = store
            .insert(task("tenant-a", Uuid::new_v4(), TaskStatus::Created))
            .await
            .unwrap()
            .0;
        assert!(matches!(
            store
                .transition(
                    "tenant-a",
                    record.id,
                    TaskStatus::Created,
                    TaskStatus::Completed,
                    None
                )
                .await,
            Err(TaskStoreError::StateConflict)
        ));
    }
}
