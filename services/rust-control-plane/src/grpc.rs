//! Authenticated internal gRPC task authority.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::auth::JwtVerifier;
use crate::persistence::PrincipalStore;
use crate::policy::POLICY_VERSION;
use crate::proto::{task_service_server::TaskService, CreateTaskRequest, CreateTaskResponse};
use crate::task::{NewTask, TaskStatus, TaskStore, TaskStoreError};

pub struct TaskGrpcService {
    verifier: Arc<JwtVerifier>,
    principal_store: Arc<dyn PrincipalStore>,
    task_store: Arc<dyn TaskStore>,
}

impl TaskGrpcService {
    pub fn new(
        verifier: Arc<JwtVerifier>,
        principal_store: Arc<dyn PrincipalStore>,
        task_store: Arc<dyn TaskStore>,
    ) -> Self {
        Self {
            verifier,
            principal_store,
            task_store,
        }
    }

    async fn authenticate(
        &self,
        request: &Request<CreateTaskRequest>,
    ) -> Result<crate::principal::TenantContext, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("authorization metadata is required"))?;
        let identity = self
            .verifier
            .verify(token)
            .await
            .map_err(|_| Status::unauthenticated("invalid credentials"))?;
        let resolved = self
            .principal_store
            .resolve(&identity.issuer, &identity.subject, &identity.tenant_id)
            .await
            .map_err(|_| Status::unavailable("authorization store unavailable"))?
            .ok_or_else(|| Status::permission_denied("tenant membership is required"))?;
        Ok(crate::principal::TenantContext { identity, resolved })
    }
}

#[tonic::async_trait]
impl TaskService for TaskGrpcService {
    async fn create_task(
        &self,
        request: Request<CreateTaskRequest>,
    ) -> Result<Response<CreateTaskResponse>, Status> {
        let context = self.authenticate(&request).await?;
        if !context
            .resolved
            .permissions
            .iter()
            .any(|permission| permission == "task:write")
        {
            return Err(Status::permission_denied(
                "task:write permission is required",
            ));
        }
        let idempotency_key = request
            .metadata()
            .get("x-idempotency-key")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Status::invalid_argument("idempotency metadata is required"))?
            .to_string();
        let request = request.into_inner();
        if request.title.trim().is_empty() || request.title.len() > 256 {
            return Err(Status::invalid_argument("task title is required"));
        }

        let task = self
            .task_store
            .insert(NewTask {
                id: Uuid::new_v4(),
                tenant_id: context.resolved.tenant_id,
                principal_id: context.resolved.principal_id,
                title: request.title,
                input: request.description,
                policy_version: POLICY_VERSION.into(),
                idempotency_key: Some(idempotency_key),
                status: TaskStatus::Ready,
            })
            .await
            .map_err(task_status)?;
        let created_at = task.0.created_at;
        Ok(Response::new(CreateTaskResponse {
            task_id: task.0.id.to_string(),
            status: task.0.status.as_str().to_string(),
            created_at: Some(prost_types::Timestamp {
                seconds: created_at.timestamp(),
                nanos: created_at.timestamp_subsec_nanos() as i32,
            }),
        }))
    }
}

fn task_status(error: TaskStoreError) -> Status {
    match error {
        TaskStoreError::Database(_) => Status::unavailable("task store unavailable"),
        TaskStoreError::NotFound => Status::not_found("task not found"),
        TaskStoreError::InvalidApprovalArguments => {
            Status::invalid_argument("invalid approval arguments")
        }
        TaskStoreError::SelfApproval => Status::permission_denied("self-approval is not allowed"),
        TaskStoreError::StateConflict
        | TaskStoreError::ApprovalConflict
        | TaskStoreError::ApprovalConsumed
        | TaskStoreError::ApprovalExpired
        | TaskStoreError::PolicyDrift => Status::failed_precondition("task state conflict"),
        TaskStoreError::Corrupt => Status::internal("task persistence failed"),
    }
}
