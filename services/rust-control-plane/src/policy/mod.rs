//! Deterministic authorization policy.
//!
//! Input: a [`TenantContext`] resolved from a validated token and PostgreSQL
//! membership data, plus the [`Action`] a caller wants to perform.
//!
//! Output: an allow only when the membership role grants the action's required
//! permission. Everything else is a deny. There is no implicit allow, no
//! wildcard, and no fallback to token claims.
//!
//! This module deliberately has no I/O. The same evaluation runs in-process
//! before the broker dispatches a tool, and behind `/v1/authorize` for clients
//! that need to know whether an action is available. A decision is advisory to
//! clients; the broker must re-evaluate at execution time.

use std::fmt;

use crate::principal::TenantContext;

/// A capability a role can grant.
///
/// Permissions are the stable vocabulary between role grants, policy, and the
/// audit trail. They are defined here as an enum so a typo cannot silently
/// create or check an unseeded grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read tenant metadata.
    TenantRead,
    /// Change tenant settings.
    TenantManage,
    /// List tenant members.
    MemberRead,
    /// Invite, remove, or change member roles.
    MemberManage,
    /// Read tasks and runs.
    TaskRead,
    /// Create or modify tasks.
    TaskWrite,
    /// Invoke a tool through the broker.
    ToolInvoke,
    /// Approve a high-risk tool action.
    ToolApprove,
    /// Read audit records.
    AuditRead,
}

impl Permission {
    /// Every permission the platform currently understands.
    pub const ALL: [Permission; 9] = [
        Permission::TenantRead,
        Permission::TenantManage,
        Permission::MemberRead,
        Permission::MemberManage,
        Permission::TaskRead,
        Permission::TaskWrite,
        Permission::ToolInvoke,
        Permission::ToolApprove,
        Permission::AuditRead,
    ];

    /// Wire and database representation, e.g. `tool:invoke`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Permission::TenantRead => "tenant:read",
            Permission::TenantManage => "tenant:manage",
            Permission::MemberRead => "member:read",
            Permission::MemberManage => "member:manage",
            Permission::TaskRead => "task:read",
            Permission::TaskWrite => "task:write",
            Permission::ToolInvoke => "tool:invoke",
            Permission::ToolApprove => "tool:approve",
            Permission::AuditRead => "audit:read",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A domain action a caller may attempt.
///
/// The action vocabulary is intentionally smaller and more stable than the
/// permission model. Several actions may later require the same permission, or
/// a permission plus resource context; callers keep sending the action name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read tenant metadata.
    TenantRead,
    /// Change tenant settings.
    TenantManage,
    /// List tenant members.
    MemberRead,
    /// Manage tenant members.
    MemberManage,
    /// Read tasks.
    TaskRead,
    /// Create or modify tasks.
    TaskWrite,
    /// Invoke a tool.
    ToolInvoke,
    /// Approve a tool action.
    ToolApprove,
    /// Read audit records.
    AuditRead,
}

impl Action {
    /// Every action currently accepted by `/v1/authorize`.
    pub const ALL: [Action; 9] = [
        Action::TenantRead,
        Action::TenantManage,
        Action::MemberRead,
        Action::MemberManage,
        Action::TaskRead,
        Action::TaskWrite,
        Action::ToolInvoke,
        Action::ToolApprove,
        Action::AuditRead,
    ];

    /// Parse the canonical dotted name, e.g. `tool.invoke`.
    ///
    /// Parsing is exact and case-sensitive. Anything unknown is rejected by the
    /// caller rather than treated as a denied permission: an unknown action is a
    /// client bug, not an authorization decision.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tenant.read" => Some(Action::TenantRead),
            "tenant.manage" => Some(Action::TenantManage),
            "member.read" => Some(Action::MemberRead),
            "member.manage" => Some(Action::MemberManage),
            "task.read" => Some(Action::TaskRead),
            "task.write" => Some(Action::TaskWrite),
            "tool.invoke" => Some(Action::ToolInvoke),
            "tool.approve" => Some(Action::ToolApprove),
            "audit.read" => Some(Action::AuditRead),
            _ => None,
        }
    }

    /// Canonical dotted name used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::TenantRead => "tenant.read",
            Action::TenantManage => "tenant.manage",
            Action::MemberRead => "member.read",
            Action::MemberManage => "member.manage",
            Action::TaskRead => "task.read",
            Action::TaskWrite => "task.write",
            Action::ToolInvoke => "tool.invoke",
            Action::ToolApprove => "tool.approve",
            Action::AuditRead => "audit.read",
        }
    }

    /// Permission required to perform the action.
    pub const fn required_permission(self) -> Permission {
        match self {
            Action::TenantRead => Permission::TenantRead,
            Action::TenantManage => Permission::TenantManage,
            Action::MemberRead => Permission::MemberRead,
            Action::MemberManage => Permission::MemberManage,
            Action::TaskRead => Permission::TaskRead,
            Action::TaskWrite => Permission::TaskWrite,
            Action::ToolInvoke => Permission::ToolInvoke,
            Action::ToolApprove => Permission::ToolApprove,
            Action::AuditRead => Permission::AuditRead,
        }
    }
}

/// Why a request was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The membership role does not grant the required permission.
    MissingPermission,
    /// The resolved membership belongs to a different tenant than the token.
    ///
    /// This should be impossible with the current store, which filters by the
    /// token tenant. It is checked anyway so a future store bug cannot cross a
    /// tenant boundary.
    TenantMismatch,
}

impl DenyReason {
    /// Stable machine-readable code for API responses and audit records.
    pub const fn as_str(self) -> &'static str {
        match self {
            DenyReason::MissingPermission => "missing_permission",
            DenyReason::TenantMismatch => "tenant_mismatch",
        }
    }
}

/// Result of evaluating one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The role grants the required permission.
    Allow {
        /// Evaluated action.
        action: Action,
        /// Permission that authorized it.
        permission: Permission,
    },
    /// The request is denied. Denials are not errors; they are decisions.
    Deny {
        /// Evaluated action.
        action: Action,
        /// Permission the action required.
        permission: Permission,
        /// Why it was denied.
        reason: DenyReason,
    },
}

impl PolicyDecision {
    /// Whether the action is allowed.
    pub const fn is_allowed(self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }

    /// Denial reason, when denied.
    pub const fn deny_reason(self) -> Option<DenyReason> {
        match self {
            PolicyDecision::Deny { reason, .. } => Some(reason),
            PolicyDecision::Allow { .. } => None,
        }
    }
}

/// Stateless RBAC engine.
///
/// Kept as a type rather than a free function so a later ABAC or external engine
/// can replace it behind the same call site without touching handlers or the
/// broker. It holds no cache: every decision reads the request's resolved
/// permissions, so a suspended membership cannot keep working from stale state.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    /// Construct the default in-process engine.
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate one action for a resolved caller.
    pub fn evaluate(&self, context: &TenantContext, action: Action) -> PolicyDecision {
        let permission = action.required_permission();

        // Defense in depth: the store resolves only the token's tenant, but a
        // mismatched context must never be authorized.
        if context.resolved.tenant_id != context.identity.tenant_id {
            return PolicyDecision::Deny {
                action,
                permission,
                reason: DenyReason::TenantMismatch,
            };
        }

        if context.has_permission(permission.as_str()) {
            PolicyDecision::Allow { action, permission }
        } else {
            PolicyDecision::Deny {
                action,
                permission,
                reason: DenyReason::MissingPermission,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Permission};

    #[test]
    fn action_names_and_permissions_are_unique() {
        for (index, action) in Action::ALL.iter().enumerate() {
            assert!(Action::parse(action.as_str()).is_some());
            assert!(
                Action::ALL[..index]
                    .iter()
                    .all(|previous| previous.as_str() != action.as_str()),
                "duplicate action name"
            );
        }

        for (index, permission) in Permission::ALL.iter().enumerate() {
            assert!(
                Permission::ALL[..index]
                    .iter()
                    .all(|previous| previous.as_str() != permission.as_str()),
                "duplicate permission name"
            );
        }
    }

    #[test]
    fn action_parsing_is_exact() {
        assert_eq!(Action::parse("tool.invoke"), Some(Action::ToolInvoke));
        assert_eq!(Action::parse("Tool.Invoke"), None);
        assert_eq!(Action::parse("tool:invoke"), None);
        assert_eq!(Action::parse(""), None);
        assert_eq!(Action::parse("tool.delete"), None);
    }
}
