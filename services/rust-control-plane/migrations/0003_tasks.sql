CREATE TABLE tasks (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    principal_id    UUID NOT NULL,
    title           TEXT NOT NULL,
    input           TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN (
        'CREATED', 'WAITING_APPROVAL', 'READY', 'RUNNING',
        'COMPLETED', 'FAILED', 'CANCELLED'
    )),
    policy_version  TEXT NOT NULL,
    idempotency_key TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    failure         TEXT
);

CREATE UNIQUE INDEX tasks_idempotency_idx
    ON tasks (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX tasks_tenant_created_idx ON tasks (tenant_id, created_at DESC);

CREATE TABLE task_approvals (
    id                      UUID PRIMARY KEY,
    task_id                 UUID NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    tenant_id               TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    proposer_principal_id   UUID NOT NULL,
    tool_name               TEXT NOT NULL,
    arguments_json           TEXT NOT NULL,
    action_hash              TEXT NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN (
        'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'
    )),
    expires_at               TIMESTAMPTZ NOT NULL,
    approved_by              UUID,
    approved_at              TIMESTAMPTZ
);

CREATE UNIQUE INDEX task_approvals_pending_idx
    ON task_approvals (task_id)
    WHERE status = 'PENDING';

CREATE INDEX task_approvals_tenant_idx ON task_approvals (tenant_id, task_id);
