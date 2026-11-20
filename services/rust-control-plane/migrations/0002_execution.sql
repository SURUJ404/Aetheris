-- Durable execution state.
--
-- PostgreSQL is the source of truth for sandbox executions. Redis may cache a
-- status for convenience, but a row here is the only authoritative record.
-- Every transition is compare-and-set on (tenant_id, id, status) so two actors
-- cannot advance the same execution.

CREATE TABLE executions (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- Not a foreign key: principals can be deleted while the audit trail must
    -- survive. The id is still the immutable audit reference.
    principal_id        UUID NOT NULL,
    task_id             TEXT NOT NULL,
    runtime             TEXT NOT NULL
                        CHECK (runtime IN ('wasmtime', 'firecracker')),
    workload            TEXT NOT NULL,
    status              TEXT NOT NULL
                        CHECK (status IN (
                            'CREATED', 'QUEUED', 'AUTHORIZED', 'STARTING',
                            'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT',
                            'CANCELLED', 'CLEANING_UP'
                        )),
    policy_version      TEXT NOT NULL,
    -- Effective limits, as validated by the broker. JSONB keeps the record
    -- readable without pinning a schema for future limit kinds.
    limits              JSONB NOT NULL,
    idempotency_key     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    exit_code           INTEGER,
    failure_kind        TEXT,
    failure_message     TEXT,
    cancel_requested_at TIMESTAMPTZ,
    duration_ms         BIGINT,
    fuel_consumed       BIGINT,
    memory_peak_bytes   BIGINT,
    -- Bounded captured output (ceiling is the execution's max_output_bytes)
    -- plus a digest of the exact bytes, which survives lossy UTF-8 decoding.
    output_digest       TEXT,
    stdout              TEXT,
    stderr              TEXT,
    -- Name/size/digest only. Artifact bytes never enter the database.
    artifacts           JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- Idempotent submission: one execution per (tenant, client key). NULL keys are
-- excluded because a request without a key is never deduplicated.
CREATE UNIQUE INDEX executions_idempotency_key_idx
    ON executions (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX executions_tenant_created_idx
    ON executions (tenant_id, created_at DESC);

-- Startup recovery scans only in-flight rows.
CREATE INDEX executions_inflight_idx
    ON executions (status)
    WHERE status NOT IN ('COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED');

-- Append-only transition log. This is what makes the lifecycle auditable: the
-- row shows the current status, this table shows how it got there.
CREATE TABLE execution_events (
    id           BIGSERIAL PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES executions (id) ON DELETE CASCADE,
    tenant_id    TEXT NOT NULL,
    from_status  TEXT,
    to_status    TEXT NOT NULL,
    reason       TEXT,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX execution_events_execution_idx
    ON execution_events (execution_id, id);
