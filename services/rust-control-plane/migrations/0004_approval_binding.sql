-- Approval binding and single-use consumption.
--
-- An approval is only meaningful if it is bound to the policy version that
-- produced it, carries a unique nonce, and can be consumed exactly once. The
-- previous schema allowed an approved row to be executed repeatedly and kept no
-- record of what policy decided it.
--
-- `policy_version` is backfilled from the parent task: every approval created
-- before this migration was written with the task's policy version.

ALTER TABLE task_approvals
    DROP CONSTRAINT task_approvals_status_check;

ALTER TABLE task_approvals
    ADD CONSTRAINT task_approvals_status_check CHECK (status IN (
        'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED'
    ));

ALTER TABLE task_approvals
    ADD COLUMN policy_version TEXT,
    ADD COLUMN nonce          UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN consumed_at    TIMESTAMPTZ,
    ADD COLUMN consumed_by    UUID;

UPDATE task_approvals AS approval
SET policy_version = task.policy_version
FROM tasks AS task
WHERE approval.task_id = task.id;

ALTER TABLE task_approvals
    ALTER COLUMN policy_version SET NOT NULL;

-- A nonce is the durable uniqueness token for one approval. A replay that
-- reuses an id or nonce cannot create a second usable record.
CREATE UNIQUE INDEX task_approvals_nonce_idx ON task_approvals (nonce);

-- Consumption metadata is all-or-nothing: a CONSUMED row must say when and by
-- whom, and no other state may carry consumption metadata.
ALTER TABLE task_approvals
    ADD CONSTRAINT task_approvals_consumed_check CHECK (
        (status = 'CONSUMED') = (consumed_at IS NOT NULL)
    );

-- Only one approved-but-unconsumed approval may exist per task, so a task
-- cannot accumulate parallel approvals for the same action.
CREATE UNIQUE INDEX task_approvals_approved_idx
    ON task_approvals (task_id)
    WHERE status = 'APPROVED';
