-- Identity and authorization data.
--
-- Keycloak proves who a caller is. This schema decides what they may do:
-- membership in a tenant, the role attached to that membership, and the
-- permissions granted to the role. Rust is the only writer and reader.

CREATE TABLE tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE principals (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE memberships (
    tenant_id    TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal_id)
);

CREATE INDEX memberships_principal_idx ON memberships (principal_id);

CREATE TABLE role_permissions (
    role       TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (role, permission)
);

INSERT INTO role_permissions (role, permission) VALUES
    ('owner',  'tenant:read'),
    ('owner',  'tenant:manage'),
    ('owner',  'member:read'),
    ('owner',  'member:manage'),
    ('owner',  'task:read'),
    ('owner',  'task:write'),
    ('owner',  'tool:invoke'),
    ('owner',  'tool:approve'),
    ('owner',  'audit:read'),

    ('admin',  'tenant:read'),
    ('admin',  'member:read'),
    ('admin',  'member:manage'),
    ('admin',  'task:read'),
    ('admin',  'task:write'),
    ('admin',  'tool:invoke'),
    ('admin',  'tool:approve'),
    ('admin',  'audit:read'),

    ('member', 'tenant:read'),
    ('member', 'task:read'),
    ('member', 'task:write'),
    ('member', 'tool:invoke'),

    ('viewer', 'tenant:read'),
    ('viewer', 'task:read');
