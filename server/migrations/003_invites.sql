BEGIN;

CREATE TABLE IF NOT EXISTS org_invites (
    id text PRIMARY KEY,
    org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('administrator', 'operator', 'viewer', 'guest')),
    token_hash text UNIQUE NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_org_invites_org ON org_invites(org_id);
CREATE INDEX IF NOT EXISTS idx_org_invites_token ON org_invites(token_hash);

CREATE TABLE IF NOT EXISTS device_group_policies (
    group_id text PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
    require_2fa boolean NOT NULL DEFAULT true,
    max_session_duration_minutes integer NOT NULL DEFAULT 480,
    allow_clipboard boolean NOT NULL DEFAULT true,
    allow_file_transfer boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMIT;
