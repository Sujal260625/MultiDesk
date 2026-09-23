BEGIN;

ALTER TABLE device_sessions 
    ADD COLUMN IF NOT EXISTS recording_consent boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS chat_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS notes_count integer NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS email_tokens (
    token_hash text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('verify', 'reset')),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens(user_id);

CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_totp_backup_user ON totp_backup_codes(user_id);

COMMIT;
