BEGIN;
CREATE TABLE users (
 id text PRIMARY KEY,
 email text NOT NULL UNIQUE CHECK (email = lower(email)),
 display_name text NOT NULL,
 password_hash text NOT NULL,
 token_version bigint NOT NULL DEFAULT 0,
 email_verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE organizations (id text PRIMARY KEY, name text NOT NULL, owner_id text NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE memberships (organization_id text NOT NULL REFERENCES organizations(id), user_id text NOT NULL REFERENCES users(id), role text NOT NULL CHECK(role IN ('owner','administrator','operator','viewer','guest')), expires_at timestamptz, PRIMARY KEY(organization_id,user_id));
CREATE TABLE devices (id text PRIMARY KEY, name text NOT NULL, owner_id text NOT NULL REFERENCES users(id), organization_id text REFERENCES organizations(id), public_key bytea UNIQUE NOT NULL CHECK(octet_length(public_key)=32), os text NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX devices_by_owner ON devices(owner_id) WHERE revoked_at IS NULL;
CREATE TABLE device_groups (id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organizations(id), name text NOT NULL);
CREATE TABLE device_group_members (group_id text NOT NULL REFERENCES device_groups(id), device_id text NOT NULL REFERENCES devices(id), PRIMARY KEY(group_id,device_id));
CREATE TABLE trusted_operators (device_id text NOT NULL REFERENCES devices(id), operator_id text NOT NULL REFERENCES users(id), allowed_permissions text[] NOT NULL DEFAULT '{}', expires_at timestamptz, PRIMARY KEY(device_id,operator_id));
CREATE TABLE unattended_policies (device_id text PRIMARY KEY REFERENCES devices(id), enabled boolean NOT NULL DEFAULT false, credential_hash text, permissions text[] NOT NULL DEFAULT '{}', allowed_hours jsonb NOT NULL DEFAULT '{}', updated_at timestamptz NOT NULL DEFAULT now(), CHECK(NOT enabled OR credential_hash IS NOT NULL));
CREATE TABLE refresh_tokens (token_hash bytea PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), family_id text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz, revoked_at timestamptz);
CREATE INDEX refresh_family ON refresh_tokens(family_id);
CREATE TABLE device_sessions (id text PRIMARY KEY, operator_id text NOT NULL REFERENCES users(id), source_device_id text NOT NULL REFERENCES devices(id), target_device_id text NOT NULL REFERENCES devices(id), state text NOT NULL CHECK(state IN ('pending','active','rejected','closed','expired','revoked','disconnected')), requested_permissions text[] NOT NULL, granted_permissions text[] NOT NULL DEFAULT '{}', epoch bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, ended_at timestamptz, CHECK(source_device_id<>target_device_id), CHECK(granted_permissions <@ requested_permissions));
CREATE INDEX active_operator_sessions ON device_sessions(operator_id) WHERE state IN ('pending','active');
-- Controller changes also take a transaction-scoped advisory lock for the target device.
CREATE UNIQUE INDEX one_controller_per_device ON device_sessions(target_device_id) WHERE state='active' AND (granted_permissions && ARRAY['mouse','keyboard']::text[]);
CREATE TABLE audit_events (id text PRIMARY KEY, actor_id text REFERENCES users(id), organization_id text REFERENCES organizations(id), action text NOT NULL, resource_id text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}', occurred_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX audit_org_time ON audit_events(organization_id,occurred_at DESC);
CREATE TABLE session_notes (id text PRIMARY KEY, session_id text NOT NULL REFERENCES device_sessions(id), author_id text NOT NULL REFERENCES users(id), body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE transfer_metadata (id text PRIMARY KEY, session_id text NOT NULL REFERENCES device_sessions(id), basename text NOT NULL, size_bytes bigint NOT NULL CHECK(size_bytes>=0), sha256 bytea NOT NULL CHECK(octet_length(sha256)=32), state text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE workflows (id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organizations(id), name text NOT NULL, definition jsonb NOT NULL, required_permissions text[] NOT NULL, enabled boolean NOT NULL DEFAULT false, created_by text NOT NULL REFERENCES users(id));
CREATE TABLE workflow_runs (id text PRIMARY KEY, workflow_id text NOT NULL REFERENCES workflows(id), session_id text NOT NULL REFERENCES device_sessions(id), approved_by text REFERENCES users(id), state text NOT NULL, started_at timestamptz, finished_at timestamptz);
CREATE TABLE subscriptions (organization_id text PRIMARY KEY REFERENCES organizations(id), plan text NOT NULL, seat_limit integer NOT NULL CHECK(seat_limit>0), status text NOT NULL, provider_reference text, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE passkeys (credential_id bytea PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), public_key bytea NOT NULL, sign_count bigint NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE second_factors (id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), kind text NOT NULL, encrypted_secret bytea NOT NULL, verified_at timestamptz);
-- Do not store screen frames, audio, clipboard values, passwords, SDP or file bytes here.
COMMIT;
