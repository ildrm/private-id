CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text UNIQUE NOT NULL, password_hash text NOT NULL, email_verified boolean NOT NULL DEFAULT false, mfa_enabled boolean NOT NULL DEFAULT false, status text NOT NULL DEFAULT 'ACTIVE', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS credentials (id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), type text NOT NULL, claims jsonb NOT NULL, issuer text NOT NULL, assurance_level text NOT NULL, issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz);
CREATE INDEX IF NOT EXISTS credentials_user_status_idx ON credentials(user_id, revoked_at, expires_at);
CREATE TABLE IF NOT EXISTS proof_requests (id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), client_id text NOT NULL, requested_claims text[] NOT NULL, status text NOT NULL, created_at timestamptz NOT NULL, decided_at timestamptz);
CREATE TABLE IF NOT EXISTS consents (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), proof_request_id uuid NOT NULL REFERENCES proof_requests(id), decision text NOT NULL, claims text[] NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions (id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz, ip_hash text);
CREATE TABLE IF NOT EXISTS audit_log (id bigserial PRIMARY KEY, event text NOT NULL, actor_id text, target_id text, metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
