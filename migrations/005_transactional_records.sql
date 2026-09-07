-- Row-level versioned documents with relational constraints and indexes.
-- Legacy tables are migration inputs only; runtime_state is no longer written.
DO $$
DECLARE entity text;
BEGIN
  FOREACH entity IN ARRAY ARRAY['accounts','sessions','challenges','mail','organizations','memberships','issuers','credentials','verifiers','requests','access','audit','usage','billing_customers','subscriptions','invoices','refunds','checkouts','billing_events','metadata'] LOOP
    EXECUTE format('CREATE TABLE pid_%I (id text PRIMARY KEY, data jsonb NOT NULL CHECK(jsonb_typeof(data) = ''object'' AND data->>''id'' = id))', entity);
    EXECUTE format('CREATE INDEX ON pid_%I USING gin(data jsonb_path_ops)', entity);
  END LOOP;
END $$;
CREATE UNIQUE INDEX pid_accounts_email_unique ON pid_accounts(lower(data->>'email'));
CREATE UNIQUE INDEX pid_session_secret_unique ON pid_sessions((data->>'tokenHash'));
CREATE UNIQUE INDEX pid_provider_customer_unique ON pid_billing_customers((data->>'stripeCustomerId'));
CREATE INDEX pid_sessions_expiry ON pid_sessions((data->>'expiresAt'));
CREATE INDEX pid_requests_expiry ON pid_requests((data->>'expiresAt'));
CREATE INDEX pid_challenges_expiry ON pid_challenges((data->>'expiresAt'));
CREATE INDEX pid_billing_events_retry ON pid_billing_events((data->>'status'), (data->>'nextAttemptAt'));
CREATE INDEX pid_credentials_subject ON pid_credentials((data->>'userId'), (data->>'expiresAt'));
CREATE UNIQUE INDEX pid_membership_unique ON pid_memberships((data->>'organizationId'),(data->>'userId'));
DO $$
DECLARE entity text;
BEGIN
  FOREACH entity IN ARRAY ARRAY['sessions','challenges','mail','credentials','requests','access','memberships'] LOOP
    EXECUTE format('ALTER TABLE pid_%I ADD COLUMN user_id text GENERATED ALWAYS AS (data->>''userId'') STORED REFERENCES pid_accounts(id)', entity);
  END LOOP;
  FOREACH entity IN ARRAY ARRAY['billing_customers','subscriptions','invoices','refunds','checkouts','usage'] LOOP
    EXECUTE format('ALTER TABLE pid_%I ADD COLUMN account_id text GENERATED ALWAYS AS (data->>''accountId'') STORED REFERENCES pid_accounts(id)', entity);
  END LOOP;
END $$;
ALTER TABLE pid_credentials ADD COLUMN issuer_id text GENERATED ALWAYS AS (data->>'issuerId') STORED REFERENCES pid_issuers(id);
ALTER TABLE pid_requests ADD COLUMN client_id text GENERATED ALWAYS AS (data->>'clientId') STORED REFERENCES pid_verifiers(id);
ALTER TABLE pid_access ADD COLUMN client_id text GENERATED ALWAYS AS (data->>'clientId') STORED REFERENCES pid_verifiers(id);
ALTER TABLE pid_memberships ADD COLUMN organization_id text GENERATED ALWAYS AS (data->>'organizationId') STORED REFERENCES pid_organizations(id);
ALTER TABLE pid_organizations ADD COLUMN owner_id text GENERATED ALWAYS AS (data->>'ownerId') STORED REFERENCES pid_accounts(id);
ALTER TABLE pid_issuers ADD COLUMN owner_id text GENERATED ALWAYS AS (data->>'ownerId') STORED REFERENCES pid_accounts(id);
ALTER TABLE pid_verifiers ADD COLUMN owner_id text GENERATED ALWAYS AS (data->>'ownerId') STORED REFERENCES pid_accounts(id);
CREATE FUNCTION privateid_prevent_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Audit records are append-only'; END $$;
CREATE TRIGGER pid_audit_immutable BEFORE UPDATE OR DELETE ON pid_audit FOR EACH ROW EXECUTE FUNCTION privateid_prevent_audit_change();
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
