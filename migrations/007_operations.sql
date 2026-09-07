CREATE INDEX pid_mail_retry ON pid_mail((data->>'status'), (data->>'nextAttemptAt'));
CREATE INDEX pid_audit_time ON pid_audit((data->>'createdAt'));
CREATE INDEX pid_metadata_kind ON pid_metadata((data->'value'->>'kind'));
CREATE INDEX pid_credentials_status_expiry ON pid_credentials((data->>'status'), (data->>'expiresAt'));
CREATE INDEX pid_accounts_status ON pid_accounts((data->>'status'), (data->>'deletedAt'));
-- Retention is available only to an explicitly granted operational role.
-- Runtime connections must not own the tables or have UPDATE/DELETE on pid_audit.
CREATE OR REPLACE FUNCTION privateid_prevent_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('privateid.retention', true) = 'authorized'
    AND current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.pid_audit'::regclass)
  THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Audit records are append-only';
END $$;
CREATE FUNCTION privateid_purge_audit(cutoff timestamptz, batch_size integer DEFAULT 1000)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE removed integer;
BEGIN
  IF cutoff > now() - interval '30 days' OR batch_size NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'Audit retention requires a cutoff at least 30 days old and a batch of 1..1000';
  END IF;
  PERFORM set_config('privateid.retention', 'authorized', true);
  DELETE FROM public.pid_audit WHERE id IN (
    SELECT id FROM public.pid_audit WHERE data->>'createdAt' < to_char(cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') ORDER BY id LIMIT batch_size
  );
  GET DIAGNOSTICS removed = ROW_COUNT;
  PERFORM set_config('privateid.retention', '', true);
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION privateid_purge_audit(timestamptz, integer) FROM PUBLIC;
