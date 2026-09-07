-- Run as database owner after migrations. Create separate LOGIN users securely,
-- then GRANT privateid_runtime or privateid_retention to the appropriate user.
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='privateid_runtime') THEN CREATE ROLE privateid_runtime NOLOGIN; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='privateid_retention') THEN CREATE ROLE privateid_retention NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO privateid_runtime, privateid_retention;
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'pid_%' AND tablename <> 'pid_audit' LOOP
 EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO privateid_runtime', t);
 END LOOP;
END $$;
GRANT SELECT, INSERT ON pid_audit TO privateid_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON pid_audit FROM privateid_runtime;
GRANT SELECT ON schema_migrations, runtime_state, billing_customers, users TO privateid_runtime;
GRANT EXECUTE ON FUNCTION privateid_purge_audit(timestamptz,integer) TO privateid_retention;
