CREATE TABLE pid_disputes(id text PRIMARY KEY, data jsonb NOT NULL CHECK(jsonb_typeof(data)='object' AND data->>'id'=id), account_id text GENERATED ALWAYS AS (data->>'accountId') STORED REFERENCES pid_accounts(id));
CREATE INDEX ON pid_disputes USING gin(data jsonb_path_ops);
REVOKE ALL ON pid_disputes FROM PUBLIC;
