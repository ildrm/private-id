CREATE TABLE IF NOT EXISTS billing_customers(account_id uuid PRIMARY KEY,stripe_customer_id text UNIQUE NOT NULL,email text,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS subscriptions(id text PRIMARY KEY,account_id uuid NOT NULL,plan_id text NOT NULL,status text NOT NULL,current_period_end timestamptz,cancel_at_period_end boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS subscriptions_account_idx ON subscriptions(account_id,status);
CREATE TABLE IF NOT EXISTS payments(id text PRIMARY KEY,account_id uuid NOT NULL,amount bigint NOT NULL,currency char(3) NOT NULL,status text NOT NULL,invoice_id text,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS stripe_events(id text PRIMARY KEY,type text NOT NULL,processed_at timestamptz NOT NULL DEFAULT now());
