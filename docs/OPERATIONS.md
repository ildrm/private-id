# Operations runbook

## Release

Run `npm ci`, `npm run check`, build the Docker image, inject production environment variables from a secret manager, and deploy one independently versioned PrivateID image. The container runs migrations before accepting traffic. Route TLS traffic to port 3001 and preserve `/site/`, API routes, and `/webhooks/stripe` without modifying request bodies.

## Required production configuration

Set `DATABASE_URL`, `PRIVATEID_PROOF_SECRET` (at least 32 random characters), `PRIVATEID_ISSUER`, `SITE_URL`, database pool/TLS settings, and the five Stripe variables described in the billing guide. Use a dedicated PostgreSQL database and dedicated Stripe webhook endpoint.

## Monitoring and recovery

Probe `/health` for process health and `/ready` for readiness. Alert on 5xx rate, authentication failures, webhook failures, database pool exhaustion, and payment-failure growth. Back up PostgreSQL with point-in-time recovery and test restores. Rotating the proof secret invalidates outstanding proofs; plan that rotation. Stripe safely retries webhooks because stored event IDs are idempotent.

## Rollback

Deploy the previous image only when its schema is compatible with all applied migrations. Database migrations are additive and must be backed up before emergency manual intervention. Never share the database volume with another project.
