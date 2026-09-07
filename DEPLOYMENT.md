# Deployment

The supplied Compose file is a local development environment. It intentionally disables billing, uses development secrets, stores mail locally and publishes only on loopback. Do not promote its environment values into production.

## Production sequence

1. Build the pinned non-root image and run the complete CI checks. Use a dedicated PostgreSQL database, restricted network access, validated TLS, and encrypted backups.
2. Run `node dist/src/cli.js migrate` with the database-owner/migrator connection. Migrations are checksummed and advisory-locked. Never edit an applied SQL file; append a new migration.
3. Apply [database roles](ops/database-roles.sql) as the database owner. Create separate LOGIN users securely and grant `privateid_runtime` to the app user and `privateid_retention` to the scheduled retention user. Neither may inherit database-owner/superuser privileges. Keep the migrator credential out of the app container.
4. Configure HTTPS `SITE_URL` and `PRIVATEID_ISSUER`; explicit allowed origins/proxy ranges; verified PostgreSQL TLS; dedicated random subject/encryption secrets; mounted Ed25519 signing key and key ID; SMTP TLS and sender. All replicas share signing keys, subject secret and encryption key. Mount secrets read-only and readable by UID 1000. See the README variable table.
5. Complete legacy cutover if old data exists. Start v2 with `NODE_ENV=production`. Startup verifies checksums, rejects legacy snapshot data and refuses a DB role that can modify audits or invoke retention.
6. Verify `/ready`, static assets, email delivery, MFA and independent staff enrollment. Review real issuer/verifier procedures before approval. If billing is enabled, complete Stripe test-mode lifecycle checks before selecting live credentials.
7. Schedule audit retention with its separate connection, configure worker/error alerts and perform a backup/restore drill. Register an operational security-reporting contact.

Use a TLS reverse proxy with a request/body limit, explicit trusted source CIDRs and an origin allowlist. Set container resource limits and a termination grace period of at least 30 seconds. The process closes HTTP listeners, drains background work and closes PostgreSQL connections. Configure deployment-level retry/rollback behavior rather than restarting indefinitely through invalid configuration.

The server has per-process pool caps and general rate limits; authentication limits, replay state and billing jobs are shared in PostgreSQL. Sum connection pools across replicas before scaling. Do not claim a throughput tier from the local test result. Measure latency, lock contention, queue age, mail/provider latency and recovery under the intended workload.

[Operations](docs/OPERATIONS.md) covers cutover, keys, queues, retention and incident recovery. [Testing](TESTING.md) distinguishes implemented tests from deployment-specific release checks.
