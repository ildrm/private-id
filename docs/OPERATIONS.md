# Operations runbook

## Health, queues and alerts

`/health` reports a live process. `/ready` reports database availability after startup checks. Core API availability does not mean Stripe or SMTP is healthy. Inspect `/api/admin/overview` for pending review counts, failed mail, pending/failed billing receipts and the last worker tick; `/api/admin/metrics` provides per-process route counters and mean/max latency. Use structured logs with request IDs to correlate safe error codes. Do not enable body, cookie, password, client-secret, proof or raw webhook logging.

Suggested initial alert policy: page on sustained readiness failure or server-error increase; investigate worker heartbeat older than two minutes, any exhausted billing receipt, failed mail, and deletion jobs pending beyond the expected provider delay. Tune thresholds from measured traffic. Export process metrics to an external monitoring system for durable history and percentiles; the built-in counters are not a full monitoring backend.

Webhook intake acknowledges only after durable receipt insertion. Workers claim leases, retry with backoff and preserve failures. Fix provider price/API version, customer mapping or database problems before using Billing event operations to queue a retry. Current provider reads and per-record versions protect subscription/invoice state against old event deliveries. Reconciliation is paginated into durable jobs. Compare provider invoices/refunds and local per-currency totals after recovery. Re-deliver missed dispute events from the provider when needed; never invent financial records to make totals match.

Mail delivery is at least once across a crash at the delivery/commit boundary; the same message ID and single-use challenge make duplicates harmless. Failed rows can be retried by a controlled operator database update to PENDING after repairing SMTP, or customers can request a fresh link. Old outbox rows are removed after one day. Development JSON mail files are local artifacts; remove them when no longer needed.

## Legacy cutover

The old prototype stored identity data in `runtime_state` and billing in separate legacy tables. V2 does not run alongside that writer.

1. Stop **all** old API/worker instances. Take and verify an encrypted database backup and record the old image/configuration. Test this procedure on a restored copy first.
2. Apply v2 migrations with the migrator role. Select a fresh archive path on encrypted operator storage; keep `DATA_ENCRYPTION_KEY` secure and available for archive recovery.
3. Run the explicit offline import:

```sh
node --env-file=.env --import tsx src/cli.ts import-legacy --archive /secure/path/privateid-v1.archive --acknowledge-invalidations
```

In the compiled image use `node dist/src/cli.js` instead. The importer writes an encrypted archive with exclusive file creation, requires an empty v2 account target, rejects orphan billing customers and duplicate canonical email, then commits imported accounts/provider mappings. It deliberately invalidates sessions, existing proofs, inferred assurance, unverified mailbox flags, administrator grants and unreviewed applications. The old password hashes remain compatible. Inactive legacy accounts stay suspended; review their deletion/suspension history before restoring any access. Current subscriptions and amounts are reconciled from Stripe instead of trusting incorrect legacy amounts/statuses.

4. After commit, consumed runtime/billing legacy data is removed. If final cleanup fails, startup still refuses traffic. `node dist/src/cli.js finalize-cutover` only finalizes an already committed import; it does not replay account creation.
5. Users verify email again; staff enroll MFA and are granted authority operationally; issuers/verifiers receive new review. Confirm billing reconciliation before granting paid access. Verify account counts, mapping counts and sample customer journeys. Start v2 traffic only then.

The offline importer supports the prototype’s actual snapshot/billing representation and archives at most 50 MiB. Larger or manually populated alternate legacy schemas require a reviewed batch mapping; do not bypass the startup guard or discard unknown data. Keep the archive only for an approved recovery period. The historical normalized identity tables were unused by the baseline runtime; inspect them during the restored-copy drill if external scripts may have written to them.

Rollback before traffic: restore the verified pre-cutover backup and old image together. After v2 accepts writes, do not roll back only the executable; that would lose or resurrect authorization/deletion state. Reconcile the data and provider side effects with a reviewed recovery migration.

## Signing and encryption keys

Generate an Ed25519 pair with `npm run keygen -- --directory /secure/path/keys`. Private files are created mode 0600 and are not overwritten. Production mounts a PKCS8 private key and explicit unique key ID. To rotate signing keys, publish a JSON map of retained old key IDs to SPKI PEM public keys, mount the new private key/ID on all replicas, and retain old public keys until all old proofs/codes have expired (at least the configured maximum lifetime plus rollout overlap). Remove a compromised key immediately and revoke affected verifier/account authority as appropriate.

`PRIVATEID_SUBJECT_SECRET` is independent of signing keys. Preserve it to maintain pairwise subject continuity. Changing it is an identity remapping migration requiring relying-party coordination. `DATA_ENCRYPTION_KEY` protects MFA, evidence references and queued mail; changing it without re-encrypting existing fields makes them unreadable. Data-key rotation currently requires an offline, reviewed re-encryption migration and verified backup; do not simply replace the environment value. Keep encryption/subject/signing keys distinct and never log them.

## Retention, deletion and restore

The background worker expires sessions/challenges/credentials/requests, redacts evidence, cleans completed receipts and processes account erasure in bounded batches. Account deletion remains pending until provider cancellation succeeds; access is already revoked. Review pending jobs and retry provider failures. The separate audit job runs using only the retention database credential:

```sh
DATABASE_URL=postgres://retention_user:SECRET@database/privateid DATABASE_SSL=true AUDIT_RETENTION_DAYS=365 node dist/src/cli.js retention
```

Pass credentials through your secret manager in practice. One call deletes at most 1,000 expired audits, with a minimum 30-day safety cutoff. Schedule repeated batches sufficient for the daily event volume. The runtime role cannot execute this function or modify audit history. Consider a write-once external audit archive if database-owner tamper resistance is required.

Back up PostgreSQL plus required decryption/signing/subject secrets separately with access controls and tested restore. Maintain a restricted deletion-tombstone export beyond any backup that could resurrect an account. Restore into an isolated network, apply pending tombstones/suspensions, invalidate stale sessions/proofs as needed, reconcile Stripe, verify keys and worker state, then approve traffic. Document backup/archive expiry so erasure is not defeated by indefinite copies. Default retention values require deployment-specific privacy review.

## Incident procedure

Contain affected credentials or issuer/verifier authority; preserve redacted evidence; rotate compromised keys/secrets; inspect audit and durable events; restore or replay through documented transactions. Do not edit paid amounts or mark failed receipts APPLIED manually. After recovery, verify revocation, a one-time proof exchange, billing reconciliation and queue drainage with synthetic cases. Record the incident, remediation and remaining customer/provider actions.
