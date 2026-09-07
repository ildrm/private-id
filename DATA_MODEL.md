# Data model and retention

The authoritative runtime schema is the checksummed `pid_*` migration series. Rows have a primary-key `id` and strict, validated `data` document. All writes pass `src/models.ts`; malformed stored records fail validation rather than silently hydrating partial state. Generated SQL foreign keys connect sessions, credentials, requests, memberships, organizations and billing rows to their parents.

| Tables | Stored purpose |
| --- | --- |
| `accounts`, `sessions`, `challenges` | Canonical email, scrypt hash, status/version, encrypted MFA, recovery hashes; hashed random session/challenge secrets |
| `mail` | Encrypted challenge message, attempt count, status and retry time; content cleared after delivery |
| `organizations`, `memberships` | Scoped ownership and roles; one active organization per Business owner |
| `issuers`, `credentials` | Reviewed claim authority/policy and bounded credential assertions with encrypted external evidence references |
| `verifiers` | Exact redirect allowlist, purpose, allowed claims, hashed client secret, review/version/environment |
| `requests`, `access`, `usage` | Consent state/provenance, hashed code/proof, disclosure values, revocation versions, UTC monthly counters |
| `billing_customers`, `subscriptions`, `invoices`, `refunds`, `disputes`, `checkouts` | Provider references, effective subscription inputs, integer minor-unit amounts and durable checkout state |
| `billing_events` | Minimal signed-event receipt and durable processing state; no raw provider event body |
| `audit`, `metadata` | Append-only security history; bounded leases, rate buckets, currency aggregates and worker cursors |

## Lifecycle

| Data | Retention behavior |
| --- | --- |
| Session | Absolute expiry, default one hour; immediately invalidated by suspension, deletion, password/role change or explicit revocation |
| Verification/reset challenge | Single use; expires after 30 minutes; obsolete challenges are replaced |
| Email outbox | Content cleared on delivery; rows removed after one day |
| Proof / authorization code | Direct proof at most 300 seconds; authorization code/proof bound to at most 60 seconds; credential expiry can shorten either |
| Credential claims/evidence | Expires or is revoked; redacted 30 days after expiry/revocation |
| Consent | Configured `CONSENT_RETENTION_DAYS`, default 730; account erasure removes subject-owned requests earlier |
| Completed/ignored billing receipt | 30 days; failed receipts remain available for repair |
| Deleted account | Personal secrets/contact data removed after provider cancellation; stable pseudonymous tombstone prevents reactivation |
| Deleted-account financial references | 730 days, then bounded cleanup; aggregate currency totals contain no account identifier |
| Security audit | Operational purge at configured retention, default 365 days; runtime cannot delete/modify audits |
| Rate buckets | Hashed source/account keys; cleaned after one day |

Deletion is `ACTIVE → DELETION_PENDING → DELETED`. Pending deletion cannot authenticate, approve proofs, or create checkout. The worker waits five minutes, cancels provider checkouts/subscriptions and scrubs provider contact fields, then removes subject-owned private records and anonymizes the account. A provider failure leaves deletion pending for retry. Financial/audit records retain pseudonymous references only as documented. Closed/withdrawn issuer and verifier identifiers remain so historical references cannot be reassigned.

Audit records are append-only for the application role. The database owner and separately authorized retention function are outside that guarantee. Backups and legacy archives need separate expiry/access policies. Restores must replay tombstones and reconcile billing before traffic resumes. Default periods require operator review for the actual deployment; no legal sufficiency is implied.
