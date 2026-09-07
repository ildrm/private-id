# Architecture

PrivateID v2 is a modular monolith. Fastify receives strict Zod input, authenticates the session, enforces browser origin/CSRF policy, delegates to a service, validates the public response, and returns a structured result. The same route definitions generate OpenAPI. React uses these public DTO types and isolated, abortable resource requests.

## Transaction boundaries

`AccountService`, `CredentialService`, `VerifierService`, `OrganizationService`, `ProofService`, and `BillingService` share the `Database` interface. Production uses `PostgresDatabase`: each unit of work runs at SERIALIZABLE isolation with bounded serialization/deadlock retries. Unique indexes protect normalized email and provider mappings. Mutations and their audit entries commit together. Authorization is re-read within the transaction, not trusted from a stale request object.

Each entity is a typed JSONB document in a `pid_*` table. Generated reference columns provide relational foreign keys; GIN and expression indexes support scoped queries and expiry/retry scans. The old mutable maps and whole-state persistence queue have been removed. The memory adapter is test-only and clones/commits atomically; it is not a production fallback.

External I/O stays outside transaction callbacks. Checkout uses a durable operation key and provider idempotency. Webhooks first commit a minimal inbox receipt, then a leased worker fetches current provider state. Projection updates, totals, continuation jobs, audit, and completion commit atomically. A failed commit remains retryable. Customer-level leases serialize common event/reconciliation paths; per-record provider versions prevent stale subscription/invoice projections.

## Proof authority

A request binds account, verifier, connection and issuer versions, requested claims, purpose, expiry and evidence sources. Approval resolves current evidence and checks the preview hash. Claims are nested beneath a protected token envelope. Higher assurance wins; conflicting claims at the highest applicable assurance reject issuance. Missing evidence produces an error, not a fabricated false value. Only `account_valid` derives from account state.

Verification/redeeming rechecks account status/version, client status/version, connection status/version, credential status/expiry, issuer authority/version, and current claim conclusions in the transaction. One-time redemption cannot succeed twice across replicas. Restoring access increments its version and cannot revive old proofs. Already disclosed information cannot be recalled from a relying party.

## Runtime and workers

The server validates configuration/schema/DB permissions, serves `/site/`, starts bounded background jobs, and drains on SIGTERM/SIGINT. Mail, billing, reconciliation, retention, and erasure jobs operate in batches. Leases and idempotency make ordinary replica overlap safe. The database is the authority; in-process route metrics are explicitly local to a replica. Health and worker indicators are separate.

The system remains a centralized issuer/verifier trust service. Operators can access database backups, and the service processes selected plaintext claims while signing. Encryption at rest is field encryption plus deployment storage controls, not cryptographic concealment from the operator. See [security](SECURITY.md) and [operations](docs/OPERATIONS.md).
