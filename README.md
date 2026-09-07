# PrivateID

PrivateID is a TypeScript identity wallet and consent service. Customers hold issuer-backed credentials, preview the exact claims an application requests, approve or deny disclosure, and revoke future access. The repository contains a **Fastify API, React/Vite interface, PostgreSQL persistence, and optional Stripe billing**. The directory name `iranbroker-next` is historical; this is not a Next.js brokerage application.

Version 0.2 replaces the prototype’s global JSON snapshot, automatic administrator bootstrap, and browser bearer storage. The API is version 2 and uses the `/api` prefix. Existing integrations must migrate; see [API and federation](API.md) and [legacy cutover](docs/OPERATIONS.md#legacy-cutover).

## What is implemented

- Verified email entry, password recovery/change, TOTP MFA, single-use recovery codes, public session IDs, and immediate session invalidation.
- Independently reviewed issuers and verifiers, scoped claim authority, encrypted evidence references, deterministic conflict detection, expiry, and credential revocation.
- Explicit consent with an exact-value preview; nested, short-lived signed claims; pairwise subjects; one-time redemption; online revocation checks; state, nonce, exact redirects, and S256 PKCE for browser federation.
- Customer wallet, consent history, connected applications, billing, account deletion, issuer/verifier workspaces, Business organizations, staff review, and security audit screens.
- Serializable PostgreSQL transactions, database uniqueness/foreign keys, append-only audit records, durable mail/webhook jobs, retry leases, reconciliation, retention, and graceful shutdown.
- One plan catalog with enforced quotas, idempotent checkout, billing portal, invoice/refund/dispute projections, and separate currency totals.

**Assurance boundary:** this software enforces which reviewed issuer may assert a claim and whether that evidence remains current. It does not itself investigate identity, prove global uniqueness, perform KYC, determine investor eligibility, or validate evidence references against an external provider. Operators must establish and review those procedures before approving issuers. Development fixtures are synthetic. These are minimal-disclosure signed proofs, not zero-knowledge proofs, OAuth/OIDC certification, or a legal compliance certification. Online verification is required for the immediate-revocation guarantee.

The [implementation record](docs/review/IMPLEMENTATION_STATUS.md) maps all 48 review findings to changes, verification, and remaining deployment responsibilities. The original [review](docs/review/PROJECT_REVIEW_AND_IMPROVEMENT_PLAN.md) describes commit `128c25c`, not the current behavior.

## Quickstart: Docker

Requirements: Docker Engine/Desktop with Compose. This setup is **local development** with disposable credentials, disabled paid checkout, and loopback-only publishing.

```sh
docker compose up --build -d --wait
```

Open **http://localhost:3001/site/**. Create an account, then read its verification email from the local container mail directory:

```sh
docker compose exec app sh -c 'cat /app/.data/mail/*.json'
```

Messages contain one-time development links. Do not use real identity data with development secrets.

To create persistent, synthetic accounts and an approved test issuer/verifier:

```sh
docker compose exec app node dist/src/cli.js seed
docker compose exec app cat /app/.data/synthetic-accounts.json
```

The generated file contains random account passwords, authenticator keys, recovery codes, and the synthetic verifier secret. Use the customer account to explore the wallet and `synthetic-verifier` to request a proof. Use the administrator account for review screens. Seeding is rejected in production and when real billing is enabled; a completed seed is idempotent. Fixtures expire after one day and have no real-world assurance.

```sh
docker compose logs -f app
docker compose stop
```

The named database and local-data volumes retain accounts across restarts. `docker compose down` removes containers; adding `-v` also **deletes local data**.

## Local development without the application container

Requirements: Node.js **22.12 or newer** (the container/CI pin is 22.23.2), npm, and PostgreSQL 17. Node 26 is also covered by the local validation run. The API requires PostgreSQL; memory storage is available only through test composition.

```sh
npm ci
cp .env.example .env
# Set DATABASE_URL to your local PostgreSQL database.
npm run migrate
npm run build:web
npm run dev
```

In another terminal:

```sh
npm run dev:web
```

Open **http://localhost:3101/site/** or **http://127.0.0.1:3101/site/**. Vite proxies the entire `/api` namespace, the API reference, and JWKS to port 3001. Email links use `SITE_URL`; the initial web build also serves the interface on port 3001. Developer/CLI commands load `.env` when present. Tests do not load it.

Development mail is written to `.data/mail/*.json` by the background worker. `npm run seed` writes synthetic credentials to `.data/synthetic-accounts.json`. Both directories and all secrets are ignored by Git and Docker build context.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` / `npm run dev:web` | Watch the API / run Vite |
| `npm run typecheck` | Strict backend, tests, and frontend TypeScript checks |
| `npm run build` / `npm start` | Compile both applications / run the compiled server |
| `npm test` | Service, API, background-job, and optional PostgreSQL regressions |
| `npm run check` | Typecheck, build, and test |
| `npm run test:e2e` | Browser journeys against an isolated local test server |
| `npm run migrate` | Apply checksummed migrations under an advisory lock |
| `npm run seed` | Persist synthetic development fixtures |
| `npm run keygen -- --directory PATH` | Generate an Ed25519 key pair without overwriting files |
| `npm run admin -- --account ID --roles USER,SECURITY_ADMIN --reason "Approved operational enrollment"` | Enroll a verified, MFA-enabled administrator; invalidates sessions |
| `npm run retention` | Purge one bounded batch of expired audits using a separate retention DB role |
| `npm run format` / `npm run format:check` | Format source/configuration / verify formatting |

For PostgreSQL regressions, use a dedicated test database; tests create synthetic records:

```sh
TEST_DATABASE_URL=postgres://test_user:test_password@localhost:5432/privateid_test npm run check
npx playwright install chromium
TEST_DATABASE_URL=postgres://test_user:test_password@localhost:5432/privateid_test npm run test:e2e
```

If a managed environment cannot download Chromium, installed Chrome can be selected with `PLAYWRIGHT_CHANNEL=chrome`. Browser tests use a temporary profile. [Testing](TESTING.md) explains coverage, test data, and limitations. CI runs PostgreSQL tests, browser journeys, dependency audit, formatting, and a clean container build.

## Configuration

Start with [.env.example](.env.example). No production secret is committed. Production fails startup when required settings, signing material, schema checksums, or restricted database permissions are missing.

| Variable | Purpose / default |
| --- | --- |
| `NODE_ENV` | `development`, `test`, or `production`; default development |
| `HOST`, `PORT` | Bind address and port; default `127.0.0.1:3001`; container uses `0.0.0.0` |
| `DATABASE_URL` | Required PostgreSQL connection string |
| `DATABASE_SSL` | Set `true` for production; certificates are verified |
| `DATABASE_POOL_SIZE` | Per-process connection cap, 1–100; default 10 |
| `SITE_URL` | Browser/email origin; HTTPS in production |
| `PRIVATEID_ISSUER` | Signed-token issuer origin; defaults to `SITE_URL` |
| `ALLOWED_ORIGINS` | Explicit comma-separated browser origins; development includes Vite |
| `TRUSTED_PROXIES` | Explicit proxy IPs/CIDRs; empty means forwarded source headers are untrusted |
| `PRIVATEID_SIGNING_KEY_FILE` | Production Ed25519 PKCS8 private key file |
| `PRIVATEID_SIGNING_KEY_ID` | Unique active signing-key identifier; required in production |
| `PRIVATEID_PUBLIC_KEYS_FILE` | Optional JSON object of old key IDs to SPKI PEM strings |
| `PRIVATEID_PROOF_SECRET` | Development/test HMAC signing secret only; keep stable across local restarts |
| `PRIVATEID_SUBJECT_SECRET` | Independent, stable random secret of at least 32 characters; changing it changes subjects |
| `DATA_ENCRYPTION_KEY` | Independent 32-byte AES key encoded as base64; protects MFA and outbox/evidence fields |
| `SMTP_URL`, `MAIL_FROM` | Required production delivery configuration; SMTPS or required STARTTLS |
| `MAIL_DIRECTORY` | Development mail output; default `.data/mail` |
| `SESSION_HOURS` | Absolute session lifetime, 1–24; default 1 |
| `PROOF_SECONDS` | Maximum direct-proof lifetime, 1–300; default 300 |
| `CONSENT_RETENTION_DAYS` | Consent record retention; default 730 |
| `AUDIT_RETENTION_DAYS` | Operational audit retention; default 365; purge has a 30-day safety minimum |
| `BILLING_ENABLED` | Default false; true requires all four Stripe settings below |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | Server-side provider credentials; test/live modes must match |
| `STRIPE_PRICE_PROFESSIONAL`, `STRIPE_PRICE_BUSINESS` | Monthly prices matching the catalog amount and currency |
| `LOG_LEVEL` | Structured log level; default info |

`PRIVATEID_BOOTSTRAP_ADMIN_EMAILS` was removed and now causes configuration failure. Mailbox allowlists never grant staff authority.

## Roles and plans

Every registered account starts as `USER`. Identity/security staff are enrolled operationally after email verification and MFA. A paid plan never grants staff permissions. Issuer/verifier owners require MFA and independent approval before receiving authority. Organization roles are `OWNER`, `ISSUER`, `VERIFIER`, and `MEMBER`; permissions are checked against the specific workspace on every operation. See the [permission matrix](docs/ROLES_AND_PERMISSIONS.md).

| Plan | USD/month | Proofs per UTC month | Active credentials | Active connections | Workspace members |
| --- | ---: | ---: | ---: | ---: | ---: |
| Free | 0 | 20 | 5 | 5 | No organization |
| Professional | 12 | 100 | 50 | 10 | No organization |
| Business | 49 | 1,000 | 500 | 100 | 10 including owner; one active organization |

Successful issuance consumes a proof allowance; preview/denial and failed issuance do not. Active or trialing subscriptions must have an unexpired provider period. Cancellation, past-due/inactive status, or expiry removes paid effective access; records remain available. Over-limit downgrades block additional usage rather than deleting existing records. [Billing](docs/BILLING_AND_PLANS.md) defines provider synchronization and currency accounting.

## Production deployment and operations

Production requires a real HTTPS origin, verified PostgreSQL TLS, distinct random secrets, Ed25519 signing material, SMTP, separate migration/runtime/retention roles, and operator-approved issuer policies. The image runs as UID 1000. Migrations run separately in production; runtime startup verifies their checksums and rejects audit-modification privileges.

Use [deployment](DEPLOYMENT.md) and the [operations runbook](docs/OPERATIONS.md) for database role setup, legacy cutover, webhook configuration, job retries, key rotation, backups, retention, and rollback. Do not run old snapshot-based instances alongside v2.

- `/health`: process liveness. `/ready`: database availability after startup validation.
- `/openapi.json`: generated OpenAPI 3.1 contracts. `/.well-known/jwks.json`: verification keys.
- `/api/admin/overview`: review queues, billing/mail failures, worker heartbeat, and per-currency totals.
- `/api/admin/metrics`: per-process bounded route counts, server errors, and mean/max latency; security staff only.
- Logs carry generated request IDs and safe error codes. Authorization headers, cookies, request bodies, and query strings are excluded from request logging.

Account deletion revokes access immediately, waits five minutes for in-flight work, retries provider cancellation, and erases personal account/evidence/consent fields. Pseudonymous financial references follow the documented 730-day retention. Audit retention requires the scheduled operational command; backup restoration must replay deletion tombstones before service resumes. These defaults are product decisions, not jurisdiction-specific legal advice.

## Documentation and repository layout

| Document | Contents |
| --- | --- |
| [Product](docs/PRODUCT.md) | Scope, assurance boundaries, measurable acceptance, external release responsibilities |
| [Architecture](ARCHITECTURE.md) / [data model](DATA_MODEL.md) | Services, transactions, invariants, storage and retention |
| [API](API.md) / [authentication](docs/AUTHENTICATION.md) | Contracts, cookies, errors, consent and federation |
| [Administration](docs/ADMINISTRATION.md) / [roles](docs/ROLES_AND_PERMISSIONS.md) | Enrollment, review, workspaces and permissions |
| [Frontend](docs/FRONTEND.md) / [testing](TESTING.md) | UI state, accessibility, build and regression coverage |
| [Operations](docs/OPERATIONS.md) / [deployment](DEPLOYMENT.md) | Production configuration and recovery procedures |
| [Security](SECURITY.md) | Threat boundaries and vulnerability reporting |
| [Implementation record](docs/review/IMPLEMENTATION_STATUS.md) | Review finding traceability and validation evidence |

`src/` contains the API, domain services, repository, provider adapters, jobs, and operational CLI. `web/src/` contains the typed interface. `migrations/` is append-only migration history. `tests/` contains service/API/PostgreSQL tests and browser journeys. `ops/` contains database grants. Dependencies and generated output are installed/built locally and are no longer tracked.

License: [MIT](LICENSE).
