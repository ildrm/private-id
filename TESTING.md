# Testing and validation

Use Node 22.12+ and `npm ci`. The default test suite runs Node’s test runner with TypeScript loading. Service tests inject a clock; the memory repository provides atomic rollback/failure injection. PostgreSQL integration tests are enabled only when `TEST_DATABASE_URL` points to a dedicated test database. They create synthetic data; never use production.

```sh
npm run check
TEST_DATABASE_URL=postgres://test_user:test_password@localhost:5432/privateid_test npm run check
npx playwright install chromium
TEST_DATABASE_URL=postgres://test_user:test_password@localhost:5432/privateid_test npm run test:e2e
npm audit --audit-level=moderate
docker build -t privateid:check .
```

`PLAYWRIGHT_CHANNEL=chrome` selects an installed Chrome browser if Chromium downloads are unavailable. Tests use a temporary browser profile and loopback test server. `tests/browser-server.ts` includes a synthetic mailbox helper; it is excluded from production compilation. Browser credentials/screenshots/traces are ignored artifacts.

## Coverage

- Foundations: canonical-email races, rollback/recovery, safe session identifiers, one-time email/MFA recovery, immutable audit and fail-closed production settings.
- Proofs: nested claims, reserved-field rejection, exact expiry boundaries, conflicting/missing evidence, one-time concurrency, account/credential/issuer/verifier/connection revocation, restore behavior, quota rollback, leap-day age and signing-key rotation with stable subjects.
- Payments: concurrent idempotent checkout, commit failure/retry, early unmapped events, event ordering, corrected paid amounts, separate currencies/refunds, expired leases and real SDK raw-signature validation.
- API: cookie flags, CSRF, origins, structured errors, unverified-account rejection, staff authorization, session response safety, generated contracts, readiness and private error handling.
- Background jobs: mail delivery/redaction, delayed erasure and shared expiring abuse limits.
- Organizations: Business gating, membership boundaries, ownership transfer, scoped issuer visibility and leaving/closing.
- PostgreSQL: migrations/checksums, database uniqueness and foreign keys, independent pools, rollback/recovery, immutable audit and concurrent one-time redemption.
- Browser: login, exact-value proof consent, verifier redemption, access revocation, rapid section changes, registration/email verification, TOTP/recovery/reset and narrow-screen keyboard entry.

CI runs formatting, strict types, builds, PostgreSQL-enabled tests, dependency audit, browser tests and a clean image build. See [implementation status](docs/review/IMPLEMENTATION_STATUS.md) for the most recent local run and environmental limits.

Historical probes under `docs/review/` intentionally assert defects in baseline commit `128c25c`. They are preserved as review evidence, not part of the v2 test command and not compatible with removed prototype modules. Current negative regressions assert the corrected behavior.

Before production, run real Stripe test-mode lifecycle cases, delivery through the configured SMTP service, key rotation/backup restore drills, and manual assistive-technology review. Capacity claims need measured deployment-specific load tests; a local functional pass is not a production throughput guarantee.
