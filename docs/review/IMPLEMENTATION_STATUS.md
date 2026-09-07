# Review implementation status — PrivateID v0.2

This record addresses the 48 findings in the baseline review of commit `128c25c`. The original report/probes remain historical evidence. V2 uses different routes, persistence, authority and UI contracts; old probe scripts intentionally asserting unsafe behavior are not the current regression suite.

**Status meaning:** “Implemented” means the repository contains the control or a corrected product contract. It does not certify a deployed service, an external issuer’s evidence, a live payment configuration, or legal/accessibility compliance. Release responsibilities that need actual operators/providers are listed explicitly below.

| Finding | Implemented correction | Evidence / acceptance |
| --- | --- | --- |
| F01 | Removed email-allowlist bootstrap; strict USER signup; verified-MFA operational enrollment | `foundations.test.ts`, `api.test.ts`; configuration rejects obsolete variable |
| F02 | Transactional account/session authorization and authVersion invalidation | Foundation, proof and PostgreSQL revocation tests |
| F03 | Source/account/client/connection versions and online authority recheck; restore cannot revive proofs | Proof revocation matrix and concurrent PostgreSQL redemption |
| F04 | Public session IDs, hashed secrets, HttpOnly browser cookies, CSRF, no localStorage bearer | API cookie/session tests and browser journey |
| F05 | Email verification, reset/change, TOTP, one-use recovery, dummy password derivation and shared abuse limits | Foundation/API/job/browser tests; comprehensive breach-password feed and exceptional lost-MFA recovery remain outside the implemented policy |
| F06 | Separate organization membership/ownership from platform staff and subscription plans | Organization scope/transfer tests and role matrix |
| F07 | Immediate access revocation, retryable cancellation and erasure, bounded data retention and tombstones | Job erasure tests, data inventory, restore runbook; live provider/backup drill required |
| F08 | Append-only row audit in mutation transactions, rejection events, restricted DB grants and separate retention function | Foundation/PostgreSQL immutable-audit tests and operations SQL |
| F09 | Removed poisoned persistence promise chain; rollback and fresh transactions recover | Memory fault injection and real-DB rollback tests |
| F10 | Removed mutable snapshot references; per-record validated transactions | Foundation rollback tests and repository design |
| F11 | Canonical-email uniqueness enforced by database index | Concurrent memory/API and independent-pool PostgreSQL tests |
| F12 | One authoritative pid_* model; old tables used only for fenced archived cutover | SQL constraints, runtime guard and migration test |
| F13 | Serializable transactions, shared replay state and durable worker leases | Independent-pool concurrent redemption accepts exactly once |
| F14 | Indexed subject/scoped queries, bounded pages/batches, aggregate currency counters, no whole-state writes | Repository/worker implementation; deployment-specific load targets still require measurement |
| F15 | Strict record schemas, checksummed advisory-locked migrations, read-only startup verification and explicit legacy archive/import | Migration checksum and cutover tests |
| F16 | Independent issuer review, approved scope/assurance, current credential evidence and encrypted external references | Proof/organization tests; actual verification procedures must be established by operators |
| F17 | Deterministic highest-assurance resolution, conflict rejection, no arbitrary user-flag fallback, explicit calendar age rule | Missing/conflicting evidence and leap-day tests |
| F18 | Strict claim catalog and nested claims beneath protected JWT fields | Reserved-claim and JWT envelope regressions |
| F19 | Ed25519 production keys, key IDs/public rotation ring and independent stable subject secret | Signing-key rotation/subject continuity test; data-key rotation is a documented offline migration |
| F20 | Strict issuer/audience/type/key/claims/lifetime validation and exp boundary | Injected-clock JWT tests |
| F21 | State/nonce/exact redirects/S256 PKCE, authenticated client code redemption and one-use local protocol contract | Proof federation negative tests; relying parties must implement their documented state/nonce checks |
| F22 | Pending applications, independent review, edit/re-review, suspension/revocation and secret rotation | Service gates, workspace UI and scoped tests |
| F23 | Consent states/expiry/source provenance, exact-value preview hash and revocation versions | Proof tests and browser exact-disclosure approval |
| F24 | Atomic UTC proof allowance, credential/connection/member limits and effective subscription policy | Quota and Business scope tests; downgrade policy documented |
| F25 | Single catalog shared by API/UI/entitlements/price validation | Catalog endpoint contract test |
| F26 | Durable webhook inbox before acknowledgment; completion atomic with projections; recoverable retries/leases | Commit-failure, duplicate and expired-lease payment tests |
| F27 | Current-provider reads, customer-level serialization, versioned subscription/invoice updates, unmatched-event retention and reconciliation | Early-event/order tests; provider reconciliation/replay procedures |
| F28 | Stable customer/checkout idempotency keys, durable per-account operation, provider active-subscription check | Concurrent checkout regression |
| F29 | Full invoice upserts replace paid/due amounts and status; totals apply deltas transactionally | Failure-to-paid payment regression and row repository |
| F30 | Effective plan separate from historical subscriptions; active/trialing plus current period required | Expired/canceled entitlement tests and catalog logic |
| F31 | Adapter matches pinned API 2026-07-29.dahlia and subscription-item period fields; signature/version/mode validation | Installed SDK types and real SDK signature test |
| F32 | Separate integer currency totals for invoice gross/refunds/disputes; removed recognized-revenue claim | Currency/refund regression and truthful operations UI; accounting reconciliation remains operational |
| F33 | Typed public DTOs and validated responses; UI consumes actual returned fields | Strict frontend typecheck, API and browser tests |
| F34 | Per-resource state, abort cleanup, keyed navigation and pagination | Browser security→billing→credentials regression |
| F35 | Entry, verification, recovery, MFA, sessions, consent, connected access, billing and deletion UI | Browser journeys and service/API negative tests |
| F36 | Real issuer/verifier/account review forms with IDs, policy, scope and reasons; no fake assurance toggle | Workspace/staff UI, organization/permission tests |
| F37 | One /api prefix with complete Vite proxy coverage | Vite configuration and API integration |
| F38 | Structured frontend errors, focused validation, session expiry handling, loading/retry and duplicate-submit prevention | API/browser journeys and shared form/resource components |
| F39 | Labeled controls, keyboard skip/focus, live feedback, reduced motion and narrow layout | 390px keyboard/browser test; manual assistive-technology signoff is not claimed |
| F40 | Typed error codes/statuses, safe 500 responses and request IDs | API error-leak and readiness regressions |
| F41 | Generated schemas/security/parameters/responses from live route definitions, with input/output distinctions | OpenAPI operation coverage and response validation |
| F42 | DB readiness, shared auth limits, trusted-proxy configuration, safe logs, route metrics, worker heartbeat and queue views | API/job tests and operations runbook; external alerting needs deployment |
| F43 | Production prerequisite and restricted-role checks; no memory fallback; separate migrations and graceful shutdown | Configuration tests, startup code and non-root image checks |
| F44 | Updated affected dependencies and lockfile; audit in CI and weekly update configuration | Clean npm audit reported zero vulnerabilities |
| F45 | Risk-based service/API/job/organization/PostgreSQL/browser regressions and CI | Validation summary below |
| F46 | Readable formatted modules, strict frontend check, source-only builds, ignored secrets/artifacts, dependencies/build output untracked | Formatter/type/build checks; Git hygiene verification |
| F47 | Rewritten README and all current guides; persistent idempotent synthetic seed and accurate commands/contracts | Compose startup/seed verification and documentation link checks |
| F48 | Explicit product boundaries, claim-authority responsibilities and measurable release acceptance | Product/role/API/operations documents; provider/legal/launch signoff remains external |

## Validation

The latest local validation results are recorded in [IMPLEMENTATION_VALIDATION.json](IMPLEMENTATION_VALIDATION.json). Tests cover memory, Fastify injection, real PostgreSQL through independent pools, archived legacy cutover, and Chrome browser workflows. The production image is built from a clean npm install and runs as a non-root user. Compose is development-mode smoke coverage, not proof that a production SMTP/TLS/Stripe deployment has been configured.

Chromium download returned a provider regional-access 403. The same browser tests ran with installed Chrome and a temporary profile. Intermittent registry tag lookups timed out; the base image was pinned to its verified digest and the final build used that reproducible reference. These environmental fallbacks did not skip the functional browser or container startup checks.

## Remaining deployment responsibilities

1. Establish actual issuer evidence procedures, independent reviewers, assurance freshness and jurisdiction-specific claim meaning. Synthetic/test evidence has no production authority.
2. Configure and validate real SMTP delivery and Stripe test/live lifecycle behavior, including disputes and provider reconciliation. No live charges or messages to real users were sent during this work.
3. Provision HTTPS, verified database TLS, restricted runtime/migrator/retention roles, secret mounts, external alerts and a private security reporting channel.
4. Approve retention/backup policies, schedule audit purges, perform restore/deletion replay and key-rotation drills. Data encryption-key rotation requires an offline re-encryption migration.
5. Complete deployment-specific load, penetration and assistive-technology reviews. Automated checks are evidence for their covered behavior, not an exhaustive defect-free or compliance guarantee.
