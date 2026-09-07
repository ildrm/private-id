# Product scope and acceptance

PrivateID v2 serves three groups: customers controlling credential disclosure; reviewed issuer/verifier organizations; and platform identity/security operators. Its core promise is a consented, minimal set of current issuer-backed assertions with server-enforced revocation. It does not sell verified identity merely because a customer pays for a larger wallet.

## Goals with acceptance criteria

| Goal | Release acceptance |
| --- | --- |
| Safe entry and recovery | Public input cannot grant roles; mailbox verification and MFA gates hold; challenges/recovery codes cannot replay; suspension and password/role changes invalidate sessions |
| Truthful claims | Unsupported/reserved claims fail; approved issuer scope/assurance and current evidence are required; missing/conflicting evidence does not become a positive or fabricated negative assertion |
| Meaningful consent | Customer sees recipient, reviewed purpose, exact values and expiry; preview changes require review; denial shares nothing; authorization binds state/nonce/PKCE/exact redirect |
| Immediate future-use revocation | Proofs fail online after account, source, issuer, client or connection changes; restoring access never revives old tokens; two replicas cannot redeem once-issued proof twice |
| Durable state and billing | Failed transactions publish nothing and do not poison later work; email uniqueness holds in PostgreSQL; webhook receipt/projection failures retry; checkout is idempotent; amounts and currency totals remain correct |
| Honest paid access | One catalog defines price/limits; UTC monthly quotas are atomic; only current paid status grants access; payment never grants platform staff scope |
| Complete customer controls | Browser journeys cover wallet, consent, connected access, sessions, recovery, MFA, billing and deletion; errors preserve a clear next action |
| Operable release | Strict types, formatting, clean builds, real-DB tests, browser tests, dependency audit, configuration validation, backups/retention and operational alerts pass |

Each criterion maps to regression tests or a named operational release check in [testing](../TESTING.md) and the [implementation record](review/IMPLEMENTATION_STATUS.md). Track production activation, consent approval/denial, unavailable/conflicting claims, successful redemption, revocation failures (target zero), queue age/failure counts and support burden using minimized aggregate telemetry. Define traffic/latency targets from a measured pilot; the repository makes no unsupported throughput or identity-accuracy claim.

## Claim authority

Boolean claims include adult status, identity/KYC/uniqueness, investor eligibility, signatory/asset ownership, employment and degree verification. Jurisdiction is a two-letter uppercase value. Only `account_valid` derives from the account itself. Adult status is 18+, using calendar dates; a February 29 birthday reaches the anniversary on March 1 in a non-leap year. The evidence-backed birth date is used for derivation and discarded.

Issuer review must establish the external procedure, jurisdiction, assurance, freshness, claim scope and revocation channel. An evidence reference alone is not proof that the procedure occurred. Product owners must reject issuer policies without an adequate verification process. For regulated/eligibility use cases, obtain domain/legal review of the actual claim meaning and evidence policy before activation. The service does not infer these guarantees from generic account flags.

## Deliberate boundaries

This release supports one active Business organization with ten members and reviewed owned issuers/verifiers. It does not implement payments to investors, brokerage, document capture, biometric matching, a global uniqueness registry, automatic regulatory compliance, zero-knowledge credentials or a standard OIDC provider. Those require separately specified authority and acceptance tests. Existing memberships/data survive downgrade; adding members and new over-limit usage requires an eligible plan.

Production release responsibilities are concrete: establish issuer evidence policies and independent reviewers; configure and test SMTP and Stripe; approve retention/backups; complete accessibility/penetration and load review for the intended environment; staff incident response and a private reporting channel. Repository tests cannot substitute for those external decisions. Development seed data must never be presented as real identity assurance.
