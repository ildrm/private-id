# Security policy and trust boundaries

PrivateID v2 protects customer/session scope, reviewed issuer/verifier authority, minimal claim disclosure, atomic replay prevention, durable payments and auditable administrative changes. It is centralized software, not an independent source of identity truth.

## Implemented controls

- Strict public schemas and canonical email uniqueness; no email-allowlist administrator bootstrap.
- Salted scrypt passwords, verified mailbox challenges, MFA for privileged operations, one-time recovery codes, hashed session/client secrets and immediate authorization-version invalidation.
- HttpOnly/Secure production cookies, CSRF and origin checks, strict CSP, no browser bearer persistence, redacted structured logs and bounded inputs.
- Ed25519 production proofs, exact issuer/audience/type/key/expiry validation, nested claims, independent pairwise-subject secret, PKCE/state/nonce, and mandatory online authority checks.
- Serializable row transactions, database constraints, immutable runtime audit permissions, durable external-effect jobs and safe error responses.
- Encrypted MFA/evidence/outbox fields and documented deletion/retention behavior.

The provider/operator remains trusted to evaluate evidence and approve the correct authority. Database owners can alter data and backups; runtime append-only audit is not protection from database-owner compromise. Use restricted runtime credentials, encrypted backups and externally immutable audit storage when the threat model requires operator-resistant history. Relying parties can retain disclosed values; revocation cannot erase their copies.

Production startup requires HTTPS origins, validated PostgreSQL TLS, SMTP TLS, mounted signing material, dedicated secrets and restricted database permissions. Dependencies are audited in CI and reviewed weekly. Do not add raw credentials, customer evidence, .env files, generated keys, tokens or mail outputs to version control.

## Reporting

No public security contact is configured in this repository. Use the hosting organization’s private vulnerability-reporting channel or private repository security advisory mechanism when available. Do not publish live credentials or personal data in public issues. Include affected version, a minimal synthetic reproduction, expected/actual behavior and impact. Rotate exposed credentials, revoke affected sessions/proofs and preserve redacted evidence through the operator incident process.

External identity procedures, jurisdiction-specific retention, deployment hardening, penetration testing and assistive-technology signoff remain operator responsibilities. [Operations](docs/OPERATIONS.md) describes incident and recovery procedures.
