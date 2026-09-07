# Authentication

Public registration is strict and always creates an unverified USER. Canonical email uniqueness is enforced by PostgreSQL. Passwords use salted scrypt; reset/change policy requires 12–128 characters and rejects a small local denylist of common passphrases. This is not a comprehensive breached-password database. Unknown-account login performs the same password-derivation work; challenge requests return a generic eligibility message. Signup deliberately returns conflict for an existing email.

Email verification and reset challenges are random, hashed, single-use, and valid for 30 minutes. Messages enter an encrypted durable outbox. Production requires SMTP; development writes local JSON mail files. Opening a link does not consume it automatically; the customer confirms in the interface. Browser fragments are removed from history and are not logged by the server.

Sessions have separate public UUIDs and hashed random bearer secrets. Browser sessions use HttpOnly cookies, Secure in production, SameSite=Strict, path `/`; a separate CSRF token must accompany mutations. Origin and fetch-site checks provide another boundary. Session lists never expose bearer hashes or secrets. Each operation rechecks account state, session expiry, authVersion, role scope and required MFA.

TOTP setup requires the current password and expires after ten minutes. Confirmation returns ten random, hashed, single-use recovery codes. TOTP steps cannot be reused; after using a code to log in, use a fresh code or recovery code for sensitive password/deletion operations. Staff and issuer/verifier management require MFA. Lost authenticator recovery uses saved recovery codes; there is no email-only MFA bypass. If both authenticator and recovery codes are lost, recovery requires a separately designed operator identity-recovery procedure; staff must not simply disable MFA by mailbox claim.

Password changes/resets, staff-role changes, suspension and deletion invalidate sessions immediately. Role changes also invalidate existing proof authority. Account/source rate limits are shared in PostgreSQL; the general route limiter is per process. Apply perimeter source limits in multi-replica deployments. Limits expire and do not permanently lock an account.

Operational staff enrollment uses the CLI after mailbox verification and MFA. `PRIVATEID_BOOTSTRAP_ADMIN_EMAILS` is rejected. The last active security administrator cannot be removed or suspended; security staff must transfer authority before deletion. See [administration](ADMINISTRATION.md).
