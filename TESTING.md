# Testing

Run `npm run check` inside this repository. Tests cover selective release, audience binding, pairwise IDs, denial, invalid policy claims, replay, privilege escalation, authentication/RBAC, durable hydration, verifier registration, trust registry, privacy history, access revocation, logout, and account deletion. CI also starts PostgreSQL and applies every migration. External provider certification, browser WebAuthn, and KMS rotation require environment-specific suites.
