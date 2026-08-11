# Security

Passwords use Node's scrypt with per-password random salt and constant-time verification. Proofs are HMAC-SHA-256 signed, audience-bound, expire after five minutes, and are rejected after first verification. Verifier policies allowlist claims. Helmet, strict no-origin CORS, rate limits, RBAC, opaque sessions, and minimal audit metadata are enabled.

Development HMAC keys and mock verification are not production controls. Production requires asymmetric KMS keys/JWKS, TLS, PKCE, MFA/passkeys, CSRF tokens for cookie flows, durable replay state, encrypted fields, recovery controls, and external security review. Never log documents, passwords, proof tokens, or keys.
