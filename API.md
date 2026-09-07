# API and federation

The canonical OpenAPI 3.1 document is generated at **`GET /openapi.json`** from the live v2 route definitions, including request/response schemas, authorization, path/query parameters and structured errors. Application routes use `/api`; `/health`, `/ready`, `/site/` and `/.well-known/jwks.json` are outside that prefix. The old unprefixed prototype routes and automatic `/federation/proof` shortcut were removed.

## Authentication and errors

`POST /api/accounts` accepts only `email` and `password`. Registration returns an unverified `USER`. Verify the email challenge, then use `POST /api/auth/login` with email/password and MFA or a recovery code when enabled. Browser login sets an HttpOnly session cookie and a separate CSRF cookie. Every cookie-authenticated mutation sends the CSRF cookie’s value in `X-CSRF-Token`; same-origin fetch includes cookies. Responses are `no-store`.

A machine client may explicitly request `bearer: true` at login and use `Authorization: Bearer TOKEN`. This does not bypass MFA or authorization. Never put tokens in URLs or localStorage. Verifier client secrets authenticate only verifier redemption/introspection, not customer accounts.

Errors are `{ "error": { "code": "CLAIM_UNAVAILABLE", "message": "...", "requestId": "...", "fields": [] } }`. `fields` is optional. Statuses distinguish 400 invalid input, 401 missing/invalid authentication, 403 forbidden, 404 absent/foreign resource, 409 conflicting state, 422 unavailable/conflicting evidence, 429 quotas/abuse limits, 500 unexpected failures and 503 retryable dependencies. Client logic should use `error.code`, not match message text. Do not blindly retry non-idempotent customer mutations after an uncertain network result; refresh state first.

Collection endpoints return `{items,nextCursor?}`. Supply `limit` 1–100 and the returned opaque ID cursor. A full last page can produce one final empty page. Issuer/verifier listings accept `organizationId` only with that workspace’s required membership. Other customer collections always scope to the authenticated account.

## Direct proof flow

1. An MFA-enabled owner registers a verifier through `/api/verifiers`; store the returned client secret on the verifier server. An independent `IDENTITY_ADMIN` reviews the exact redirects, purpose and claim scope.
2. The customer creates `/api/proof-requests` with `clientId` and `requestedClaims`. Nothing is shared yet.
3. Fetch `/api/proof-requests/{id}/preview`; show the exact values, purpose, recipient and expiry. Approval requires the returned `previewHash`.
4. `POST /api/proof-requests/{id}/approve` with `{previewHash}` returns the proof once. Denial uses `/deny`. A changed conclusion forces another preview.
5. The verifier server calls `/api/proofs/verify` with `{proof,clientId,clientSecret}`. This consumes the proof once. `/api/proofs/introspect` checks continuing validity without consuming it.

The JWT protects `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, `request_id`, optional `nonce`, and nested `claims`. Header type is `privateid-proof+jwt`. Claims cannot overwrite envelope fields. Production signs Ed25519; development/test can use HMAC. JWKS publishes asymmetric verification keys only. Offline signature verification does **not** establish current revocation state.

## Browser authorization-code flow

This is a documented custom protocol, not an OAuth/OIDC implementation.

1. On the relying-party server, create fresh random state and nonce (at least 16 characters each), and a cryptographically random PKCE verifier of 43–128 permitted characters. Compute `BASE64URL(SHA256(verifier))`. Retain state/nonce/verifier in a secure, one-time local transaction bound to the initiating browser session.
2. Send the browser to `/site/?client_id=CLIENT&scope=account_valid%20adult_verified&redirect_uri=EXACT_URI&state=STATE&nonce=NONCE&code_challenge=CHALLENGE`. URL-encode every value. Only S256 is supported.
3. PrivateID requires login, displays a reviewed consent purpose and exact values, then issues a short-lived code. It returns the code and unchanged state only to the exact approved redirect. Denial returns `error=access_denied` and state.
4. The relying party verifies state against its initiating browser session and atomically consumes that local transaction. Its server calls `POST /api/federation/token` with `{clientId,clientSecret,code,codeVerifier,redirectUri}`. Never embed the client secret in frontend code.
5. Validate the response nonce against the stored nonce, issuer/audience and expiry as applicable, then use the pairwise `subject` as the application-local identifier. The code cannot be redeemed twice. Optional subsequent `/api/proofs/introspect` is non-consuming; `/verify` is for direct unconsumed proofs.

Claim disclosures have already occurred when redemption succeeds. Application-side retention/deletion is the relying party’s responsibility. Restoring a PrivateID connection permits new consent, not replay.

## Important endpoints

| Area | Routes |
| --- | --- |
| Entry/recovery | `/accounts`, `/auth/login`, `/auth/me`, `/auth/verify-email`, `/auth/resend-verification`, `/auth/forgot-password`, `/auth/reset-password`, `/auth/password`, `/auth/logout` |
| MFA/session control | `/auth/mfa/setup`, `/auth/mfa/confirm`, `/sessions`, `/sessions/{id}` |
| Wallet | `/privacy-dashboard`, `/credentials`, `/proof-requests`, `/connections`, `/accounts/me` |
| Issuers/verifiers | `/issuers`, `/issuers/{id}/review`, `/issuers/{id}/credentials`, `/verifiers`, `/verifiers/{id}/review`, `/verifiers/{id}/rotate-secret`, `/trust-registry` |
| Organizations | `/organizations`, `/organizations/{id}/members`, `/transfer`, `/leave`, `/close`, `/audit` |
| Billing | `/billing/plans`, `/billing/subscription`, `/billing/checkout`, `/billing/portal`, `/billing/reconcile`, `/billing/invoices`, `/webhooks/stripe` |
| Staff | `/admin/customers`, `/admin/customers/{id}/roles`, `/admin/customers/{id}/status`, `/audit`, `/admin/overview`, `/admin/metrics`, `/admin/billing/events` |

All entries in this table are beneath `/api`; use OpenAPI for exact HTTP methods and complete schemas.
