# Authentication and role entry

`/site/` is public only as a sign-in and registration surface. A dashboard is never rendered until the saved bearer token succeeds against both `GET /customers/me` and `GET /auth/capabilities`. Failed or expired tokens are deleted locally. Sign-out calls `POST /auth/logout` before removing the browser token.

Relationship Network and AssetToken start sign-in at PrivateID with a client identifier. PrivateID displays the minimal requested claims, creates an audience-bound proof only after consent, and returns the browser to the independently deployed site. Configure the destinations with `RELATIONSHIP_SITE_URL` and `ASSETTOKEN_SITE_URL`.

Public registration always creates an ordinary customer. To establish the first controlled administrator, set `PRIVATEID_BOOTSTRAP_ADMIN_EMAILS` to a comma-separated allowlist before that account registers or signs in. Matching accounts receive the PrivateID administrative roles server-side. A `SECURITY_ADMIN` can subsequently manage roles with `PUT /admin/customers/{id}/roles`; clients cannot self-assign roles.

The UI shows customer functions to every authenticated account and adds issuer, verifier, trust-registry, customer-administration, or audit workspaces only when `GET /auth/capabilities` returns the corresponding capability.
