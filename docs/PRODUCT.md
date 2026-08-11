# PrivateID product guide

## Customer lifecycle

A visitor creates a PrivateID account with an email and a password of at least 12 characters, signs in, and receives a revocable bearer session. The customer can inspect active sessions, credentials, proof requests, disclosure history, and connected relying parties. Account deletion revokes sessions, credentials, and connected access.

Credential administrators issue typed claims with an assurance level and optional expiry. A customer approves or denies each proof request. Approval releases only the requested claims, binds the result to the relying-party audience, and records a one-time proof identifier. Verification rejects altered, expired, wrong-audience, and replayed proofs.

Organizations can apply for sandbox or production verifier access and declare redirect URLs, claim allowlists, and an optional webhook. Identity administrators review the global application list and maintain trusted issuer entries. Security administrators review the audit trail and operational totals.

## Site areas

The responsive `/site/` application contains a credential wallet, proof-request workflow, connected-app controls, plan/usage view, role-aware administrator area, and billing launch points. API consumers use the same domain rules through authenticated JSON endpoints.

## Ownership boundary

PrivateID owns its accounts, customer records, sessions, credentials, proof keys, roles, billing customers, subscriptions, payments, web assets, migrations, tests, and database. Relationship Network and AssetToken consume proofs over HTTP; they never import this repository or access its database.
