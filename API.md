# API

The canonical machine-readable summary is `GET /openapi.json`. Public account entry uses `POST /accounts` and `POST /auth/token`. Protected session routes are `GET /auth/capabilities`, `POST /auth/logout`, `GET|DELETE /sessions`, and `DELETE /accounts/me`.

Identity workflows use `GET|POST /credentials`, credential revocation, proof-request create/read/approve/deny, `POST /federation/proof`, and public one-time verification at `POST /proofs/verify`. Verifier registration, the trust registry, connected-app revocation, privacy history, plans, subscriptions, checkout, and the Stripe webhook have separate routes.

Administrative routes are `GET /admin/overview`, `GET /admin/customers`, `PUT /admin/customers/:id/roles`, `PUT /admin/customers/:id/assurance`, and `GET /audit`. Every protected route requires `Authorization: Bearer <opaque-session>` and independently enforces its required role.
