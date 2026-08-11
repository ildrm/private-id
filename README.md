# PrivateID

PrivateID is a self-contained identity and selective-disclosure site. This repository owns its web application, API, PostgreSQL schema, customer accounts, roles, plans, Stripe billing, administrator workspace, tests, container image, and deployment configuration. It does not require source code or a shared database from either sibling product.

## Run the complete site

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3001/site/`. Health and readiness endpoints are `/health` and `/ready`; the machine-readable API inventory is `/openapi.json`.

For local development, use Node.js 22+, PostgreSQL 17, `npm ci`, `npm run migrate`, then `npm run dev` and `npm run dev:web` in separate terminals. `npm run check` builds the API and responsive React site and runs every automated test.

## Product capabilities

- Customer registration, password authentication, sessions, logout, deletion, and privacy dashboard
- Credential issuance/revocation and audience-bound, minimal-claim proofs with replay protection
- Connected-application revocation, verifier onboarding, issuer trust registry, and immutable audit events
- Independent Free, Professional, and Business plans
- Independent Stripe customer, Checkout subscription, Customer Portal, payment, and signed webhook lifecycle
- Role-separated customer, verifier, identity administration, and security administration views
- Responsive customer and administrator web application served by the same deployable artifact

## Documentation

- [Product and customer journeys](docs/PRODUCT.md)
- [Roles and permissions](docs/ROLES_AND_PERMISSIONS.md)
- [Authentication and role entry](docs/AUTHENTICATION.md)
- [Plans and billing](docs/BILLING_AND_PLANS.md)
- [Administrator guide](docs/ADMINISTRATION.md)
- [Web application and verified renders](docs/FRONTEND.md)
- [Operations runbook](docs/OPERATIONS.md)
- [API reference](API.md), [architecture](ARCHITECTURE.md), [data model](DATA_MODEL.md), [security](SECURITY.md), [testing](TESTING.md), and [deployment](DEPLOYMENT.md)
- [Dashboard design reference](docs/design/dashboard-concept.png)

No production secret is committed. Checkout intentionally returns `503` until this repository's own Stripe variables are configured.
