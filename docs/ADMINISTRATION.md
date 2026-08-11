# Administration guide

The web application's role switch exposes the administrator workspace for authorized staff. `GET /admin/overview` returns customer, credential, proof-request, verifier-application, trust-registry, subscription, payment, and recognized-revenue totals. `GET /audit` is restricted to security administrators.

Routine work includes reviewing verifier applications, maintaining trusted issuer status, investigating disclosure or session events, revoking compromised credentials, and monitoring failed invoices in Stripe. Every privileged domain change generates an audit entry. Operators should assign separate identity and security roles where staffing allows and should use short-lived sessions.

Customer support must never request passwords, proof signing secrets, Stripe secret keys, or complete credentials. When investigating a customer issue, use identifiers and audit metadata, disclose the minimum information, and record any manual role change through the organization's change-control procedure.
