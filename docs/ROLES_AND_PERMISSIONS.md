# Roles and permissions

Roles are stored on the PrivateID account and checked server-side; hiding a control in the browser is never the authorization boundary.

| Role | Intended permissions |
| --- | --- |
| `USER` | Own sessions, credentials, proof decisions, privacy history, connected apps, subscription, and billing portal |
| `ISSUER_ADMIN` | Issue and revoke credentials for customers |
| `VERIFIER_ADMIN` | Create verifier applications and view applications owned by the account |
| `IDENTITY_ADMIN` | View all verifier applications, maintain the trust registry, and open administration metrics |
| `SECURITY_ADMIN` | Open administration metrics and inspect the complete audit feed |

Public registration always creates a `USER`; callers cannot self-assert verification state or privileged roles. Administrative roles must be assigned through a controlled operational process. Least privilege is expected: billing access remains customer-scoped, while audit access requires `SECURITY_ADMIN`.
