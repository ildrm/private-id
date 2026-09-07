# Roles and permissions

Review responsibilities (the sixteen roles in the historical review) are different from application permissions.

| Principal | Permitted scope |
| --- | --- |
| USER | Own account, wallet, consent, sessions, billing and privacy controls; submit owned issuer/verifier identities after MFA |
| IDENTITY_ADMIN | Review issuers/verifiers independently, revoke credentials, read safe customer/operations data, suspend/restore other accounts; MFA required |
| SECURITY_ADMIN | Assign staff roles, review issuers, revoke credentials, read security audit/billing retries/metrics, read customer/operations data, suspend/restore other accounts; MFA required |
| ISSUER_ADMIN / VERIFIER_ADMIN | Legacy staff labels retained in the role schema; they do not grant global issuer or verifier ownership or bypass review |
| Organization OWNER | Manage members, transfer/close the workspace, view its audit, manage workspace issuers/verifiers |
| Organization ISSUER | Submit/manage and issue through that workspace’s reviewed issuers; MFA required |
| Organization VERIFIER | Submit/manage that workspace’s verifier applications; MFA required |
| Organization MEMBER | Membership visibility; no issuer/verifier or staff authority |
| Authenticated verifier client | Redeem/introspect only its own audience-bound proof/code; no customer account authority |

New accounts start with USER only. A subscription changes quotas and organization entitlement, never platform staff roles. Identity/security review cannot approve the reviewer’s own issuer/verifier or a workspace in which the reviewer is a member. REVIEWED status plus claim scope is mandatory for issuance and use.

Organization resources belong to the organization owner, not permanently to the member who submitted them. Ownership transfer updates resource ownership and authority versions. Removing/leaving membership removes scope immediately. Closing a workspace invalidates its trust. Non-owners may leave; owners must transfer or close first. A paid-plan downgrade stops adding members but preserves existing records and security controls; it does not automatically revoke valid existing evidence.

All permissions are enforced in service transactions. Hiding a UI action is only presentation. Foreign-owned resource IDs never expand access. Staff customer listings omit passwords, MFA secrets, recovery hashes and session secrets.
