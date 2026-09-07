# Administration

Create and verify a normal account, sign in, enroll TOTP in Security, and save recovery codes. An authorized operator uses the separate administrative CLI:

```sh
npm run admin -- --account ACCOUNT_ID --roles USER,IDENTITY_ADMIN,SECURITY_ADMIN --reason "Approved initial operator enrollment"
```

The CLI uses database access as its operational authority, records the grant and invalidates sessions. Sign in again with a fresh authenticator or recovery code. Limit CLI/migrator credentials to operators; never expose this command through an HTTP endpoint. Establish a second verified security administrator before removing the first.

## Review an issuer

Review the real organization, claim-specific evidence collection, assurance, freshness, revocation process and access controls outside the software. In Issuer workspace, inspect the submitted policy, jurisdiction, supported claims and requested assurance. Approve only an issuer you are authorized to trust. The submitter/organization cannot approve itself. Suspension invalidates proofs through version checks; revocation is permanent. Evidence references must point to controlled external records, not contain raw identity documents.

## Review a verifier

Confirm organization ownership, exact HTTPS redirects, requested claims, customer-visible purpose and appropriate retention. Approve through Verifier workspace with a specific reason. Editing policy/redirects requires renewed review. Secret rotation invalidates old authorization versions and returns the new secret once. Do not send client secrets through browser URLs or logs.

## Customer and organization operations

Account administration exposes safe IDs, verification/MFA status and roles. Suspension revokes all sessions/proofs. Restoration requires a new login and does not revive old proofs. Password and identity flags cannot be edited by staff; evidence-backed credentials replace the prototype’s arbitrary assurance toggles.

Business owners add already verified accounts to workspace roles, remove members, transfer ownership to another eligible owner, or close the workspace. Members can leave. Workspaces do not grant global staff access. A security administrator must relinquish that role before requesting account deletion.

Operations shows worker heartbeat, failed mail, pending reviews, webhook failures and separate currency totals. Billing event operations can queue a failed receipt after the underlying problem is repaired. Audit provides a paginated, append-only record. A reason field must not contain passwords, identity documents or unnecessary personal information.
