# Data model

Users own sessions, credentials, and proof requests. Credentials carry issuer, type, claims, assurance, issuance/expiry, and revocation. Proof requests bind subject, client, exact requested claims, and decision. Consents and append-oriented audit records retain the minimal decision record. Retention defaults: failed security events 12 months, proof consent 24 months, expired sessions 30 days; production policy must be jurisdiction-reviewed.
