# Architecture

The modular monolith separates accounts/sessions, credentials, proof consent, verifier policy, issuer RBAC, trust registry, privacy dashboard, and audit concerns. `SignedCredentialProofProvider` is the working provider behind a future ProofProvider family. Pairwise subjects are client-specific. Production startup migrates PostgreSQL, hydrates durable state, and persists mutations before responses complete; tests use an isolated in-memory adapter.
