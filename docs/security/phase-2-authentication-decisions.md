# Phase 2 Security Decisions: Authentication and Key Generation

## Decisions

1. **Device identity is permanent**: each device owns an Ed25519 identity key pair for authentication and signed device metadata.
2. **Signed pre-key is separate**: the X25519 signed pre-key is used for future session setup and is signed by the Ed25519 identity key to prevent substitution.
3. **Server receives public material only**: the backend stores identity public keys, signed pre-key public keys, signatures, approval status, and timestamps only.
4. **Challenge authentication is domain-separated**: signed authentication payloads include the `secure-messaging.auth.v1` domain separator to prevent cross-protocol replay.
5. **Approval gate is enforced during authentication**: pending and revoked devices fail authentication even when signatures are cryptographically valid.
6. **Challenge lifetime is short**: challenges are time-bound and rejected after expiration.
7. **Private keys stay in secure storage**: client abstractions require platform secure-storage implementations and forbid private-key transport models.

## Phase 3 prerequisites

Before messaging begins, the project must define Double Ratchet session initialization, one-time pre-key handling, encrypted envelope schemas, replay protection, and message metadata minimization.
