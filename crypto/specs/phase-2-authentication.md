# Phase 2 Authentication and Key Generation

## Scope

Phase 2 defines device identity generation and public-key authentication. It does not yet implement encrypted messaging sessions, invites, groups, or file transfer.

## Device keys

Each device generates and stores:

| Key | Algorithm | Lifetime | Leaves device? |
| --- | --- | --- | --- |
| Identity signing key | Ed25519 | Device lifetime unless reset | Public key only |
| Signed pre-key agreement key | X25519 | Rotated periodically | Public key only |

Private key bytes must remain in platform secure storage. The server stores only public keys, signatures, approval state, and operational metadata.

## Signed pre-key proof

The device signs the X25519 signed pre-key public key with its Ed25519 identity key. The server verifies this proof before accepting a pending device identity record.

## Authentication challenge

1. Server issues a short-lived challenge containing a challenge id, device id, 32-byte random nonce, issue time, and expiration time.
2. Client signs the domain-separated challenge payload with its Ed25519 identity key.
3. Server verifies the signature against the registered public identity key.
4. Server rejects pending, revoked, expired, mismatched, or invalid challenges.

## Domain separation

Authentication challenge payloads use the `secure-messaging.auth.v1` domain separator so signatures cannot be replayed as another protocol message.

## Phase 2 non-goals

- No password authentication.
- No email, phone, or social-login enrollment.
- No private-key export.
- No server-side message decryption.
