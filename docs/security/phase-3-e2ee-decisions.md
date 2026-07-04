# Phase 3 Security Decisions: End-to-End Encrypted Messaging

## Decisions

1. **Encrypted envelopes only**: the backend validates routing metadata but does not parse or decrypt message content.
2. **Double Ratchet boundary**: client message sessions own root keys, chain keys, message keys, skipped-key handling, and ratchet headers.
3. **AEAD-required payloads**: every application event must be protected by an approved AEAD with authenticated associated data.
4. **Metadata minimization**: only delivery-critical identifiers are server-visible in Phase 3.
5. **Revocation remains authoritative**: the server must reject sends from revoked devices and clients must reject newly received envelopes from revoked identities once revocation state syncs.
6. **No sensitive logging**: operational logs may mention envelope acceptance or rejection counts but not envelope bytes, nonces, tags, associated data, or plaintext-derived identifiers.

## Phase 4 prerequisites

Invite codes and QR invitations must bind enrollment intent to a device identity public key and must remain single-use, time-limited, and manually approved before messaging access is granted.
