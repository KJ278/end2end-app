# Phase 3 End-to-End Encrypted Messaging

## Scope

Phase 3 introduces encrypted message-envelope contracts and Double Ratchet session boundaries. The server remains a relay and must never receive plaintext message bodies, attachment bytes, private keys, message keys, or ratchet root keys.

## Cryptographic construction

- Initial shared secrets are derived from X25519 key agreement material established from approved device key bundles.
- Root keys, chain keys, and message keys are derived with HKDF.
- Message payloads are encrypted with ChaCha20-Poly1305 or AES-256-GCM.
- Ed25519 identity keys authenticate device key bundles and signed pre-keys; they do not encrypt messages.
- Double Ratchet state provides forward secrecy and practical post-compromise recovery after new ratchet steps.

## Encrypted envelope

The server-visible envelope contains only routing and cryptographic framing fields:

| Field | Server can read? | Rationale |
| --- | --- | --- |
| Envelope id | Yes | Idempotency and deduplication |
| Conversation id | Yes | Routing and queue partitioning |
| Sender device id | Yes | Authorization and abuse control |
| Recipient device ids | Yes | Delivery routing |
| Ratchet public key/header | Yes | Required by recipient ratchet state |
| Associated data | Yes | Authenticated protocol framing |
| Nonce | Yes | AEAD decryption input |
| Ciphertext | No plaintext | Encrypted payload only |
| Authentication tag | Yes | AEAD verification input |

## Plaintext payloads

One-to-one messages, group messages, images, files, voice notes, emoji reactions, replies, edits, deletes, read receipts, typing indicators, expiration metadata, and self-destruct metadata are represented as plaintext application events before encryption. After encryption, the server sees only encrypted envelopes.

## Replay and ordering

Clients reject duplicate envelope ids, repeated ratchet message numbers in the same receiving chain, invalid AEAD tags, stale skipped-message-key windows, and envelopes from revoked devices.

## Server responsibilities

- Validate that envelope routing identifiers are present.
- Verify the sender device is approved and not revoked before accepting an envelope.
- Store and forward ciphertext bytes without inspection or transformation.
- Avoid logging ciphertext, associated data, nonces, tags, keys, or plaintext-derived values.

## Phase 3 non-goals

- Group sender-key optimization.
- Attachment chunk encryption implementation.
- LAN/WebRTC synchronization.
- Voice/video calling.
