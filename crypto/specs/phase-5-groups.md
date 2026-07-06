# Phase 5 Groups

## Scope

Phase 5 adds group membership contracts and encrypted group metadata. Group message payloads continue to use encrypted envelopes from Phase 3; the server must not receive plaintext group names, descriptions, avatars, membership notes, message bodies, or group message keys.

## Membership model

- Every group has a server-visible group id and membership epoch.
- Members are tracked by approved device identity, role, and active/removed status.
- Owners and administrators can add or remove members.
- Removed devices must not be able to send future group envelopes.
- Membership changes advance the membership epoch.

## Encrypted group profile

Group names, descriptions, avatars, notification labels, and other human-readable profile metadata are stored in an encrypted profile blob with an AEAD nonce and authentication tag.

## Keying strategy

The first implementation uses pairwise encrypted sender material or per-recipient encrypted group state until a reviewed sender-key optimization is introduced. Membership changes must rotate group encryption state so removed devices cannot decrypt future messages.

## Server responsibilities

- Enforce that only active group members can send to a group.
- Enforce administrator permissions for membership changes.
- Store encrypted group profile bytes without inspection.
- Avoid logging group profile ciphertext, nonces, authentication tags, or plaintext-derived labels.

## Non-goals

- Large public communities.
- Public group discovery.
- Server-readable group metadata.
- Voice/video group calls.
