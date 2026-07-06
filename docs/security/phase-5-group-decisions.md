# Phase 5 Security Decisions: Groups

## Decisions

1. **Group metadata is encrypted**: names, avatars, descriptions, and labels are not server-readable.
2. **Membership epochs are explicit**: every membership change increments the epoch to force client-side key rotation.
3. **Removed devices lose future access**: removed members cannot send and must not receive future group key material.
4. **Administrative changes are gated**: only active owners and administrators can add or remove members.
5. **Owner protection**: owners cannot be removed by another administrator in the current model.
6. **Sender-key optimization is deferred**: pairwise/per-recipient group state remains the baseline until a separate review approves sender keys.

## Phase 6 prerequisites

Secure file sharing must define chunk encryption, content-addressing rules that do not leak plaintext, attachment size limits, resumable transfer integrity, and deletion semantics.
