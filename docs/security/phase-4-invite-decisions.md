# Phase 4 Security Decisions: Invite System

## Decisions

1. **Invites are bootstrap-only**: redeeming an invite creates a pending approval request rather than granting messaging access.
2. **Single-use default**: invite records support redemption limits and transition to redeemed once the limit is reached.
3. **No raw secret persistence**: server-side invite records store secret hashes or proof verifiers, never QR/code bearer secrets.
4. **Identity binding**: redemption records include the candidate Ed25519 identity public key so administrator approval is tied to a permanent device identity.
5. **Expiration and revocation are authoritative**: expired and revoked invites cannot be redeemed.
6. **Admin-controlled access**: approval remains a separate administrator action after successful invite redemption.

## Phase 5 prerequisites

Group support must define group membership authorization, sender-key or pairwise encryption strategy, membership-change handling, and encrypted group metadata.
