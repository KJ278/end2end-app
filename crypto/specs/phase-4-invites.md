# Phase 4 Invite System

## Scope

Phase 4 adds QR and one-time invite-code enrollment. Invites bootstrap device registration only; they never grant messaging access without administrator approval.

## Invite lifecycle

1. Administrator generates an invite with high-entropy random secret material.
2. Server stores only an invite id, creator id, secret hash/proof verifier, expiration, redemption limit, and status.
3. Candidate device scans the QR code or enters the one-time code.
4. Candidate submits the invite id, proof of invite secret possession, and its Ed25519 identity public key.
5. Server marks the invite redeemed when redemption limits are reached and creates a pending approval request.
6. Administrator manually approves or rejects the device.

## Security requirements

- Invite secrets must be generated with operating-system secure randomness.
- Invite secrets are bearer credentials and must be short-lived.
- One-time invite codes must be single-use by default.
- Server storage must use secret hashes or proof verifiers, not raw invite secrets.
- Invite redemption must bind the candidate's permanent device identity public key.
- Redeemed devices remain unable to authenticate for messaging until approved.
- Revoked or expired invites must not be redeemable.

## QR payload

The QR payload may contain an invite id, relay URL, expiration timestamp, and invite secret. It must not contain administrator credentials, server private keys, user private keys, or group message keys.

## Non-goals

- Public self-registration.
- Email or phone verification.
- Social login.
- Automatic approval.
