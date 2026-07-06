# Security Baseline

## Non-negotiable constraints

- Do not invent custom cryptography.
- Do not log message contents, private keys, encryption keys, invite secrets, tokens, or authentication challenge material.
- Do not implement password, email, phone-number, social-login, analytics, advertising, tracking, or cloud-backup systems.
- Do not allow unapproved devices to send or receive application messages.

## Approved cryptographic building blocks

- Identity signatures: Ed25519.
- Key agreement: X25519.
- Message encryption: ChaCha20-Poly1305 or AES-256-GCM.
- Key derivation: HKDF.
- Messaging protocol: Signal Double Ratchet with forward secrecy and practical post-compromise security.
- Randomness: operating-system secure random number generation only.

## Secret storage targets

| Platform | Secret storage target |
| --- | --- |
| Android | Android Keystore-backed storage |
| iOS | Keychain with Secure Enclave support where available |
| Windows | OS credential storage where available |
| macOS | Keychain |
| Linux | Secret Service/libsecret-compatible credential storage where available |

## Threat model seed

Primary threats include stolen server infrastructure, compromised network paths, unauthorized device enrollment, replayed invites, lost or stolen devices, metadata leakage, malicious logs, and implementation bugs in cryptographic state transitions.

## Phase 2 security gates

Before implementing authentication, the project must define identity-key lifecycle, challenge formats, secure-storage interfaces, invite bootstrap states, revocation semantics, and cryptographic test expectations.
