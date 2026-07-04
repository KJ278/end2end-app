# Secure Private Messaging Application

This repository contains an incrementally built, invite-only private messaging system for a small trusted group. The project prioritizes end-to-end encryption, public-key authentication, manual user approval, and minimal operational metadata.

## Phase status

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Architecture and folder structure | Complete |
| 2 | Authentication and key generation | Pending approval |
| 3 | End-to-end encrypted messaging | Pending |
| 4 | Invite system | Pending |
| 5 | Groups | Pending |
| 6 | File sharing | Pending |
| 7 | Offline synchronization | Pending |
| 8 | UI polish | Pending |
| 9 | Testing | Pending |
| 10 | Deployment | Pending |

## Repository layout

```text
client/          Flutter application using Clean Architecture, Riverpod, GetIt, GoRouter, Dio, and SQLCipher.
server/          Rust backend skeleton for WebSocket relay, approval, device registry, and administrative APIs.
shared/          Cross-platform protocol definitions and schemas shared by clients and server.
crypto/          Cryptographic protocol specifications, test vectors, and audit notes.
docs/            Architecture, security, API, operations, and onboarding documentation.
infrastructure/  Docker, CI/CD, Kubernetes, and Terraform infrastructure assets.
deployment/      Environment-specific deployment manifests and scripts.
tests/           Cross-system integration, load, and penetration-test assets.
```

## Security principles

- The server never receives plaintext message content, private keys, or recovery secrets.
- Authentication is based on device identity keys and signed challenges; passwords are out of scope.
- New devices must be invited and manually approved before they can communicate.
- Revocation is enforced by server-side authorization and client-side encrypted state synchronization.
- Logs must contain only operational events and must never include message bodies, keys, tokens, or secrets.

## Next step

Phase 2 will add client-side identity key generation, secure local secret storage abstractions, and public-key authentication protocol definitions after approval.
