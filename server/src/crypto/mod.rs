//! Server-side cryptographic helpers.
//!
//! This module must never contain client private-key generation, storage, or
//! message decryption. Server cryptography is limited to public verification,
//! server transport security, and operational key rotation.

pub const AUTH_DOMAIN_SEPARATOR: &[u8] = b"secure-messaging.auth.v1";
