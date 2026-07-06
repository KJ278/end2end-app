pub const AUTH_DOMAIN_SEPARATOR: &[u8] = b"secure-messaging.auth.v1";
pub const MESSAGE_ENVELOPE_DOMAIN_SEPARATOR: &[u8] = b"secure-messaging.envelope.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAgreementAlgorithm {
    X25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519,
}
