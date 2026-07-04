use std::error::Error;
use std::fmt::{Display, Formatter};

use super::ratchet::RatchetHeader;

pub const MIN_NONCE_BYTES: usize = 12;
pub const MIN_AUTH_TAG_BYTES: usize = 16;
pub const MAX_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    OneToOneMessage,
    GroupMessage,
    DeliveryReceipt,
    ReadReceipt,
    TypingIndicator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub envelope_id: String,
    pub conversation_id: String,
    pub sender_device_id: String,
    pub recipient_device_ids: Vec<String>,
    pub kind: EnvelopeKind,
    pub ratchet_header: RatchetHeader,
    pub associated_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authentication_tag: Vec<u8>,
    pub server_received_at_unix_seconds: i64,
}

impl EncryptedEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        conversation_id: impl Into<String>,
        sender_device_id: impl Into<String>,
        recipient_device_ids: Vec<String>,
        kind: EnvelopeKind,
        ratchet_header: RatchetHeader,
        associated_data: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        authentication_tag: Vec<u8>,
        server_received_at_unix_seconds: i64,
    ) -> Result<Self, EncryptedEnvelopeError> {
        let envelope = Self {
            envelope_id: envelope_id.into(),
            conversation_id: conversation_id.into(),
            sender_device_id: sender_device_id.into(),
            recipient_device_ids,
            kind,
            ratchet_header,
            associated_data,
            nonce,
            ciphertext,
            authentication_tag,
            server_received_at_unix_seconds,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), EncryptedEnvelopeError> {
        if self.envelope_id.trim().is_empty()
            || self.conversation_id.trim().is_empty()
            || self.sender_device_id.trim().is_empty()
        {
            return Err(EncryptedEnvelopeError::MissingRoutingIdentifier);
        }
        if self.recipient_device_ids.is_empty()
            || self
                .recipient_device_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return Err(EncryptedEnvelopeError::MissingRecipient);
        }
        if self
            .recipient_device_ids
            .iter()
            .any(|id| id == &self.sender_device_id)
        {
            return Err(EncryptedEnvelopeError::SenderIncludedAsRecipient);
        }
        if self.ratchet_header.sender_ratchet_public_key_x25519 == [0; 32] {
            return Err(EncryptedEnvelopeError::InvalidRatchetHeader);
        }
        if self.nonce.len() < MIN_NONCE_BYTES {
            return Err(EncryptedEnvelopeError::InvalidNonce);
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(EncryptedEnvelopeError::InvalidCiphertextSize);
        }
        if self.authentication_tag.len() < MIN_AUTH_TAG_BYTES {
            return Err(EncryptedEnvelopeError::InvalidAuthenticationTag);
        }
        Ok(())
    }

    pub fn contains_plaintext_hint(&self, forbidden: &[&[u8]]) -> bool {
        forbidden.iter().any(|needle| {
            !needle.is_empty()
                && (self
                    .associated_data
                    .windows(needle.len())
                    .any(|window| window == *needle)
                    || self
                        .ciphertext
                        .windows(needle.len())
                        .any(|window| window == *needle))
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptedEnvelopeError {
    MissingRoutingIdentifier,
    MissingRecipient,
    SenderIncludedAsRecipient,
    InvalidRatchetHeader,
    InvalidNonce,
    InvalidCiphertextSize,
    InvalidAuthenticationTag,
}

impl Display for EncryptedEnvelopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for EncryptedEnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> RatchetHeader {
        RatchetHeader::new([7; 32], 0, 1)
    }

    fn valid_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope::new(
            "env-1",
            "conversation-1",
            "sender-device",
            vec!["recipient-device".to_owned()],
            EnvelopeKind::OneToOneMessage,
            valid_header(),
            b"secure-messaging.envelope.v1".to_vec(),
            vec![1; MIN_NONCE_BYTES],
            vec![2; 128],
            vec![3; MIN_AUTH_TAG_BYTES],
            1000,
        )
        .expect("valid encrypted envelope")
    }

    #[test]
    fn accepts_valid_encrypted_envelope() {
        assert_eq!(valid_envelope().validate(), Ok(()));
    }

    #[test]
    fn rejects_missing_recipient() {
        let envelope = EncryptedEnvelope::new(
            "env-1",
            "conversation-1",
            "sender-device",
            vec![],
            EnvelopeKind::OneToOneMessage,
            valid_header(),
            vec![],
            vec![1; MIN_NONCE_BYTES],
            vec![2; 128],
            vec![3; MIN_AUTH_TAG_BYTES],
            1000,
        );

        assert_eq!(envelope, Err(EncryptedEnvelopeError::MissingRecipient));
    }

    #[test]
    fn rejects_sender_as_recipient() {
        let envelope = EncryptedEnvelope::new(
            "env-1",
            "conversation-1",
            "sender-device",
            vec!["sender-device".to_owned()],
            EnvelopeKind::OneToOneMessage,
            valid_header(),
            vec![],
            vec![1; MIN_NONCE_BYTES],
            vec![2; 128],
            vec![3; MIN_AUTH_TAG_BYTES],
            1000,
        );

        assert_eq!(
            envelope,
            Err(EncryptedEnvelopeError::SenderIncludedAsRecipient)
        );
    }

    #[test]
    fn rejects_zero_ratchet_public_key() {
        let envelope = EncryptedEnvelope::new(
            "env-1",
            "conversation-1",
            "sender-device",
            vec!["recipient-device".to_owned()],
            EnvelopeKind::OneToOneMessage,
            RatchetHeader::new([0; 32], 0, 1),
            vec![],
            vec![1; MIN_NONCE_BYTES],
            vec![2; 128],
            vec![3; MIN_AUTH_TAG_BYTES],
            1000,
        );

        assert_eq!(envelope, Err(EncryptedEnvelopeError::InvalidRatchetHeader));
    }

    #[test]
    fn rejects_empty_ciphertext() {
        let envelope = EncryptedEnvelope::new(
            "env-1",
            "conversation-1",
            "sender-device",
            vec!["recipient-device".to_owned()],
            EnvelopeKind::OneToOneMessage,
            valid_header(),
            vec![],
            vec![1; MIN_NONCE_BYTES],
            vec![],
            vec![3; MIN_AUTH_TAG_BYTES],
            1000,
        );

        assert_eq!(envelope, Err(EncryptedEnvelopeError::InvalidCiphertextSize));
    }

    #[test]
    fn detects_forbidden_plaintext_hints() {
        let envelope = valid_envelope();
        assert!(envelope.contains_plaintext_hint(&[b"envelope.v1"]));
        assert!(!envelope.contains_plaintext_hint(&[b"hello plaintext"]));
    }
}
