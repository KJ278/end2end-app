use std::error::Error;
use std::fmt::{Display, Formatter};

use super::device_identity::DeviceIdentity;

pub const CHALLENGE_NONCE_BYTES: usize = 32;
pub const CHALLENGE_DOMAIN: &[u8] = b"secure-messaging.auth.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub challenge_id: String,
    pub device_id: String,
    pub nonce: [u8; CHALLENGE_NONCE_BYTES],
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthChallenge {
    pub challenge_id: String,
    pub device_id: String,
    pub signature_ed25519: [u8; 64],
}

impl AuthChallenge {
    pub fn new(
        challenge_id: impl Into<String>,
        device_id: impl Into<String>,
        nonce: [u8; CHALLENGE_NONCE_BYTES],
        issued_at_unix_seconds: i64,
        ttl_seconds: i64,
    ) -> Result<Self, AuthChallengeError> {
        let challenge_id = challenge_id.into();
        let device_id = device_id.into();
        if challenge_id.trim().is_empty() || device_id.trim().is_empty() {
            return Err(AuthChallengeError::EmptyIdentifier);
        }
        if nonce == [0; CHALLENGE_NONCE_BYTES] {
            return Err(AuthChallengeError::InvalidNonce);
        }
        if ttl_seconds <= 0 || ttl_seconds > 300 {
            return Err(AuthChallengeError::InvalidTtl);
        }
        Ok(Self {
            challenge_id,
            device_id,
            nonce,
            issued_at_unix_seconds,
            expires_at_unix_seconds: issued_at_unix_seconds + ttl_seconds,
        })
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(CHALLENGE_DOMAIN);
        payload.extend_from_slice(self.challenge_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.device_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.expires_at_unix_seconds.to_be_bytes());
        payload
    }

    pub fn is_expired(&self, now_unix_seconds: i64) -> bool {
        now_unix_seconds >= self.expires_at_unix_seconds
    }
}

pub struct AuthChallengeVerifier;

impl AuthChallengeVerifier {
    pub fn verify_metadata(
        challenge: &AuthChallenge,
        signed: &SignedAuthChallenge,
        device: &DeviceIdentity,
        now_unix_seconds: i64,
    ) -> Result<(), AuthChallengeError> {
        if challenge.is_expired(now_unix_seconds) {
            return Err(AuthChallengeError::ExpiredChallenge);
        }
        if challenge.challenge_id != signed.challenge_id || challenge.device_id != signed.device_id
        {
            return Err(AuthChallengeError::ChallengeMismatch);
        }
        if device.device_id != challenge.device_id {
            return Err(AuthChallengeError::DeviceMismatch);
        }
        if !device.can_authenticate() {
            return Err(AuthChallengeError::DeviceNotApproved);
        }
        if signed.signature_ed25519 == [0; 64] {
            return Err(AuthChallengeError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthChallengeError {
    EmptyIdentifier,
    InvalidNonce,
    InvalidTtl,
    ExpiredChallenge,
    ChallengeMismatch,
    DeviceMismatch,
    DeviceNotApproved,
    InvalidSignature,
}

impl Display for AuthChallengeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for AuthChallengeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::device_identity::DeviceIdentity;

    fn approved_device() -> DeviceIdentity {
        let mut device =
            DeviceIdentity::new_pending("device-1", "Test", [1; 32], [2; 32], [3; 64], 100)
                .expect("valid public key material");
        device.approve(101).expect("pending device approval");
        device
    }

    #[test]
    fn builds_domain_separated_signing_payload() {
        let challenge = AuthChallenge::new("challenge-1", "device-1", [9; 32], 100, 60)
            .expect("valid challenge");
        let payload = challenge.signing_payload();

        assert!(payload.starts_with(CHALLENGE_DOMAIN));
        assert!(
            payload
                .windows("challenge-1".len())
                .any(|window| window == b"challenge-1")
        );
        assert!(
            payload
                .windows("device-1".len())
                .any(|window| window == b"device-1")
        );
    }

    #[test]
    fn rejects_pending_device_metadata() {
        let device =
            DeviceIdentity::new_pending("device-1", "Test", [1; 32], [2; 32], [3; 64], 100)
                .expect("valid public key material");
        let challenge = AuthChallenge::new("challenge-1", "device-1", [9; 32], 100, 60)
            .expect("valid challenge");
        let signed = SignedAuthChallenge {
            challenge_id: "challenge-1".to_owned(),
            device_id: "device-1".to_owned(),
            signature_ed25519: [4; 64],
        };

        assert_eq!(
            AuthChallengeVerifier::verify_metadata(&challenge, &signed, &device, 120),
            Err(AuthChallengeError::DeviceNotApproved)
        );
    }

    #[test]
    fn rejects_expired_challenge_metadata() {
        let device = approved_device();
        let challenge = AuthChallenge::new("challenge-1", "device-1", [9; 32], 100, 60)
            .expect("valid challenge");
        let signed = SignedAuthChallenge {
            challenge_id: "challenge-1".to_owned(),
            device_id: "device-1".to_owned(),
            signature_ed25519: [4; 64],
        };

        assert_eq!(
            AuthChallengeVerifier::verify_metadata(&challenge, &signed, &device, 160),
            Err(AuthChallengeError::ExpiredChallenge)
        );
    }

    #[test]
    fn accepts_valid_approved_device_challenge_metadata() {
        let device = approved_device();
        let challenge = AuthChallenge::new("challenge-1", "device-1", [9; 32], 100, 60)
            .expect("valid challenge");
        let signed = SignedAuthChallenge {
            challenge_id: "challenge-1".to_owned(),
            device_id: "device-1".to_owned(),
            signature_ed25519: [4; 64],
        };

        assert_eq!(
            AuthChallengeVerifier::verify_metadata(&challenge, &signed, &device, 159),
            Ok(())
        );
    }
}
