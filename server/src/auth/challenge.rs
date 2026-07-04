use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::device_identity::DeviceIdentity;

const CHALLENGE_NONCE_BYTES: usize = 32;
const CHALLENGE_DOMAIN: &[u8] = b"secure-messaging.auth.v1";

/// Short-lived server challenge signed by a device identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge_id: Uuid,
    pub device_id: Uuid,
    pub nonce: ChallengeNonce,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Zeroizing challenge nonce to reduce accidental retention in memory dumps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChallengeNonce([u8; CHALLENGE_NONCE_BYTES]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuthChallenge {
    pub challenge_id: Uuid,
    pub device_id: Uuid,
    pub signature: Signature,
}

impl AuthChallenge {
    pub fn issue(device_id: Uuid, issued_at: OffsetDateTime, ttl: Duration) -> Self {
        let mut nonce = [0_u8; CHALLENGE_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);

        Self {
            challenge_id: Uuid::new_v4(),
            device_id,
            nonce: ChallengeNonce(nonce),
            issued_at,
            expires_at: issued_at + ttl,
        }
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(CHALLENGE_DOMAIN.len() + 16 + 16 + CHALLENGE_NONCE_BYTES + 16);
        payload.extend_from_slice(CHALLENGE_DOMAIN);
        payload.extend_from_slice(self.challenge_id.as_bytes());
        payload.extend_from_slice(self.device_id.as_bytes());
        payload.extend_from_slice(&self.nonce.0);
        payload.extend_from_slice(&self.expires_at.unix_timestamp().to_be_bytes());
        payload
    }

    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }
}

/// Stateless verifier for a signed authentication challenge.
pub struct AuthChallengeVerifier;

impl AuthChallengeVerifier {
    pub fn verify(
        challenge: &AuthChallenge,
        signed: &SignedAuthChallenge,
        device: &DeviceIdentity,
        now: OffsetDateTime,
    ) -> Result<(), AuthChallengeError> {
        if challenge.is_expired(now) {
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

        verify_signature(
            &device.identity_public_key,
            &challenge.signing_payload(),
            &signed.signature,
        )
    }
}

fn verify_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature: &Signature,
) -> Result<(), AuthChallengeError> {
    verifying_key
        .verify(payload, signature)
        .map_err(|_| AuthChallengeError::InvalidSignature)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthChallengeError {
    #[error("authentication challenge is expired")]
    ExpiredChallenge,
    #[error("signed challenge identifiers do not match issued challenge")]
    ChallengeMismatch,
    #[error("challenge device does not match registered device")]
    DeviceMismatch,
    #[error("device must be approved and not revoked before authentication")]
    DeviceNotApproved,
    #[error("challenge signature is invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    use super::*;
    use crate::auth::device_identity::DeviceIdentity;

    fn approved_device(now: OffsetDateTime) -> (SigningKey, DeviceIdentity) {
        let identity_key = SigningKey::generate(&mut OsRng);
        let signed_prekey = [7_u8; 32];
        let signed_prekey_signature = identity_key.sign(&signed_prekey);
        let mut device = DeviceIdentity::new_pending(
            "Test Device",
            identity_key.verifying_key(),
            signed_prekey,
            signed_prekey_signature,
            now,
        )
        .expect("valid signed pre-key");
        device.approve(now).expect("pending device can be approved");
        (identity_key, device)
    }

    #[test]
    fn accepts_valid_signature_from_approved_device() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (identity_key, device) = approved_device(now);
        let challenge = AuthChallenge::issue(device.device_id, now, Duration::minutes(5));
        let signed = SignedAuthChallenge {
            challenge_id: challenge.challenge_id,
            device_id: device.device_id,
            signature: identity_key.sign(&challenge.signing_payload()),
        };

        let result = AuthChallengeVerifier::verify(&challenge, &signed, &device, now);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_pending_device_even_with_valid_signature() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let identity_key = SigningKey::generate(&mut OsRng);
        let signed_prekey = [8_u8; 32];
        let signed_prekey_signature = identity_key.sign(&signed_prekey);
        let device = DeviceIdentity::new_pending(
            "Pending Device",
            identity_key.verifying_key(),
            signed_prekey,
            signed_prekey_signature,
            now,
        )
        .expect("valid signed pre-key");
        let challenge = AuthChallenge::issue(device.device_id, now, Duration::minutes(5));
        let signed = SignedAuthChallenge {
            challenge_id: challenge.challenge_id,
            device_id: device.device_id,
            signature: identity_key.sign(&challenge.signing_payload()),
        };

        let result = AuthChallengeVerifier::verify(&challenge, &signed, &device, now);

        assert_eq!(result, Err(AuthChallengeError::DeviceNotApproved));
    }

    #[test]
    fn rejects_expired_challenge() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (identity_key, device) = approved_device(now);
        let challenge = AuthChallenge::issue(device.device_id, now, Duration::seconds(1));
        let signed = SignedAuthChallenge {
            challenge_id: challenge.challenge_id,
            device_id: device.device_id,
            signature: identity_key.sign(&challenge.signing_payload()),
        };

        let result =
            AuthChallengeVerifier::verify(&challenge, &signed, &device, now + Duration::seconds(2));

        assert_eq!(result, Err(AuthChallengeError::ExpiredChallenge));
    }

    #[test]
    fn rejects_tampered_signature() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (identity_key, device) = approved_device(now);
        let attacker_key = SigningKey::generate(&mut OsRng);
        let challenge = AuthChallenge::issue(device.device_id, now, Duration::minutes(5));
        let signed = SignedAuthChallenge {
            challenge_id: challenge.challenge_id,
            device_id: device.device_id,
            signature: attacker_key.sign(&challenge.signing_payload()),
        };

        let result = AuthChallengeVerifier::verify(&challenge, &signed, &device, now);

        assert_eq!(result, Err(AuthChallengeError::InvalidSignature));
        drop(identity_key);
    }
}
