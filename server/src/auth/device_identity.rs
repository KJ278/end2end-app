use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Server-visible device identity record.
///
/// This record contains public information only. Private identity keys are
/// generated and stored on the client device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: Uuid,
    pub display_name: String,
    pub identity_public_key: VerifyingKey,
    pub signed_prekey_public_key: [u8; 32],
    pub signed_prekey_signature: Signature,
    pub status: DeviceStatus,
    pub created_at: OffsetDateTime,
    pub approved_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    PendingApproval,
    Approved,
    Revoked,
}

impl DeviceIdentity {
    pub fn new_pending(
        display_name: impl Into<String>,
        identity_public_key: VerifyingKey,
        signed_prekey_public_key: [u8; 32],
        signed_prekey_signature: Signature,
        created_at: OffsetDateTime,
    ) -> Result<Self, DeviceIdentityError> {
        let display_name = display_name.into();
        if display_name.trim().is_empty() {
            return Err(DeviceIdentityError::EmptyDisplayName);
        }

        identity_public_key
            .verify(&signed_prekey_public_key, &signed_prekey_signature)
            .map_err(|_| DeviceIdentityError::InvalidSignedPrekeySignature)?;

        Ok(Self {
            device_id: Uuid::new_v4(),
            display_name,
            identity_public_key,
            signed_prekey_public_key,
            signed_prekey_signature,
            status: DeviceStatus::PendingApproval,
            created_at,
            approved_at: None,
            revoked_at: None,
        })
    }

    pub fn approve(&mut self, approved_at: OffsetDateTime) -> Result<(), DeviceIdentityError> {
        if self.status == DeviceStatus::Revoked {
            return Err(DeviceIdentityError::CannotApproveRevokedDevice);
        }

        self.status = DeviceStatus::Approved;
        self.approved_at = Some(approved_at);
        Ok(())
    }

    pub fn revoke(&mut self, revoked_at: OffsetDateTime) {
        self.status = DeviceStatus::Revoked;
        self.revoked_at = Some(revoked_at);
    }

    pub fn can_authenticate(&self) -> bool {
        self.status == DeviceStatus::Approved && self.revoked_at.is_none()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceIdentityError {
    #[error("display name must not be empty")]
    EmptyDisplayName,
    #[error("signed pre-key signature does not verify against the identity key")]
    InvalidSignedPrekeySignature,
    #[error("revoked devices cannot be re-approved")]
    CannotApproveRevokedDevice,
}
