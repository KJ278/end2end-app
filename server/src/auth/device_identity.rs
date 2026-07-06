use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub display_name: String,
    pub identity_public_key_ed25519: [u8; 32],
    pub signed_prekey_public_key_x25519: [u8; 32],
    pub signed_prekey_signature_ed25519: [u8; 64],
    pub status: DeviceStatus,
    pub created_at_unix_seconds: i64,
    pub approved_at_unix_seconds: Option<i64>,
    pub revoked_at_unix_seconds: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    PendingApproval,
    Approved,
    Revoked,
}

impl DeviceIdentity {
    pub fn new_pending(
        device_id: impl Into<String>,
        display_name: impl Into<String>,
        identity_public_key_ed25519: [u8; 32],
        signed_prekey_public_key_x25519: [u8; 32],
        signed_prekey_signature_ed25519: [u8; 64],
        created_at_unix_seconds: i64,
    ) -> Result<Self, DeviceIdentityError> {
        let device_id = device_id.into();
        let display_name = display_name.into();
        if device_id.trim().is_empty() {
            return Err(DeviceIdentityError::EmptyDeviceId);
        }
        if display_name.trim().is_empty() {
            return Err(DeviceIdentityError::EmptyDisplayName);
        }
        if identity_public_key_ed25519 == [0; 32] {
            return Err(DeviceIdentityError::InvalidPublicKey);
        }
        if signed_prekey_public_key_x25519 == [0; 32] {
            return Err(DeviceIdentityError::InvalidSignedPrekey);
        }
        if signed_prekey_signature_ed25519 == [0; 64] {
            return Err(DeviceIdentityError::MissingSignedPrekeyProof);
        }

        Ok(Self {
            device_id,
            display_name,
            identity_public_key_ed25519,
            signed_prekey_public_key_x25519,
            signed_prekey_signature_ed25519,
            status: DeviceStatus::PendingApproval,
            created_at_unix_seconds,
            approved_at_unix_seconds: None,
            revoked_at_unix_seconds: None,
        })
    }

    pub fn approve(&mut self, approved_at_unix_seconds: i64) -> Result<(), DeviceIdentityError> {
        if self.status == DeviceStatus::Revoked {
            return Err(DeviceIdentityError::CannotApproveRevokedDevice);
        }
        self.status = DeviceStatus::Approved;
        self.approved_at_unix_seconds = Some(approved_at_unix_seconds);
        Ok(())
    }

    pub fn revoke(&mut self, revoked_at_unix_seconds: i64) {
        self.status = DeviceStatus::Revoked;
        self.revoked_at_unix_seconds = Some(revoked_at_unix_seconds);
    }

    pub fn can_authenticate(&self) -> bool {
        self.status == DeviceStatus::Approved && self.revoked_at_unix_seconds.is_none()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceIdentityError {
    EmptyDeviceId,
    EmptyDisplayName,
    InvalidPublicKey,
    InvalidSignedPrekey,
    MissingSignedPrekeyProof,
    CannotApproveRevokedDevice,
}

impl Display for DeviceIdentityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for DeviceIdentityError {}
