use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    Active,
    Redeemed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub invite_id: String,
    pub created_by_admin_device_id: String,
    pub invite_secret_hash: [u8; 32],
    pub created_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub max_redemptions: u8,
    pub redemption_count: u8,
    pub status: InviteStatus,
    pub revoked_at_unix_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRedemption {
    pub invite_id: String,
    pub candidate_device_id: String,
    pub candidate_identity_public_key_ed25519: [u8; 32],
    pub redeemed_at_unix_seconds: i64,
    pub requires_manual_approval: bool,
}

impl Invite {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invite_id: impl Into<String>,
        created_by_admin_device_id: impl Into<String>,
        invite_secret_hash: [u8; 32],
        created_at_unix_seconds: i64,
        expires_at_unix_seconds: i64,
        max_redemptions: u8,
    ) -> Result<Self, InviteError> {
        let invite_id = invite_id.into();
        let created_by_admin_device_id = created_by_admin_device_id.into();
        if invite_id.trim().is_empty() || created_by_admin_device_id.trim().is_empty() {
            return Err(InviteError::MissingIdentifier);
        }
        if invite_secret_hash == [0; 32] {
            return Err(InviteError::MissingSecretHash);
        }
        if expires_at_unix_seconds <= created_at_unix_seconds {
            return Err(InviteError::InvalidExpiration);
        }
        if max_redemptions == 0 {
            return Err(InviteError::InvalidRedemptionLimit);
        }

        Ok(Self {
            invite_id,
            created_by_admin_device_id,
            invite_secret_hash,
            created_at_unix_seconds,
            expires_at_unix_seconds,
            max_redemptions,
            redemption_count: 0,
            status: InviteStatus::Active,
            revoked_at_unix_seconds: None,
        })
    }

    pub fn revoke(&mut self, revoked_at_unix_seconds: i64) {
        self.status = InviteStatus::Revoked;
        self.revoked_at_unix_seconds = Some(revoked_at_unix_seconds);
    }

    pub fn redeem(
        &mut self,
        presented_secret_hash: [u8; 32],
        candidate_device_id: impl Into<String>,
        candidate_identity_public_key_ed25519: [u8; 32],
        now_unix_seconds: i64,
    ) -> Result<InviteRedemption, InviteError> {
        self.refresh_expiration(now_unix_seconds);
        if self.status != InviteStatus::Active {
            return Err(InviteError::InviteNotActive);
        }
        if presented_secret_hash != self.invite_secret_hash {
            return Err(InviteError::SecretMismatch);
        }
        if candidate_identity_public_key_ed25519 == [0; 32] {
            return Err(InviteError::InvalidCandidateIdentityKey);
        }
        let candidate_device_id = candidate_device_id.into();
        if candidate_device_id.trim().is_empty() {
            return Err(InviteError::MissingIdentifier);
        }

        self.redemption_count = self.redemption_count.saturating_add(1);
        if self.redemption_count >= self.max_redemptions {
            self.status = InviteStatus::Redeemed;
        }

        Ok(InviteRedemption {
            invite_id: self.invite_id.clone(),
            candidate_device_id,
            candidate_identity_public_key_ed25519,
            redeemed_at_unix_seconds: now_unix_seconds,
            requires_manual_approval: true,
        })
    }

    pub fn refresh_expiration(&mut self, now_unix_seconds: i64) {
        if self.status == InviteStatus::Active && now_unix_seconds >= self.expires_at_unix_seconds {
            self.status = InviteStatus::Expired;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    MissingIdentifier,
    MissingSecretHash,
    InvalidExpiration,
    InvalidRedemptionLimit,
    InviteNotActive,
    SecretMismatch,
    InvalidCandidateIdentityKey,
}

impl Display for InviteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for InviteError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_invite() -> Invite {
        Invite::new("invite-1", "admin-device", [8; 32], 100, 200, 1).expect("valid invite")
    }

    #[test]
    fn redeems_invite_once_and_requires_manual_approval() {
        let mut invite = active_invite();

        let redemption = invite
            .redeem([8; 32], "candidate-device", [9; 32], 120)
            .expect("valid redemption");

        assert_eq!(invite.status, InviteStatus::Redeemed);
        assert_eq!(invite.redemption_count, 1);
        assert!(redemption.requires_manual_approval);
        assert_eq!(redemption.invite_id, "invite-1");
    }

    #[test]
    fn rejects_reuse_after_single_redemption() {
        let mut invite = active_invite();
        invite
            .redeem([8; 32], "candidate-device", [9; 32], 120)
            .expect("valid redemption");

        assert_eq!(
            invite.redeem([8; 32], "other-device", [7; 32], 121),
            Err(InviteError::InviteNotActive)
        );
    }

    #[test]
    fn rejects_wrong_secret_hash() {
        let mut invite = active_invite();

        assert_eq!(
            invite.redeem([1; 32], "candidate-device", [9; 32], 120),
            Err(InviteError::SecretMismatch)
        );
    }

    #[test]
    fn rejects_expired_invite() {
        let mut invite = active_invite();

        assert_eq!(
            invite.redeem([8; 32], "candidate-device", [9; 32], 201),
            Err(InviteError::InviteNotActive)
        );
        assert_eq!(invite.status, InviteStatus::Expired);
    }

    #[test]
    fn rejects_revoked_invite() {
        let mut invite = active_invite();
        invite.revoke(110);

        assert_eq!(
            invite.redeem([8; 32], "candidate-device", [9; 32], 120),
            Err(InviteError::InviteNotActive)
        );
        assert_eq!(invite.revoked_at_unix_seconds, Some(110));
    }
}
