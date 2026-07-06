use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMemberRole {
    Owner,
    Admin,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMemberStatus {
    Active,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub device_id: String,
    pub role: GroupMemberRole,
    pub status: GroupMemberStatus,
    pub joined_at_unix_seconds: i64,
    pub removed_at_unix_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub group_id: String,
    pub created_by_device_id: String,
    pub encrypted_group_profile: Vec<u8>,
    pub profile_nonce: Vec<u8>,
    pub profile_authentication_tag: Vec<u8>,
    pub members: Vec<GroupMember>,
    pub created_at_unix_seconds: i64,
    pub membership_epoch: u64,
}

impl Group {
    pub fn new(
        group_id: impl Into<String>,
        created_by_device_id: impl Into<String>,
        encrypted_group_profile: Vec<u8>,
        profile_nonce: Vec<u8>,
        profile_authentication_tag: Vec<u8>,
        created_at_unix_seconds: i64,
    ) -> Result<Self, GroupError> {
        let group_id = group_id.into();
        let created_by_device_id = created_by_device_id.into();
        validate_identifier(&group_id)?;
        validate_identifier(&created_by_device_id)?;
        validate_encrypted_profile(
            &encrypted_group_profile,
            &profile_nonce,
            &profile_authentication_tag,
        )?;

        Ok(Self {
            group_id,
            created_by_device_id: created_by_device_id.clone(),
            encrypted_group_profile,
            profile_nonce,
            profile_authentication_tag,
            members: vec![GroupMember {
                device_id: created_by_device_id,
                role: GroupMemberRole::Owner,
                status: GroupMemberStatus::Active,
                joined_at_unix_seconds: created_at_unix_seconds,
                removed_at_unix_seconds: None,
            }],
            created_at_unix_seconds,
            membership_epoch: 1,
        })
    }

    pub fn add_member(
        &mut self,
        actor_device_id: &str,
        new_member_device_id: impl Into<String>,
        role: GroupMemberRole,
        joined_at_unix_seconds: i64,
    ) -> Result<(), GroupError> {
        self.require_admin(actor_device_id)?;
        let new_member_device_id = new_member_device_id.into();
        validate_identifier(&new_member_device_id)?;
        if role == GroupMemberRole::Owner {
            return Err(GroupError::CannotAddOwnerRole);
        }
        if self.active_member(&new_member_device_id).is_some() {
            return Err(GroupError::MemberAlreadyActive);
        }
        self.members.push(GroupMember {
            device_id: new_member_device_id,
            role,
            status: GroupMemberStatus::Active,
            joined_at_unix_seconds,
            removed_at_unix_seconds: None,
        });
        self.membership_epoch = self.membership_epoch.saturating_add(1);
        Ok(())
    }

    pub fn remove_member(
        &mut self,
        actor_device_id: &str,
        target_device_id: &str,
        removed_at_unix_seconds: i64,
    ) -> Result<(), GroupError> {
        self.require_admin(actor_device_id)?;
        if actor_device_id == target_device_id {
            return Err(GroupError::CannotRemoveSelf);
        }
        let target_index = self
            .members
            .iter()
            .position(|member| {
                member.device_id == target_device_id && member.status == GroupMemberStatus::Active
            })
            .ok_or(GroupError::MemberNotActive)?;
        if self.members[target_index].role == GroupMemberRole::Owner {
            return Err(GroupError::CannotRemoveOwner);
        }
        self.members[target_index].status = GroupMemberStatus::Removed;
        self.members[target_index].removed_at_unix_seconds = Some(removed_at_unix_seconds);
        self.membership_epoch = self.membership_epoch.saturating_add(1);
        Ok(())
    }

    pub fn rotate_encrypted_profile(
        &mut self,
        actor_device_id: &str,
        encrypted_group_profile: Vec<u8>,
        profile_nonce: Vec<u8>,
        profile_authentication_tag: Vec<u8>,
    ) -> Result<(), GroupError> {
        self.require_admin(actor_device_id)?;
        validate_encrypted_profile(
            &encrypted_group_profile,
            &profile_nonce,
            &profile_authentication_tag,
        )?;
        self.encrypted_group_profile = encrypted_group_profile;
        self.profile_nonce = profile_nonce;
        self.profile_authentication_tag = profile_authentication_tag;
        self.membership_epoch = self.membership_epoch.saturating_add(1);
        Ok(())
    }

    pub fn active_member(&self, device_id: &str) -> Option<&GroupMember> {
        self.members.iter().find(|member| {
            member.device_id == device_id && member.status == GroupMemberStatus::Active
        })
    }

    pub fn can_send(&self, device_id: &str) -> bool {
        self.active_member(device_id).is_some()
    }

    fn require_admin(&self, actor_device_id: &str) -> Result<(), GroupError> {
        match self.active_member(actor_device_id) {
            Some(member)
                if member.role == GroupMemberRole::Owner
                    || member.role == GroupMemberRole::Admin =>
            {
                Ok(())
            }
            Some(_) => Err(GroupError::InsufficientPermission),
            None => Err(GroupError::ActorNotActiveMember),
        }
    }
}

fn validate_identifier(value: &str) -> Result<(), GroupError> {
    if value.trim().is_empty() {
        return Err(GroupError::MissingIdentifier);
    }
    Ok(())
}

fn validate_encrypted_profile(
    encrypted_group_profile: &[u8],
    profile_nonce: &[u8],
    profile_authentication_tag: &[u8],
) -> Result<(), GroupError> {
    if encrypted_group_profile.is_empty() {
        return Err(GroupError::MissingEncryptedProfile);
    }
    if profile_nonce.len() < 12 {
        return Err(GroupError::InvalidProfileNonce);
    }
    if profile_authentication_tag.len() < 16 {
        return Err(GroupError::InvalidProfileAuthenticationTag);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum GroupError {
    MissingIdentifier,
    MissingEncryptedProfile,
    InvalidProfileNonce,
    InvalidProfileAuthenticationTag,
    ActorNotActiveMember,
    InsufficientPermission,
    CannotAddOwnerRole,
    MemberAlreadyActive,
    MemberNotActive,
    CannotRemoveSelf,
    CannotRemoveOwner,
}

impl Display for GroupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for GroupError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_profile() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (vec![1; 32], vec![2; 12], vec![3; 16])
    }

    fn group() -> Group {
        let (profile, nonce, tag) = encrypted_profile();
        Group::new("group-1", "owner-device", profile, nonce, tag, 100).expect("valid group")
    }

    #[test]
    fn creates_group_with_owner_and_encrypted_profile() {
        let group = group();

        assert_eq!(group.membership_epoch, 1);
        assert!(group.can_send("owner-device"));
        assert_eq!(group.members[0].role, GroupMemberRole::Owner);
    }

    #[test]
    fn admin_can_add_member_and_epoch_advances() {
        let mut group = group();

        group
            .add_member(
                "owner-device",
                "member-device",
                GroupMemberRole::Member,
                101,
            )
            .expect("owner can add member");

        assert!(group.can_send("member-device"));
        assert_eq!(group.membership_epoch, 2);
    }

    #[test]
    fn normal_member_cannot_add_member() {
        let mut group = group();
        group
            .add_member(
                "owner-device",
                "member-device",
                GroupMemberRole::Member,
                101,
            )
            .expect("owner can add member");

        assert_eq!(
            group.add_member(
                "member-device",
                "other-device",
                GroupMemberRole::Member,
                102
            ),
            Err(GroupError::InsufficientPermission)
        );
    }

    #[test]
    fn admin_can_remove_member_and_epoch_advances() {
        let mut group = group();
        group
            .add_member(
                "owner-device",
                "member-device",
                GroupMemberRole::Member,
                101,
            )
            .expect("owner can add member");

        group
            .remove_member("owner-device", "member-device", 102)
            .expect("owner can remove member");

        assert!(!group.can_send("member-device"));
        assert_eq!(group.membership_epoch, 3);
    }

    #[test]
    fn cannot_remove_group_owner() {
        let mut group = group();
        group
            .add_member("owner-device", "admin-device", GroupMemberRole::Admin, 101)
            .expect("owner can add admin");

        assert_eq!(
            group.remove_member("admin-device", "owner-device", 102),
            Err(GroupError::CannotRemoveOwner)
        );
    }

    #[test]
    fn rejects_plaintext_missing_encrypted_profile() {
        let result = Group::new(
            "group-1",
            "owner-device",
            vec![],
            vec![2; 12],
            vec![3; 16],
            100,
        );

        assert_eq!(result, Err(GroupError::MissingEncryptedProfile));
    }
}
