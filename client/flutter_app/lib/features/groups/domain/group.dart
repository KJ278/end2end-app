/// Server-routable group state with encrypted profile metadata.
///
/// Human-readable group names, avatars, descriptions, and policy labels belong
/// inside [encryptedGroupProfile], not in server-visible fields.
final class SecureGroup {
  const SecureGroup({
    required this.groupId,
    required this.membershipEpoch,
    required this.encryptedGroupProfile,
    required this.profileNonce,
    required this.profileAuthenticationTag,
    required this.members,
  });

  final String groupId;
  final int membershipEpoch;
  final List<int> encryptedGroupProfile;
  final List<int> profileNonce;
  final List<int> profileAuthenticationTag;
  final List<GroupMember> members;
}

final class GroupMember {
  const GroupMember({
    required this.deviceId,
    required this.role,
    required this.isActive,
  });

  final String deviceId;
  final GroupMemberRole role;
  final bool isActive;
}

enum GroupMemberRole { owner, admin, member }
