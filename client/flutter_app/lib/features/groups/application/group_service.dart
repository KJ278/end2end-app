import '../domain/group.dart';

/// Manages encrypted group metadata and membership epochs.
///
/// Implementations must rotate group encryption state whenever membership
/// changes so removed devices cannot decrypt future group messages.
abstract interface class GroupService {
  Future<SecureGroup> createGroup({
    required List<String> initialMemberDeviceIds,
    required List<int> plaintextGroupProfile,
  });

  Future<SecureGroup> addMember({
    required String groupId,
    required String deviceId,
  });

  Future<SecureGroup> removeMember({
    required String groupId,
    required String deviceId,
  });
}
