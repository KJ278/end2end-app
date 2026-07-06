/// Invite material scanned from a QR code or entered as a one-time code.
///
/// [secret] is the bearer secret and must be cleared from memory as soon as the
/// redemption request is constructed. Only a server-side hash of this value may
/// be stored by infrastructure.
final class InviteBootstrap {
  const InviteBootstrap({
    required this.inviteId,
    required this.relayUrl,
    required this.secret,
    required this.expiresAt,
  });

  final String inviteId;
  final Uri relayUrl;
  final List<int> secret;
  final DateTime expiresAt;
}

/// Result of redeeming an invite before administrator approval.
final class PendingInviteApproval {
  const PendingInviteApproval({
    required this.inviteId,
    required this.candidateDeviceId,
    required this.submittedAt,
  });

  final String inviteId;
  final String candidateDeviceId;
  final DateTime submittedAt;
}
