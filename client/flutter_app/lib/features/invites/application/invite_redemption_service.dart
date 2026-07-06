import '../domain/invite.dart';

/// Redeems QR or one-time invite codes into a pending approval request.
///
/// Implementations must bind the redemption to the local Ed25519 device identity
/// public key. Successful redemption never grants messaging access directly; an
/// administrator must approve the device first.
abstract interface class InviteRedemptionService {
  Future<PendingInviteApproval> redeemInvite(InviteBootstrap invite);
}
