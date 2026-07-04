/// Public key material generated on a device during Phase 2 enrollment.
///
/// Private keys are intentionally absent from this model. They must remain in
/// platform secure storage and must never be serialized for transport.
final class DeviceKeyBundle {
  const DeviceKeyBundle({
    required this.identityPublicKeyEd25519,
    required this.signedPrekeyPublicKeyX25519,
    required this.signedPrekeySignatureEd25519,
    required this.createdAt,
  });

  final List<int> identityPublicKeyEd25519;
  final List<int> signedPrekeyPublicKeyX25519;
  final List<int> signedPrekeySignatureEd25519;
  final DateTime createdAt;
}
