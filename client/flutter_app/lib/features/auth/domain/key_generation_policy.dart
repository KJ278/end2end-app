/// Phase 2 key-generation requirements for the client.
final class KeyGenerationPolicy {
  const KeyGenerationPolicy._();

  static const identityAlgorithm = 'Ed25519';
  static const keyAgreementAlgorithm = 'X25519';
  static const authDomainSeparator = 'secure-messaging.auth.v1';
  static const signedPrekeyRotationDays = 30;
}
