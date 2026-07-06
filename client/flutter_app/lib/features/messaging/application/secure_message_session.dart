import '../domain/encrypted_envelope.dart';

/// Encrypts and decrypts application messages using Double Ratchet session state.
///
/// Implementations must use X25519, HKDF, and an approved AEAD such as
/// ChaCha20-Poly1305 or AES-256-GCM. Session state and skipped message keys must
/// be persisted only through encrypted local storage.
abstract interface class SecureMessageSession {
  Future<EncryptedEnvelope> encryptMessage({
    required String conversationId,
    required String senderDeviceId,
    required List<String> recipientDeviceIds,
    required List<int> plaintext,
  });

  Future<List<int>> decryptEnvelope(EncryptedEnvelope envelope);
}
