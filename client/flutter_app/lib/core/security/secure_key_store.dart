/// Secure storage abstraction for long-lived client secrets.
///
/// Implementations must bind to platform secure storage:
/// - Android Keystore-backed storage.
/// - iOS Keychain with Secure Enclave support where available.
/// - macOS Keychain.
/// - Windows Credential Manager or DPAPI-backed storage.
/// - Linux Secret Service/libsecret-compatible storage where available.
abstract interface class SecureKeyStore {
  Future<void> writeSecret({required String keyId, required List<int> value});

  Future<List<int>?> readSecret({required String keyId});

  Future<void> deleteSecret({required String keyId});
}
