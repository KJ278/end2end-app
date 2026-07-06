import '../domain/device_key_bundle.dart';

/// Generates and stores device identity material.
///
/// Implementations must use audited cryptographic libraries and operating-system
/// secure random number generation. Private keys must be persisted only via the
/// secure key-store abstraction.
abstract interface class DeviceIdentityService {
  Future<DeviceKeyBundle> createDeviceIdentity();

  Future<DeviceKeyBundle?> loadPublicDeviceKeyBundle();

  Future<List<int>> signAuthenticationChallenge(List<int> challengePayload);
}
