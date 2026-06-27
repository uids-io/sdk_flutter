import 'dart:async';
import 'dart:convert';

import '../errors/uids_auth_exception.dart';
import '../logging/sdk_logger.dart';
import '../models/device_models.dart';
import '../network/auth_api_client.dart';
import '../storage/sdk_storage.dart';
import '../storage/storage_keys.dart';

/// Callback that yields a backend access token on demand.
///
/// DeviceManager intentionally does NOT depend on SessionManager — it only
/// needs a way to obtain a valid access token at the moment of a backend call.
/// The SDK facade wires this to `SessionManager.getValidSession`.
typedef AccessTokenProvider = Future<String> Function();

/// Manages device registration and its cached state.
///
/// Rules:
/// - All write operations require a valid backend access token, fetched lazily
///   via [AccessTokenProvider].
/// - [ensureDeviceRegistered] is idempotent: it returns the cached device if
///   one exists, otherwise calls the backend.
/// - The backend registration endpoint should also be idempotent, keyed on
///   [DeviceRegisterRequest.stableDeviceKey].
/// - Device state is independent of the auth session; signing out does not
///   automatically clear or unregister a device.
final class DeviceManager {
  DeviceManager({
    required AuthApiClient apiClient,
    required AccessTokenProvider tokenProvider,
    required SdkStorage storage,
    SdkLogger? logger,
  })  : _api = apiClient,
        _tokenProvider = tokenProvider,
        _storage = storage,
        _log = logger ?? SdkLogger(onLog: null);

  final AuthApiClient _api;
  final AccessTokenProvider _tokenProvider;
  final SdkStorage _storage;
  final SdkLogger _log;

  RegisteredDevice? _memoryCache;

  final _deviceController = StreamController<RegisteredDevice?>.broadcast();

  /// Stream of device changes.  Emits `null` on unregister.
  Stream<RegisteredDevice?> get deviceChanges => _deviceController.stream;

  // ── Public API ────────────────────────────────────────────────────────────

  /// Returns the cached device (memory → secure storage), or `null`.
  Future<RegisteredDevice?> currentDevice() async {
    if (_memoryCache != null) return _memoryCache;
    return _loadFromStorage();
  }

  /// Registers [request] with the backend unconditionally.
  Future<RegisteredDevice> registerDevice(
    DeviceRegisterRequest request,
  ) async {
    _log.info('Device registration started', {
      'stableDeviceKey': request.stableDeviceKey,
    });
    final token = await _accessToken();
    try {
      final device = await _api.registerDevice(request, token);
      await _saveDevice(device);
      _log.info('Device registration succeeded', {'deviceId': device.id});
      return device;
    } catch (e, st) {
      _log.warn(
        'Device registration failed',
        error: e,
        stackTrace: st,
        data: {'stableDeviceKey': request.stableDeviceKey},
      );
      throw UidsDeviceRegistrationException(
        'Failed to register device.',
        cause: e,
      );
    }
  }

  /// Returns the cached device, or registers [request] if no cache exists.
  ///
  /// The backend must be idempotent (keyed on
  /// [DeviceRegisterRequest.stableDeviceKey]).
  Future<RegisteredDevice> ensureDeviceRegistered(
    DeviceRegisterRequest request,
  ) async {
    final cached = await currentDevice();
    if (cached != null) {
      _log.trace('ensureDeviceRegistered: using cached device', {
        'deviceId': cached.id,
      });
      return cached;
    }
    return registerDevice(request);
  }

  /// Updates the cached device with [request].
  Future<RegisteredDevice> updateDevice(DeviceUpdateRequest request) async {
    final device = await currentDevice();
    if (device == null) {
      throw const UidsDeviceRegistrationException(
        'No registered device found. Call registerDevice() first.',
      );
    }
    final token = await _accessToken();
    final updated = await _api.updateDevice(device.id, request, token);
    await _saveDevice(updated);
    return updated;
  }

  /// Unregisters the current device from the backend and clears the cache.
  Future<void> unregisterDevice() async {
    final device = await currentDevice();
    if (device == null) {
      _log.trace('unregisterDevice: no cached device');
      return;
    }
    _log.info('Device unregister started', {'deviceId': device.id});
    final token = await _accessToken();
    await _api.unregisterDevice(device.id, token);
    await _clearDevice();
    _log.info('Device unregister completed', {'deviceId': device.id});
  }

  /// Returns the cached device, throwing if none is registered.
  Future<RegisteredDevice> getValidDevice() async {
    final device = await currentDevice();
    if (device == null) {
      throw const UidsDeviceRegistrationException(
        'No registered device in cache.',
      );
    }
    return device;
  }

  void clearMemoryCache() => _memoryCache = null;

  Future<void> clearAll() => _clearDevice();

  void dispose() => _deviceController.close();

  // ── Internals ─────────────────────────────────────────────────────────────

  Future<String> _accessToken() => _tokenProvider();

  Future<RegisteredDevice?> _loadFromStorage() async {
    final raw = await _storage.read(StorageKeys.device);
    if (raw == null) return null;
    try {
      final device =
          RegisteredDevice.fromJson(jsonDecode(raw) as Map<String, dynamic>);
      _memoryCache = device;
      return device;
    } catch (_) {
      await _storage.delete(StorageKeys.device);
      return null;
    }
  }

  Future<void> _saveDevice(RegisteredDevice device) async {
    _memoryCache = device;
    await _storage.write(StorageKeys.device, jsonEncode(device.toJson()));
    _deviceController.add(device);
  }

  Future<void> _clearDevice() async {
    _memoryCache = null;
    await _storage.delete(StorageKeys.device);
    _deviceController.add(null);
  }
}
