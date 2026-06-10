import '../auth/auth_manager.dart';
import '../auth/google_auth_adapter.dart';
import '../auth/microsoft_auth_adapter.dart';
import '../auth/provider_auth_adapter.dart';
import '../config/uids_sdk_config.dart';
import '../device/device_manager.dart';
import '../errors/uids_auth_exception.dart';
import '../models/auth_provider.dart';
import '../models/auth_session.dart';
import '../models/device_models.dart';
import '../models/email_auth_models.dart';
import '../network/auth_api_client.dart';
import '../session/session_manager.dart';
import '../storage/secure_sdk_storage.dart';
import '../storage/sdk_storage.dart';
import 'uids_auth_sdk_public.dart';

/// Concrete facade implementation.
///
/// Wires together all internal managers and exposes the public [UidsAuthSdk]
/// surface.  Consumers never import or reference this class directly.
final class UidsAuthSdkImpl implements UidsAuthSdk {
  UidsAuthSdkImpl({SdkStorage? storage}) : _storageOverride = storage;

  final SdkStorage? _storageOverride;

  late AuthApiClient _api;
  late SessionManager _session;
  late DeviceManager _device;
  late AuthManager _auth;

  bool _initialized = false;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  @override
  Future<void> initialize(UidsSdkConfig config) async {
    if (_initialized) return;

    final storage = _storageOverride ?? SecureSdkStorage();

    _api = AuthApiClient(config: config);

    _session = SessionManager(
      apiClient: _api,
      storage: storage,
      refreshBeforeExpiry: config.refreshBeforeExpiry,
      autoRefresh: config.autoRefresh,
    );

    // DeviceManager depends only on a token provider — not on SessionManager —
    // so the device flow stays orthogonal to the auth flow.
    _device = DeviceManager(
      apiClient: _api,
      tokenProvider: () async => (await _session.getValidSession()).accessToken,
      storage: storage,
    );

    _auth = AuthManager(
      apiClient: _api,
      sessionManager: _session,
      adapters: _buildAdapters(config),
    );

    _initialized = true;
  }

  // ── Authentication ────────────────────────────────────────────────────────

  @override
  Future<AuthSession> signInWithProvider({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
  }) async {
    _assertInitialized();
    return _auth.signIn(provider: provider, scopes: scopes);
  }

  @override
  Future<AuthSession> refreshProviderSession({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
  }) async {
    _assertInitialized();
    return _auth.refreshProvider(provider: provider, scopes: scopes);
  }

  @override
  Future<UsernameAvailabilityResult> checkUsernameAvailable(
    String username,
  ) async {
    _assertInitialized();
    return _auth.checkUsernameAvailable(username);
  }

  @override
  Future<EmailRegistrationResult> registerWithEmail({
    required String username,
    required String email,
    required String password,
  }) async {
    _assertInitialized();
    return _auth.registerWithEmail(
      username: username,
      email: email,
      password: password,
    );
  }

  @override
  Future<AuthSession> signInWithEmail({
    required String email,
    required String password,
    required String otp,
    String? tenant,
  }) async {
    _assertInitialized();
    return _auth.signInWithEmail(
      email: email,
      password: password,
      otp: otp,
      tenant: tenant,
    );
  }

  @override
  Future<EmailLoginResult> loginWithEmail({
    required String email,
    required String password,
  }) async {
    _assertInitialized();
    return _auth.loginWithEmail(email: email, password: password);
  }

  @override
  Future<AuthSession> completeEmailSignIn({
    required String otp,
    required String pendingAccessToken,
    String? tenant,
  }) async {
    _assertInitialized();
    return _auth.completeEmailSignIn(
      otp: otp,
      pendingAccessToken: pendingAccessToken,
      tenant: tenant,
    );
  }

  // ── Session ───────────────────────────────────────────────────────────────

  @override
  Future<AuthSession?> currentSession() async {
    _assertInitialized();
    return _session.currentSession();
  }

  @override
  Future<AuthSession> getValidSession() async {
    _assertInitialized();
    return _session.getValidSession();
  }

  @override
  Future<String> accessToken() async {
    _assertInitialized();
    final session = await _session.getValidSession();
    return session.accessToken;
  }

  @override
  Future<Map<String, String>> authHeaders() async {
    _assertInitialized();
    final session = await _session.getValidSession();
    return {'Authorization': session.authorizationHeader};
  }

  @override
  Future<AuthSession> refreshSession({bool force = false}) async {
    _assertInitialized();
    if (force) {
      return _session.refreshSession();
    }
    return _session.getValidSession();
  }

  @override
  Future<bool> isSignedIn() async {
    _assertInitialized();
    final session = await _session.currentSession();
    return session != null;
  }

  // ── Device ────────────────────────────────────────────────────────────────

  @override
  Future<RegisteredDevice> registerDevice(DeviceRegisterRequest request) async {
    _assertInitialized();
    return _device.registerDevice(request);
  }

  @override
  Future<RegisteredDevice> ensureDeviceRegistered(
    DeviceRegisterRequest request,
  ) async {
    _assertInitialized();
    return _device.ensureDeviceRegistered(request);
  }

  @override
  Future<RegisteredDevice?> currentDevice() async {
    _assertInitialized();
    return _device.currentDevice();
  }

  @override
  Future<RegisteredDevice> updateDevice(DeviceUpdateRequest request) async {
    _assertInitialized();
    return _device.updateDevice(request);
  }

  @override
  Future<void> unregisterDevice() async {
    _assertInitialized();
    return _device.unregisterDevice();
  }

  // ── Sign-out & cache ──────────────────────────────────────────────────────

  @override
  Future<void> signOut() async {
    _assertInitialized();
    final session = await _session.currentSession();
    // Auth-only sign-out.  Device state is intentionally left untouched —
    // call unregisterDevice() or clearAll() for the device flow.
    await _auth.signOut(session?.provider);
  }

  @override
  Future<void> clearMemoryCache() async {
    _assertInitialized();
    _session.clearMemoryCache();
    _device.clearMemoryCache();
  }

  @override
  Future<void> clearAll() async {
    _assertInitialized();
    await _session.clearSession();
    await _device.clearAll();
  }

  // ── Streams ───────────────────────────────────────────────────────────────

  @override
  Stream<AuthSession?> get sessionChanges {
    _assertInitialized();
    return _session.sessionChanges;
  }

  @override
  Stream<RegisteredDevice?> get deviceChanges {
    _assertInitialized();
    return _device.deviceChanges;
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  void _assertInitialized() {
    if (!_initialized) throw const UidsNotInitializedException();
  }

  Map<AuthProvider, ProviderAuthAdapter> _buildAdapters(UidsSdkConfig config) {
    final adapters = <AuthProvider, ProviderAuthAdapter>{};

    if (config.google != null) {
      adapters[AuthProvider.google] = GoogleAuthAdapter.fromPlatform(
        config: config.google!,
      );
    }

    if (config.microsoft != null) {
      adapters[AuthProvider.microsoft] = MicrosoftAuthAdapter(
        config: config.microsoft!,
      );
    }

    return adapters;
  }
}
