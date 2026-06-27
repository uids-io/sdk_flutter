import '../config/uids_sdk_config.dart';
import '../models/auth_provider.dart';
import '../models/auth_session.dart';
import '../models/device_models.dart';
import '../models/email_auth_models.dart';
import '../models/provider_sign_in_options.dart';
import '../storage/sdk_storage.dart';
import 'uids_auth_sdk_impl.dart';

/// Public facade for the UIDS Auth SDK.
///
/// The API is split into two independent flows:
///
/// - **Authentication** — OAuth provider sign-in, email/password sign-in,
///   session lifecycle, refresh.
/// - **Device registration** — register / update / unregister a device.
///
/// The two flows share an access token but are otherwise independently
/// composable.  Sign-in does not register a device; signing out does not
/// unregister or clear a device.  Compose them at the app layer however your
/// product needs.
///
/// Obtain an instance via [UidsAuthSdk.create] and call [initialize] before
/// using any other method.
abstract interface class UidsAuthSdk {
  /// Creates a new SDK instance.
  ///
  /// Pass a custom [storage] implementation to replace the default
  /// [SecureSdkStorage].  Omit it (or pass `null`) to keep the default
  /// platform-secure storage behaviour.
  factory UidsAuthSdk.create({SdkStorage? storage}) =>
      UidsAuthSdkImpl(storage: storage);

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  Future<void> initialize(UidsSdkConfig config);

  // ── Authentication ────────────────────────────────────────────────────────

  /// Interactive sign-in with the given provider.
  Future<AuthSession> signInWithProvider({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  });

  /// Silently re-acquires a provider credential and exchanges it for a fresh
  /// backend session.  Falls back to throwing — call [signInWithProvider] if
  /// the provider has no cached account.
  Future<AuthSession> refreshProviderSession({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
  });

  /// Signs the user out of the provider and clears the SDK session.
  ///
  /// Does **not** clear or unregister the device cache.  Call
  /// [unregisterDevice] or [clearAll] separately if you also want to detach
  /// the device.
  Future<void> signOut();

  // ── Email / password ──────────────────────────────────────────────────────

  /// Checks whether [username] is available for email registration.
  Future<UsernameAvailabilityResult> checkUsernameAvailable(String username);

  /// Sends a one-time verification code to [email] before registration.
  Future<void> sendRegisterEmailOtp({required String email});

  /// Register a new account with username, email, password, and email OTP.
  ///
  /// Returns a [EmailRegistrationResult] with a QR code for authenticator
  /// setup. Call [completeEmailSignIn] with the pending token and a TOTP
  /// code to finish registration.
  Future<EmailRegistrationResult> registerWithEmail({
    required String username,
    required String email,
    required String password,
    required String emailOtp,
  });

  /// Sign in with email, password, and authenticator code in one step.
  ///
  /// When the account has multiple tenants, pass [tenant] explicitly or
  /// catch [UidsTenantSelectionRequiredException] to present a picker.
  Future<AuthSession> signInWithEmail({
    required String email,
    required String password,
    required String otp,
    String? tenant,
  });

  /// Step 1 of a multi-screen email sign-in — validates credentials.
  Future<EmailLoginResult> loginWithEmail({
    required String email,
    required String password,
  });

  /// Step 2 of a multi-screen email sign-in — verifies TOTP and saves session.
  Future<AuthSession> completeEmailSignIn({
    required String otp,
    required String pendingAccessToken,
    String? tenant,
  });

  // ── Session ───────────────────────────────────────────────────────────────

  Future<AuthSession?> currentSession();

  Future<AuthSession> getValidSession();

  Future<String> accessToken();

  Future<Map<String, String>> authHeaders();

  Future<AuthSession> refreshSession({bool force = false});

  /// Loads [session] as the active local session (profile switching).
  Future<void> restoreLocalSession(AuthSession session);

  /// Clears the active local session without provider sign-out.
  Future<void> clearLocalSession();

  Future<bool> isSignedIn();

  // ── Device ────────────────────────────────────────────────────────────────

  Future<RegisteredDevice> registerDevice(DeviceRegisterRequest request);

  Future<RegisteredDevice> ensureDeviceRegistered(
    DeviceRegisterRequest request,
  );

  Future<RegisteredDevice?> currentDevice();

  Future<RegisteredDevice> updateDevice(DeviceUpdateRequest request);

  Future<void> unregisterDevice();

  // ── Cache ─────────────────────────────────────────────────────────────────

  /// Clears the in-memory caches for both session and device.  Secure storage
  /// is untouched so the next read can rehydrate from disk.
  Future<void> clearMemoryCache();

  /// Clears persisted state for both session and device locally.  Does not
  /// hit the backend.
  Future<void> clearAll();

  // ── Streams ───────────────────────────────────────────────────────────────

  Stream<AuthSession?> get sessionChanges;

  Stream<RegisteredDevice?> get deviceChanges;
}
