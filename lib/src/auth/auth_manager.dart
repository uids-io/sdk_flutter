import '../errors/uids_auth_exception.dart';
import '../utils/password_validation.dart';
import '../logging/sdk_logger.dart';
import '../models/auth_provider.dart';
import '../models/auth_session.dart';
import '../models/email_auth_models.dart';
import '../models/provider_auth_result.dart';
import '../models/provider_sign_in_options.dart';
import '../network/auth_api_client.dart';
import '../session/session_manager.dart';
import 'provider_auth_adapter.dart';

/// Orchestrates the provider sign-in pipeline.
///
/// 1. Delegates to the appropriate [ProviderAuthAdapter] to obtain a provider
///    token.
/// 2. Sends the provider token to the backend via [AuthApiClient].
/// 3. Saves the resulting [AuthSession] through [SessionManager].
///
/// AuthManager is concerned only with **authentication**.  It does not know
/// about devices.  Adapters never call the backend; AuthManager is the only
/// class that does (for auth endpoints).
final class AuthManager {
  AuthManager({
    required AuthApiClient apiClient,
    required SessionManager sessionManager,
    required Map<AuthProvider, ProviderAuthAdapter> adapters,
    SdkLogger? logger,
  }) : _api = apiClient,
       _session = sessionManager,
       _adapters = adapters,
       _log = logger ?? SdkLogger(onLog: null);

  final AuthApiClient _api;
  final SessionManager _session;
  final Map<AuthProvider, ProviderAuthAdapter> _adapters;
  final SdkLogger _log;

  /// Sign in with the given [provider] and exchange for a backend session.
  Future<AuthSession> signIn({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  }) async {
    _log.info('Provider sign-in started', {'provider': provider.label});
    try {
      final adapter = _requireAdapter(provider);
      final providerResult = await adapter.signIn(scopes: scopes, options: options);
      final session = await _api.exchangeProviderToken(providerResult);
      await _session.saveSession(session);
      _log.info('Provider sign-in succeeded', {
        'provider': provider.label,
        'user': session.user.email,
      });
      return session;
    } catch (e, st) {
      _log.warn(
        'Provider sign-in failed',
        error: e,
        stackTrace: st,
        data: {'provider': provider.label},
      );
      rethrow;
    }
  }

  /// Silently refreshes the provider credential and re-exchanges it for a
  /// fresh backend session.
  ///
  /// Useful when the backend refresh token has been revoked but the provider
  /// credential is still valid (e.g. after a backend-side logout).
  ///
  /// Throws [UidsProviderSignInException] if the provider has no cached
  /// account — callers should fall back to interactive [signIn].
  Future<AuthSession> refreshProvider({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
  }) async {
    _log.info('Provider silent refresh started', {'provider': provider.label});
    try {
      final adapter = _requireAdapter(provider);
      final ProviderAuthResult providerResult = await adapter.refresh(
        scopes: scopes,
      );
      final session = await _api.exchangeProviderToken(providerResult);
      await _session.saveSession(session);
      _log.info('Provider silent refresh succeeded', {
        'provider': provider.label,
        'user': session.user.email,
      });
      return session;
    } catch (e, st) {
      _log.warn(
        'Provider silent refresh failed',
        error: e,
        stackTrace: st,
        data: {'provider': provider.label},
      );
      rethrow;
    }
  }

  // ── Email / password ──────────────────────────────────────────────────────

  /// Returns whether [username] is available for registration.
  Future<UsernameAvailabilityResult> checkUsernameAvailable(String username) {
    return _api.checkUsernameAvailable(username);
  }

  /// Sends a one-time verification code to [email] before registration.
  Future<void> sendRegisterEmailOtp({required String email}) {
    return _api.sendRegisterEmailOtp(email: email);
  }

  /// Register a new account. Returns a QR code for authenticator setup.
  Future<EmailRegistrationResult> registerWithEmail({
    required String username,
    required String email,
    required String password,
    required String emailOtp,
  }) {
    final passwordError = validateRegistrationPassword(password);
    if (passwordError != null) {
      throw UidsWeakPasswordException(passwordError);
    }

    return _api.registerWithEmail(
      username: username,
      email: email,
      password: password,
      emailOtp: emailOtp,
    );
  }

  /// Step 1 — validate email/password and obtain a pending token for 2FA.
  Future<EmailLoginResult> loginWithEmail({
    required String email,
    required String password,
  }) {
    return _api.loginWithEmail(email: email, password: password);
  }

  /// Step 2+3 — verify TOTP and exchange for a fully-scoped session.
  ///
  /// When [tenant] is omitted and the user has exactly one tenant it is
  /// selected automatically. Otherwise [UidsTenantSelectionRequiredException]
  /// is thrown listing the available tenants.
  Future<AuthSession> completeEmailSignIn({
    required String otp,
    required String pendingAccessToken,
    String? tenant,
  }) async {
    _log.info('Email sign-in completing', {'tenant': tenant ?? '(auto)'});
    try {
      final otpResult = await _api.verifyEmailOtp(
        otp: otp,
        pendingAccessToken: pendingAccessToken,
      );
      final entity = _selectTenantEntity(otpResult.entities, tenant);
      final session = await _api.exchangeAud(
        tenant: entity.tenant,
        username: otpResult.username,
        refreshToken: entity.refreshToken,
        idpName: otpResult.idpName,
      );
      await _session.saveSession(session);
      _log.info('Email sign-in succeeded', {
        'user': session.user.email,
        'tenant': entity.tenant,
      });
      return session;
    } catch (e, st) {
      _log.warn('Email sign-in failed', error: e, stackTrace: st);
      rethrow;
    }
  }

  /// Convenience: login + 2FA + tenant exchange in one call.
  Future<AuthSession> signInWithEmail({
    required String email,
    required String password,
    required String otp,
    String? tenant,
  }) async {
    final login = await loginWithEmail(email: email, password: password);
    return completeEmailSignIn(
      otp: otp,
      pendingAccessToken: login.pendingAccessToken,
      tenant: tenant,
    );
  }

  /// Signs the user out of the provider and clears the SDK session.
  ///
  /// Does **not** touch device state — that is owned by `DeviceManager` and
  /// must be cleared separately if desired.
  Future<void> signOut(AuthProvider? provider) async {
    _log.info('Sign-out started', {
      'provider': provider?.label ?? 'all',
    });
    try {
      if (provider != null) {
        await _adapters[provider]?.signOut();
      } else {
        for (final adapter in _adapters.values) {
          await adapter.signOut();
        }
      }
      await _session.clearSession();
      _log.info('Sign-out completed');
    } catch (e, st) {
      _log.warn('Sign-out failed', error: e, stackTrace: st);
      rethrow;
    }
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  ProviderAuthAdapter _requireAdapter(AuthProvider provider) {
    final adapter = _adapters[provider];
    if (adapter == null) {
      throw UidsProviderNotConfiguredException(
        '${provider.label} is not configured. '
        'Pass the corresponding config to UidsSdkConfig.',
      );
    }
    return adapter;
  }

  EmailTenantEntity _selectTenantEntity(
    List<EmailTenantEntity> entities,
    String? tenant,
  ) {
    if (entities.isEmpty) {
      throw const UidsNoTenantsAvailableException();
    }

    if (tenant != null) {
      final match = entities.where(
        (e) => e.tenant.toLowerCase() == tenant.toLowerCase(),
      );
      if (match.isEmpty) {
        throw UidsTenantNotFoundException(
          'Tenant "$tenant" is not available for this account.',
        );
      }
      return match.first;
    }

    if (entities.length == 1) return entities.first;

    throw UidsTenantSelectionRequiredException(
      entities.map((e) => e.tenant).toList(),
    );
  }
}
