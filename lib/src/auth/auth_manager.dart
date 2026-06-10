import '../errors/uids_auth_exception.dart';
import '../models/auth_provider.dart';
import '../models/auth_session.dart';
import '../models/email_auth_models.dart';
import '../models/provider_auth_result.dart';
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
  }) : _api = apiClient,
       _session = sessionManager,
       _adapters = adapters;

  final AuthApiClient _api;
  final SessionManager _session;
  final Map<AuthProvider, ProviderAuthAdapter> _adapters;

  /// Sign in with the given [provider] and exchange for a backend session.
  Future<AuthSession> signIn({
    required AuthProvider provider,
    List<String> scopes = const ['openid', 'email', 'profile'],
  }) async {
    final adapter = _requireAdapter(provider);
    final providerResult = await adapter.signIn(scopes: scopes);
    final session = await _api.exchangeProviderToken(providerResult);
    await _session.saveSession(session);
    return session;
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
    final adapter = _requireAdapter(provider);
    final ProviderAuthResult providerResult = await adapter.refresh(
      scopes: scopes,
    );
    final session = await _api.exchangeProviderToken(providerResult);
    await _session.saveSession(session);
    return session;
  }

  // ── Email / password ──────────────────────────────────────────────────────

  /// Returns whether [username] is available for registration.
  Future<UsernameAvailabilityResult> checkUsernameAvailable(String username) {
    return _api.checkUsernameAvailable(username);
  }

  /// Register a new account. Returns a QR code for authenticator setup.
  Future<EmailRegistrationResult> registerWithEmail({
    required String username,
    required String email,
    required String password,
  }) {
    return _api.registerWithEmail(
      username: username,
      email: email,
      password: password,
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
    return session;
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
    if (provider != null) {
      await _adapters[provider]?.signOut();
    } else {
      for (final adapter in _adapters.values) {
        await adapter.signOut();
      }
    }
    await _session.clearSession();
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
