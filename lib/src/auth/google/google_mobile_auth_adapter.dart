import 'dart:io' show Platform;

import 'package:google_sign_in/google_sign_in.dart';

import '../../config/google_auth_config.dart';
import '../../errors/uids_auth_exception.dart';
import '../../models/auth_provider.dart';
import '../../models/provider_auth_result.dart';
import '../../models/provider_sign_in_options.dart';
import 'google_auth_platform_adapter.dart';

/// Google sign-in for Android and iOS using `google_sign_in: ^7.2.0`.
///
/// In v7:
/// - `GoogleSignIn.instance.initialize()` is required.
/// - `idToken` comes from `account.authentication`.
/// - `accessToken` comes from `account.authorizationClient`.
final class GoogleMobileAuthAdapter implements GoogleAuthPlatformAdapter {
  GoogleMobileAuthAdapter({required GoogleAuthConfig config})
    : _config = config;

  final GoogleAuthConfig _config;

  bool _initialized = false;

  @override
  Future<ProviderAuthResult> signIn({
    List<String> scopes = const [],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  }) async {
    try {
      await _ensureInitialized();

      final loginHint = options.trimmedLoginHint;
      if (loginHint != null) {
        final silent = await GoogleSignIn.instance
            .attemptLightweightAuthentication();
        if (silent != null &&
            silent.email.trim().toLowerCase() == loginHint.toLowerCase()) {
          return _toResult(silent, scopes, failureMessage: 'Google sign-in');
        }
      }

      final account = await GoogleSignIn.instance.authenticate();

      return _toResult(account, scopes, failureMessage: 'Google sign-in');
    } on GoogleSignInException catch (e) {
      if (e.code == GoogleSignInExceptionCode.canceled) {
        throw const UidsProviderCancelledException();
      }

      throw UidsProviderSignInException(
        _formatGoogleSignInException(e),
        cause: e,
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException('Google sign-in failed.', cause: e);
    }
  }

  @override
  Future<ProviderAuthResult> refresh({List<String> scopes = const []}) async {
    try {
      await _ensureInitialized();

      final account = await GoogleSignIn.instance
          .attemptLightweightAuthentication();

      if (account == null) {
        throw const UidsProviderSignInException(
          'No cached Google account available — interactive sign-in required.',
        );
      }

      return _toResult(
        account,
        scopes,
        failureMessage: 'Google silent refresh',
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Google silent refresh failed.',
        cause: e,
      );
    }
  }

  @override
  Future<void> signOut() async {
    await GoogleSignIn.instance.signOut();
  }

  Future<void> _ensureInitialized() async {
    if (_initialized) return;

    await GoogleSignIn.instance.initialize(
      clientId: _resolveClientId(),
      serverClientId: _config.webClientId,
    );

    _initialized = true;
  }

  String? _resolveClientId() {
    if (Platform.isAndroid) {
      return _config.androidClientId ?? _config.webClientId;
    }

    if (Platform.isIOS) {
      return _config.iosClientId ?? _config.webClientId;
    }

    return _config.webClientId;
  }

  Future<ProviderAuthResult> _toResult(
    GoogleSignInAccount account,
    List<String> scopes, {
    required String failureMessage,
  }) async {
    final auth = account.authentication;
    final idToken = auth.idToken;

    if (idToken == null) {
      throw UidsProviderSignInException(
        '$failureMessage returned no id_token.',
      );
    }

    final accessToken = await _getAccessToken(account, scopes);

    return ProviderAuthResult(
      provider: AuthProvider.google,
      idToken: idToken,
      accessToken: accessToken,
      scopes: scopes,
    );
  }

  Future<String?> _getAccessToken(
    GoogleSignInAccount account,
    List<String> scopes,
  ) async {
    if (scopes.isEmpty) return null;

    var authorization = await account.authorizationClient
        .authorizationForScopes(scopes);

    authorization ??= await account.authorizationClient.authorizeScopes(scopes);

    return authorization.accessToken;
  }

  String _formatGoogleSignInException(GoogleSignInException e) {
    final description = (e.description ?? '').trim();
    final code = e.code.toString().split('.').last;

    if (e.code == GoogleSignInExceptionCode.clientConfigurationError) {
      if (Platform.isAndroid &&
          description.contains('serverClientId must be provided on Android')) {
        return 'Google sign-in configuration error on Android. '
            'serverClientId is required. '
            'Set GoogleAuthConfig.webClientId to your Google Web OAuth client ID.';
      }

      return description.isEmpty
          ? 'Google sign-in configuration error.'
          : 'Google sign-in configuration error: $description';
    }

    return description.isEmpty
        ? 'Google sign-in failed ($code).'
        : 'Google sign-in failed ($code): $description';
  }
}
