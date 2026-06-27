import 'package:google_sign_in/google_sign_in.dart';

import '../../config/google_auth_config.dart';
import '../../errors/uids_auth_exception.dart';
import '../../models/auth_provider.dart';
import '../../models/provider_auth_result.dart';
import '../../models/provider_sign_in_options.dart';
import 'google_auth_platform_adapter.dart';

/// Google sign-in for Flutter Web using `google_sign_in_web`.
///
/// Initialises [GoogleSignIn.instance] with [GoogleAuthConfig.webClientId]
/// and delegates the sign-in flow to the plugin's OAuth popup.
///
/// Unlike the mobile adapter, the web flow does **not** use
/// `authorizationClient` — the access token is returned directly in
/// [GoogleSignInAuthentication.accessToken] after the OAuth popup completes.
///
/// ## App setup
///
/// 1. Add `google_sign_in_web` to your app's `pubspec.yaml`.
/// 2. Add the Google Identity Services script to `web/index.html`:
///    ```html
///    <script src="https://accounts.google.com/gsi/client"></script>
///    ```
/// 3. Supply [GoogleAuthConfig.webClientId] in [UidsSdkConfig].
final class GoogleWebAuthAdapter implements GoogleAuthPlatformAdapter {
  GoogleWebAuthAdapter({required GoogleAuthConfig config}) : _config = config;

  final GoogleAuthConfig _config;
  bool _initialized = false;

  // ── GoogleAuthPlatformAdapter ─────────────────────────────────────────────

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
          return _toResult(silent, scopes, context: 'sign-in');
        }
      }
      final account = await GoogleSignIn.instance.authenticate();
      return _toResult(account, scopes, context: 'sign-in');
    } on GoogleSignInException catch (e) {
      if (e.code == GoogleSignInExceptionCode.canceled) {
        throw const UidsProviderCancelledException();
      }
      throw UidsProviderSignInException(_formatException(e), cause: e);
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Google sign-in (web) failed.',
        cause: e,
      );
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
      return _toResult(account, scopes, context: 'silent refresh');
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Google silent refresh (web) failed.',
        cause: e,
      );
    }
  }

  @override
  Future<void> signOut() async {
    await GoogleSignIn.instance.signOut();
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  Future<void> _ensureInitialized() async {
    if (_initialized) return;
    final clientId = _config.webClientId;
    if (clientId == null || clientId.isEmpty) {
      throw const UidsProviderSignInException(
        'Google web sign-in requires GoogleAuthConfig.webClientId. '
        'Create a "Web application" OAuth 2.0 client in the Google Cloud '
        'Console and pass its client ID as webClientId.',
      );
    }
    await GoogleSignIn.instance.initialize(clientId: clientId);
    _initialized = true;
  }

  Future<ProviderAuthResult> _toResult(
    GoogleSignInAccount account,
    List<String> scopes, {
    required String context,
  }) async {
    final auth = account.authentication;
    final idToken = auth.idToken;
    if (idToken == null) {
      throw UidsProviderSignInException(
        'Google $context (web) returned no id_token.',
      );
    }
    // On web the access token is available directly from authentication;
    // the authorizationClient pattern used by the mobile adapter is not needed.
    final accessToken = await _getAccessToken(account, scopes);
    return ProviderAuthResult(
      provider: AuthProvider.google,
      idToken: idToken,
      accessToken: accessToken,
      scopes: scopes,
    );
  }

  String _formatException(GoogleSignInException e) {
    final desc = (e.description ?? '').trim();
    final code = e.code.toString().split('.').last;
    return desc.isEmpty
        ? 'Google sign-in (web) failed ($code).'
        : 'Google sign-in (web) failed ($code): $desc';
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
}
