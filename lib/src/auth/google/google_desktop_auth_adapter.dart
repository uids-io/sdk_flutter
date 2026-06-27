import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import '../../browser/auth_browser_launcher.dart';
import '../../browser/external_browser_launcher.dart';
import '../../config/google_auth_config.dart';
import '../../errors/uids_auth_exception.dart';
import '../../models/auth_provider.dart';
import '../../models/provider_auth_result.dart';
import '../../models/provider_sign_in_options.dart';
import 'google_auth_platform_adapter.dart';

/// Google sign-in via the OAuth 2.0 Authorization Code flow with PKCE.
///
/// Used on Windows / macOS / Linux by default, and on Android / iOS when
/// [GoogleAuthConfig.useWebFlow] is `true`.
///
/// Flow:
/// 1. Generate `code_verifier`, `code_challenge` (S256), `state`.
/// 2. Open the authorization URL via [AuthBrowserLauncher].
/// 3. The launcher captures the redirect and returns the callback [Uri].
/// 4. Validate `state`, extract `code`.
/// 5. POST to Google's token endpoint with `code` + `code_verifier`.
/// 6. Return [ProviderAuthResult] (id_token + access_token).
///
/// **Mobile deep-link wiring** — when this adapter runs on Android / iOS,
/// [ExternalBrowserLauncher] waits for a deep-link URI via
/// [ExternalBrowserLauncher.handleDeepLinkCallback].  Forward the URI from
/// your app's link handler:
/// ```dart
/// _appLinks.uriLinkStream.listen(GoogleAuthAdapter.handleDeepLinkCallback);
/// ```
///
/// No tokens are persisted; the refresh token (when granted) is held in memory
/// for the lifetime of the adapter so that [refresh] can run without UI.
final class GoogleDesktopAuthAdapter implements GoogleAuthPlatformAdapter {
  GoogleDesktopAuthAdapter({
    required GoogleAuthConfig config,
    http.Client? httpClient,
    AuthBrowserLauncher? browserLauncher,
    bool requireLoopbackRedirect = true,
  }) : _config = config,
       _http = httpClient ?? http.Client(),
       _launcher = browserLauncher ?? const ExternalBrowserLauncher(),
       _requireLoopbackRedirect = requireLoopbackRedirect;

  static const _authorizeEndpoint =
      'https://accounts.google.com/o/oauth2/v2/auth';
  static const _tokenEndpoint = 'https://oauth2.googleapis.com/token';
  static const _revokeEndpoint = 'https://oauth2.googleapis.com/revoke';

  static const _flowTimeout = Duration(minutes: 5);

  final GoogleAuthConfig _config;
  final http.Client _http;
  final AuthBrowserLauncher _launcher;
  final bool _requireLoopbackRedirect;

  /// Held in memory only — never persisted.  Set after a successful sign-in
  /// so that [refresh] can run without UI.
  String? _refreshToken;

  // ── GoogleAuthPlatformAdapter ────────────────────────────────────────────

  @override
  Future<ProviderAuthResult> signIn({
    List<String> scopes = const [],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  }) async {
    final clientId = _requireClientId();
    final redirectUri = _resolveRedirectUri();
    final effectiveScopes = _withOpenIdScopes(scopes);
    final loginHint = options.trimmedLoginHint;

    final verifier = _randomUrlSafe(64);
    final challenge = _s256Challenge(verifier);
    final state = _randomUrlSafe(32);

    final queryParameters = <String, String>{
      'response_type': 'code',
      'client_id': clientId,
      'redirect_uri': redirectUri.toString(),
      'scope': effectiveScopes.join(' '),
      'code_challenge': challenge,
      'code_challenge_method': 'S256',
      'state': state,
      'access_type': 'offline',
      'include_granted_scopes': 'true',
    };

    if (loginHint != null) {
      queryParameters['login_hint'] = loginHint;
      queryParameters['prompt'] = 'login';
    } else {
      queryParameters['prompt'] = 'consent';
    }

    final authorizeUrl = Uri.parse(_authorizeEndpoint).replace(
      queryParameters: queryParameters,
    );

    try {
      final callbackUri = await _launcher.launch(
        authUrl: authorizeUrl,
        redirectUri: redirectUri,
        timeout: _flowTimeout,
      );

      final params = callbackUri.queryParameters;

      if (params['state'] != state) {
        throw const UidsProviderSignInException(
          'Google redirect failed state validation.',
        );
      }

      final error = params['error'];
      if (error != null) {
        if (error == 'access_denied') throw const UidsProviderCancelledException();
        throw UidsProviderSignInException('Google sign-in error: $error.');
      }

      final code = params['code'];
      if (code == null || code.isEmpty) {
        throw const UidsProviderSignInException(
          'Google redirect did not include an authorization code.',
        );
      }

      return await _exchangeCode(
        code: code,
        verifier: verifier,
        clientId: clientId,
        redirectUri: redirectUri,
        scopes: effectiveScopes,
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Google desktop sign-in failed.',
        cause: e,
      );
    }
  }

  @override
  Future<ProviderAuthResult> refresh({List<String> scopes = const []}) async {
    final refreshToken = _refreshToken;
    if (refreshToken == null) {
      throw const UidsProviderSignInException(
        'No cached Google refresh token — interactive sign-in required.',
      );
    }

    final clientId = _requireClientId();
    final clientSecret = _resolveClientSecret();
    final effectiveScopes = _withOpenIdScopes(scopes);

    try {
      final response = await _http.post(
        Uri.parse(_tokenEndpoint),
        body: <String, String>{
          'client_id': clientId,
          if (clientSecret != null) 'client_secret': clientSecret,
          'grant_type': 'refresh_token',
          'refresh_token': refreshToken,
        },
      );

      if (response.statusCode != 200) {
        _refreshToken = null;
        throw UidsProviderSignInException(
          'Google refresh failed (HTTP ${response.statusCode}): '
          '${_describeError(response.body)}',
        );
      }

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final idToken = json['id_token'] as String?;
      if (idToken == null) {
        throw const UidsProviderSignInException(
          'Google refresh returned no id_token.',
        );
      }

      // Google may rotate the refresh token.
      _refreshToken = (json['refresh_token'] as String?) ?? _refreshToken;

      return ProviderAuthResult(
        provider: AuthProvider.google,
        idToken: idToken,
        accessToken: json['access_token'] as String?,
        scopes: effectiveScopes,
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
    final token = _refreshToken;
    _refreshToken = null;
    if (token == null) return;

    try {
      await _http.post(
        Uri.parse(_revokeEndpoint),
        body: <String, String>{'token': token},
      );
    } catch (_) {
      // Best-effort revocation — local credential already cleared.
    }
  }

  // ── Token exchange ────────────────────────────────────────────────────────

  Future<ProviderAuthResult> _exchangeCode({
    required String code,
    required String verifier,
    required String clientId,
    required Uri redirectUri,
    required List<String> scopes,
  }) async {
    final clientSecret = _resolveClientSecret();

    final response = await _http.post(
      Uri.parse(_tokenEndpoint),
      body: <String, String>{
        'client_id': clientId,
        if (clientSecret != null) 'client_secret': clientSecret,
        'grant_type': 'authorization_code',
        'code': code,
        'code_verifier': verifier,
        'redirect_uri': redirectUri.toString(),
      },
    );

    if (response.statusCode != 200) {
      throw UidsProviderSignInException(
        'Google token exchange failed (HTTP ${response.statusCode}): '
        '${_describeError(response.body)}',
      );
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final idToken = json['id_token'] as String?;
    if (idToken == null) {
      throw const UidsProviderSignInException(
        'Google token exchange returned no id_token.',
      );
    }

    _refreshToken = (json['refresh_token'] as String?) ?? _refreshToken;

    return ProviderAuthResult(
      provider: AuthProvider.google,
      idToken: idToken,
      accessToken: json['access_token'] as String?,
      scopes: scopes,
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  String _requireClientId() {
    final clientId = _config.desktopClientId ?? _config.webClientId;
    if (clientId == null || clientId.isEmpty) {
      throw const UidsProviderSignInException(
        'Google desktop sign-in requires desktopClientId or webClientId in '
        'GoogleAuthConfig.',
      );
    }
    return clientId;
  }

  String? _resolveClientSecret() {
    final secret = _config.desktopClientSecret;
    if (secret == null || secret.isEmpty) return null;
    return secret;
  }

  Uri _resolveRedirectUri() {
    final raw = _config.desktopRedirectUri;
    if (raw == null || raw.isEmpty) {
      throw const UidsProviderSignInException(
        'Google sign-in requires desktopRedirectUri in GoogleAuthConfig. '
        'Use a loopback URL on desktop (e.g. http://localhost:8585/callback) '
        'or an app-scheme URI on mobile (e.g. myapp://oauth2redirect).',
      );
    }
    final uri = Uri.parse(raw);
    if (_requireLoopbackRedirect &&
        (!(uri.host == 'localhost' || uri.host == '127.0.0.1') ||
            uri.scheme != 'http' ||
            uri.port == 0)) {
      throw const UidsProviderSignInException(
        'desktopRedirectUri must be a loopback URL with an explicit port '
        '(e.g. http://localhost:8585/callback).',
      );
    }
    return uri;
  }

  List<String> _withOpenIdScopes(List<String> scopes) {
    final set = <String>{...scopes};
    set.addAll(['openid', 'email', 'profile']);
    return set.toList(growable: false);
  }

  String _randomUrlSafe(int byteLength) {
    final rng = Random.secure();
    final bytes = List<int>.generate(
      byteLength,
      (_) => rng.nextInt(256),
      growable: false,
    );
    return _base64UrlNoPad(bytes);
  }

  String _s256Challenge(String verifier) {
    final digest = sha256.convert(utf8.encode(verifier));
    return _base64UrlNoPad(digest.bytes);
  }

  static String _base64UrlNoPad(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static String _describeError(String body) {
    try {
      final json = jsonDecode(body) as Map<String, dynamic>;
      final error = json['error'];
      final description = json['error_description'];
      if (error != null && description != null) return '$error — $description';
      if (error != null) return error.toString();
    } catch (_) {}
    return body.length > 200 ? '${body.substring(0, 200)}…' : body;
  }
}
