import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../browser/auth_browser_launcher.dart';
import '../browser/external_browser_launcher.dart';
import '../config/github_auth_config.dart';
import '../errors/uids_auth_exception.dart';
import '../models/auth_provider.dart';
import '../models/provider_auth_result.dart';
import 'provider_auth_adapter.dart';

/// GitHub OAuth 2.0 authentication adapter.
///
/// Implements the Authorization Code flow with PKCE directly — no third-party
/// package required.
///
/// The browser interaction is delegated to an [AuthBrowserLauncher]:
/// - [ExternalBrowserLauncher] (default): opens the system browser.
///   - Desktop: uses a transient HTTP loopback server.
///   - Mobile: uses a custom-scheme deep link — register the redirect URI
///     scheme in your `AndroidManifest.xml` / `Info.plist` and forward every
///     incoming URI to [GitHubAuthAdapter.handleDeepLinkCallback].
///
/// ## Refresh
/// GitHub OAuth App tokens do not expire by default.  When a refresh token is
/// present (GitHub Apps with token expiry enabled), [refresh] exchanges it
/// silently.  Otherwise the cached access token is returned as-is.
/// Tokens are **never** persisted to disk.
///
/// ## GitHub and OIDC
/// GitHub does not issue an ID token in the OAuth response.  The access token
/// is used in place of `idToken` in [ProviderAuthResult].
final class GitHubAuthAdapter implements ProviderAuthAdapter {
  GitHubAuthAdapter({
    required GitHubAuthConfig config,
    http.Client? httpClient,
    AuthBrowserLauncher? browserLauncher,
  }) : _config = config,
       _http = httpClient ?? http.Client(),
       _launcher = browserLauncher ?? const ExternalBrowserLauncher();

  static const _authorizeEndpoint = 'https://github.com/login/oauth/authorize';
  static const _tokenEndpoint = 'https://github.com/login/oauth/access_token';

  static const _desktopFlowTimeout = Duration(minutes: 2);
  static const _mobileFlowTimeout = Duration(minutes: 5);

  final GitHubAuthConfig _config;
  final http.Client _http;
  final AuthBrowserLauncher _launcher;

  // ── Static deep-link bridge (backward compatibility) ──────────────────────

  /// Forward deep-link URIs from your app's link handler on mobile.
  ///
  /// This is a convenience delegate for [ExternalBrowserLauncher.handleDeepLinkCallback].
  /// Needed when using [ExternalBrowserLauncher] on mobile.
  ///
  /// ```dart
  /// // e.g. with package:app_links
  /// _appLinks.uriLinkStream.listen(GitHubAuthAdapter.handleDeepLinkCallback);
  /// ```
  static void handleDeepLinkCallback(Uri uri) =>
      ExternalBrowserLauncher.handleDeepLinkCallback(uri);

  // ── In-memory credential cache ────────────────────────────────────────────

  String? _accessToken;
  String? _refreshToken;

  bool get _isMobile =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  // ── ProviderAuthAdapter ───────────────────────────────────────────────────

  @override
  AuthProvider get provider => AuthProvider.github;

  @override
  Future<ProviderAuthResult> signIn({List<String> scopes = const []}) async {
    final state = _randomUrlSafe(32);
    final effectiveScopes = _withDefaultScopes(scopes);
    final redirectUri = _resolveRedirectUri();

    final verifier = _randomUrlSafe(64);
    final challenge = _s256Challenge(verifier);

    final authUrl = Uri.parse(_authorizeEndpoint).replace(
      queryParameters: <String, String>{
        'client_id': _config.clientId,
        'redirect_uri': redirectUri,
        'scope': effectiveScopes.join(' '),
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
      },
    );

    try {
      final callbackUri = await _launcher.launch(
        authUrl: authUrl,
        redirectUri: Uri.parse(redirectUri),
        timeout: _isMobile ? _mobileFlowTimeout : _desktopFlowTimeout,
      );

      if (callbackUri.queryParameters['state'] != state) {
        throw const UidsProviderSignInException(
          'Invalid OAuth state in GitHub callback.',
        );
      }

      return await _exchangeCode(
        callbackUri: callbackUri,
        redirectUri: redirectUri,
        scopes: effectiveScopes,
        verifier: verifier,
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException('GitHub sign-in failed.', cause: e);
    }
  }

  @override
  Future<ProviderAuthResult> refresh({List<String> scopes = const []}) async {
    final refreshToken = _refreshToken;
    if (refreshToken != null) {
      return _refreshWithToken(refreshToken, scopes);
    }

    // GitHub OAuth App tokens do not expire by default — return cached token.
    final cached = _accessToken;
    if (cached != null) {
      return ProviderAuthResult(
        provider: AuthProvider.github,
        idToken: cached,
        accessToken: cached,
        scopes: _withDefaultScopes(scopes),
      );
    }

    throw const UidsProviderSignInException(
      'No cached GitHub credential — interactive sign-in required.',
    );
  }

  @override
  Future<void> signOut() async {
    _accessToken = null;
    _refreshToken = null;
  }

  // ── Token exchange ────────────────────────────────────────────────────────

  Future<ProviderAuthResult> _exchangeCode({
    required Uri callbackUri,
    required String redirectUri,
    required List<String> scopes,
    required String verifier,
  }) async {
    _validateCallbackUri(callbackUri);
    final code = callbackUri.queryParameters['code']!;

    final response = await _http.post(
      Uri.parse(_tokenEndpoint),
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: <String, String>{
        'client_id': _config.clientId,
        'client_secret': _config.clientSecret,
        'code': code,
        'redirect_uri': redirectUri,
        'code_verifier': verifier,
      },
    );

    if (response.statusCode != 200) {
      throw UidsProviderSignInException(
        'GitHub token exchange failed (HTTP ${response.statusCode}): '
        '${_describeError(response.body)}',
      );
    }

    return _buildResult(
      jsonDecode(response.body) as Map<String, dynamic>,
      scopes,
    );
  }

  Future<ProviderAuthResult> _refreshWithToken(
    String token,
    List<String> scopes,
  ) async {
    final effectiveScopes = _withDefaultScopes(scopes);
    try {
      final response = await _http.post(
        Uri.parse(_tokenEndpoint),
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: <String, String>{
          'client_id': _config.clientId,
          'client_secret': _config.clientSecret,
          'grant_type': 'refresh_token',
          'refresh_token': token,
        },
      );

      if (response.statusCode != 200) {
        _refreshToken = null;
        throw UidsProviderSignInException(
          'GitHub token refresh failed (HTTP ${response.statusCode}): '
          '${_describeError(response.body)}',
        );
      }

      return _buildResult(
        jsonDecode(response.body) as Map<String, dynamic>,
        effectiveScopes,
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'GitHub silent refresh failed.',
        cause: e,
      );
    }
  }

  ProviderAuthResult _buildResult(
    Map<String, dynamic> data,
    List<String> requestedScopes,
  ) {
    final error = data['error'] as String?;
    if (error != null) {
      final desc = data['error_description'] as String? ?? '';
      if (error == 'access_denied') {
        throw const UidsProviderCancelledException();
      }
      throw UidsProviderSignInException('GitHub OAuth error: $error — $desc');
    }

    final accessToken = data['access_token'] as String?;
    if (accessToken == null || accessToken.isEmpty) {
      throw const UidsProviderSignInException(
        'GitHub token response is missing access_token.',
      );
    }

    _accessToken = accessToken;
    final newRefreshToken = data['refresh_token'] as String?;
    if (newRefreshToken != null && newRefreshToken.isNotEmpty) {
      _refreshToken = newRefreshToken;
    }

    final scopeStr = (data['scope'] as String? ?? '').trim();
    final grantedScopes = scopeStr.isEmpty
        ? requestedScopes
        : scopeStr.split(RegExp(r'[, ]+'));

    return ProviderAuthResult(
      provider: AuthProvider.github,
      idToken: accessToken,
      accessToken: accessToken,
      scopes: grantedScopes,
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  void _validateCallbackUri(Uri uri) {
    final error = uri.queryParameters['error'];
    if (error != null) {
      final desc = uri.queryParameters['error_description'] ?? '';
      if (error == 'access_denied') {
        throw const UidsProviderCancelledException();
      }
      throw UidsProviderSignInException('GitHub OAuth error: $error — $desc');
    }
    if (!uri.queryParameters.containsKey('code')) {
      throw const UidsProviderSignInException(
        'GitHub callback is missing the authorization code.',
      );
    }
  }

  List<String> _withDefaultScopes(List<String> scopes) {
    return <String>{
      'read:user',
      'user:email',
      ...scopes,
    }.toList(growable: false);
  }

  String _resolveRedirectUri() {
    final uri = _config.redirectUri;
    if (uri == null || uri.isEmpty) {
      throw const UidsProviderSignInException(
        'GitHubAuthConfig.redirectUri is required.\n'
        '  Desktop: use a loopback URL, e.g. http://localhost:9100/auth\n'
        '  Mobile:  use a custom scheme, e.g. com.example.app://auth/github',
      );
    }
    return uri;
  }

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
}
