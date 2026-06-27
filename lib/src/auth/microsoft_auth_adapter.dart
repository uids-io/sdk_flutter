import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../browser/auth_browser_launcher.dart';
import '../browser/external_browser_launcher.dart';
import '../config/microsoft_auth_config.dart';
import '../errors/uids_auth_exception.dart';
import '../models/auth_provider.dart';
import '../models/provider_auth_result.dart';
import '../models/provider_sign_in_options.dart';
import 'provider_auth_adapter.dart';

/// Microsoft (Entra ID / Azure AD) authentication adapter.
///
/// Implements the OAuth 2.0 Authorization Code flow directly — no MSAL or
/// third-party package required.
///
/// The browser interaction is delegated to an [AuthBrowserLauncher]:
/// - [ExternalBrowserLauncher] (default): opens the system browser.
///   - Desktop: uses a transient HTTP loopback server.
///   - Mobile: uses a custom-scheme deep link — register the redirect URI
///     scheme in your `AndroidManifest.xml` / `Info.plist` and forward every
///     incoming URI to [MicrosoftAuthAdapter.handleDeepLinkCallback].
///
/// ## Refresh
/// After a successful [signIn] the Microsoft refresh token is stored in-memory
/// so that [refresh] can silently obtain new tokens without UI.  The token is
/// **never** persisted to disk.
final class MicrosoftAuthAdapter implements ProviderAuthAdapter {
  MicrosoftAuthAdapter({
    required MicrosoftAuthConfig config,
    http.Client? httpClient,
    AuthBrowserLauncher? browserLauncher,
  }) : _config = config,
       _http = httpClient ?? http.Client(),
       _launcher = browserLauncher ?? const ExternalBrowserLauncher();

  static const _authorizeBase =
      'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize';
  static const _tokenBase =
      'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token';

  static const _desktopFlowTimeout = Duration(minutes: 2);
  static const _mobileFlowTimeout = Duration(minutes: 5);

  final MicrosoftAuthConfig _config;
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
  /// _appLinks.uriLinkStream.listen(MicrosoftAuthAdapter.handleDeepLinkCallback);
  /// ```
  static void handleDeepLinkCallback(Uri uri) =>
      ExternalBrowserLauncher.handleDeepLinkCallback(uri);

  // ── In-memory credential cache ────────────────────────────────────────────

  /// Held in memory only — never persisted.
  String? _refreshToken;

  bool get _isMobile =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  // ── ProviderAuthAdapter ───────────────────────────────────────────────────

  @override
  AuthProvider get provider => AuthProvider.microsoft;

  @override
  Future<ProviderAuthResult> signIn({
    List<String> scopes = const [],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  }) async {
    final state = DateTime.now().millisecondsSinceEpoch.toString();
    final effectiveScopes = _withRequiredScopes(scopes);
    final redirectUri = _resolveRedirectUri();
    final tenant = _config.tenantId;
    final loginHint = options.trimmedLoginHint;

    final queryParameters = <String, String>{
      'client_id': _config.clientId,
      'response_type': 'code',
      'redirect_uri': redirectUri,
      'response_mode': 'query',
      'scope': effectiveScopes.join(' '),
      'state': state,
    };

    if (loginHint != null) {
      queryParameters['login_hint'] = loginHint;
      queryParameters['prompt'] = 'login';
    } else {
      queryParameters['prompt'] = 'select_account';
    }

    final authUrl = Uri.parse(_authorizeBase.replaceFirst('{tenant}', tenant))
        .replace(
          queryParameters: queryParameters,
        );

    try {
      final callbackUri = await _launcher.launch(
        authUrl: authUrl,
        redirectUri: Uri.parse(redirectUri),
        timeout: _isMobile ? _mobileFlowTimeout : _desktopFlowTimeout,
      );

      if (callbackUri.queryParameters['state'] != state) {
        throw const UidsProviderSignInException('Invalid OAuth state.');
      }

      return await _exchangeCode(
        callbackUri: callbackUri,
        redirectUri: redirectUri,
        tenant: tenant,
        scopes: effectiveScopes,
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException('Microsoft sign-in failed.', cause: e);
    }
  }

  @override
  Future<ProviderAuthResult> refresh({List<String> scopes = const []}) async {
    final token = _refreshToken;
    if (token == null) {
      throw const UidsProviderSignInException(
        'No cached Microsoft refresh token — interactive sign-in required.',
      );
    }

    final effectiveScopes = _withRequiredScopes(scopes);
    final tenant = _config.tenantId;
    final redirectUri = _resolveRedirectUri();

    try {
      final response = await _http.post(
        Uri.parse(_tokenBase.replaceFirst('{tenant}', tenant)),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: <String, String>{
          'client_id': _config.clientId,
          'grant_type': 'refresh_token',
          'refresh_token': token,
          'redirect_uri': redirectUri,
          'scope': effectiveScopes.join(' '),
        },
      );

      if (response.statusCode != 200) {
        _refreshToken = null;
        throw UidsProviderSignInException(
          'Microsoft token refresh failed (HTTP ${response.statusCode}): '
          '${_describeError(response.body)}',
        );
      }

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      return _buildResult(data, effectiveScopes);
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Microsoft silent refresh failed.',
        cause: e,
      );
    }
  }

  @override
  Future<void> signOut() async {
    _refreshToken = null;
  }

  // ── Token exchange ────────────────────────────────────────────────────────

  Future<ProviderAuthResult> _exchangeCode({
    required Uri callbackUri,
    required String redirectUri,
    required String tenant,
    required List<String> scopes,
  }) async {
    _validateCallbackUri(callbackUri);
    final code = callbackUri.queryParameters['code']!;

    final response = await _http.post(
      Uri.parse(_tokenBase.replaceFirst('{tenant}', tenant)),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: <String, String>{
        'client_id': _config.clientId,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirectUri,
        'scope': scopes.join(' '),
      },
    );

    if (response.statusCode != 200) {
      throw UidsProviderSignInException(
        'Microsoft token exchange failed (HTTP ${response.statusCode}): '
        '${_describeError(response.body)}',
      );
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    return _buildResult(data, scopes);
  }

  ProviderAuthResult _buildResult(
    Map<String, dynamic> data,
    List<String> requestedScopes,
  ) {
    final accessToken = data['access_token'] as String?;
    final idToken = data['id_token'] as String?;
    final newRefreshToken = data['refresh_token'] as String?;
    final grantedScopeStr = (data['scope'] as String? ?? '').trim();
    final grantedScopes = grantedScopeStr.isEmpty
        ? requestedScopes
        : grantedScopeStr.split(' ');

    if (accessToken == null || accessToken.isEmpty) {
      throw const UidsProviderSignInException(
        'Microsoft token response is missing access_token.',
      );
    }

    if (newRefreshToken != null && newRefreshToken.isNotEmpty) {
      _refreshToken = newRefreshToken;
    }

    return ProviderAuthResult(
      provider: AuthProvider.microsoft,
      idToken: idToken ?? accessToken,
      accessToken: accessToken,
      scopes: grantedScopes,
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  void _validateCallbackUri(Uri uri) {
    final error = uri.queryParameters['error'];
    if (error != null) {
      final desc = uri.queryParameters['error_description'] ?? '';
      if (error == 'access_denied')
        throw const UidsProviderCancelledException();
      throw UidsProviderSignInException(
        'Microsoft OAuth error: $error — $desc',
      );
    }
    if (!uri.queryParameters.containsKey('code')) {
      throw const UidsProviderSignInException(
        'Microsoft callback is missing the authorization code.',
      );
    }
  }

  List<String> _withRequiredScopes(List<String> scopes) {
    return <String>{
      'openid',
      'profile',
      'email',
      'offline_access',
      ...scopes,
    }.toList(growable: false);
  }

  String _resolveRedirectUri() {
    final uri = _config.redirectUri;
    if (uri == null || uri.isEmpty) {
      throw const UidsProviderSignInException(
        'MicrosoftAuthConfig.redirectUri is required.\n'
        '  Desktop: use a loopback URL, e.g. http://localhost:9000/auth\n'
        '  Mobile:  use a custom scheme, e.g. msauth://com.example.app/callback',
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
}
