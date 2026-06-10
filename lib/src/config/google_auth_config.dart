/// Google Sign-In configuration.
///
/// Supply the credential that matches the current platform.
/// The SDK selects the correct credential automatically.
final class GoogleAuthConfig {
  const GoogleAuthConfig({
    this.webClientId,
    this.androidClientId,
    this.iosClientId,
    this.desktopClientId,
    this.desktopClientSecret,
    this.desktopRedirectUri,
    this.useInstalledAppFlowOnDesktop = false,
    this.useWebFlow = false,
  });

  /// OAuth 2.0 Web Client ID — used when the backend expects a web credential
  /// or as a fallback on desktop when no desktop client ID is provided.
  final String? webClientId;

  /// Android OAuth 2.0 Client ID.
  final String? androidClientId;

  /// iOS OAuth 2.0 Client ID.
  final String? iosClientId;

  /// Desktop OAuth 2.0 Client ID (installed-app or native-app credential).
  final String? desktopClientId;

  /// Desktop OAuth 2.0 Client Secret.
  ///
  /// Required by Google's token endpoint for **Desktop app** and **Web
  /// application** OAuth client types — even when PKCE is in use.  Without
  /// it the token exchange (authorization_code → tokens) returns HTTP 400
  /// with `error: invalid_client`.
  ///
  /// The "secret" issued for a Desktop app credential is not actually
  /// confidential — Google explicitly notes it can be embedded in the
  /// distributed app — so it is safe to ship in client config.
  ///
  /// Leave `null` only if you have registered the credential as an
  /// **iOS / Android** OAuth client type (which does not issue a secret).
  final String? desktopClientSecret;

  /// Localhost redirect URI used in the PKCE desktop flow.
  /// Example: `http://localhost:8585/callback`
  final String? desktopRedirectUri;

  /// When `true` and [desktopClientId] is provided, use the installed-app
  /// (out-of-band / loopback) flow instead of a browser redirect.
  final bool useInstalledAppFlowOnDesktop;

  /// When `true`, forces the PKCE browser-based OAuth flow on every native
  /// platform (Android, iOS, Windows, macOS, Linux) instead of the default
  /// native sign-in plugin on mobile.
  ///
  /// **Desktop** — [desktopRedirectUri] must be a loopback URL
  /// (e.g. `http://localhost:8585/callback`).
  ///
  /// **Mobile (Android / iOS)** — [desktopRedirectUri] must be a URI your app
  /// can capture, typically a custom-scheme deep-link such as
  /// `myapp://oauth2redirect`.  Register the scheme in `AndroidManifest.xml` /
  /// `Info.plist` and forward every incoming URI from your link handler:
  /// ```dart
  /// _appLinks.uriLinkStream.listen(GoogleAuthAdapter.handleDeepLinkCallback);
  /// ```
  ///
  /// Defaults to `false` — each platform uses its native adapter.
  final bool useWebFlow;
}
