import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kIsWeb;

import '../browser/auth_browser_launcher.dart';
import '../browser/external_browser_launcher.dart';
import '../config/google_auth_config.dart';
import '../errors/uids_auth_exception.dart';
import '../models/auth_provider.dart';
import '../models/provider_auth_result.dart';
import 'google/google_auth_platform_adapter.dart';
import 'google/google_desktop_auth_adapter.dart';
import 'google/google_mobile_auth_adapter.dart';
import 'google/google_web_auth_adapter.dart';
import 'provider_auth_adapter.dart';

/// `ProviderAuthAdapter` for Google.
///
/// This class is a thin façade — it delegates **every** call to a
/// [GoogleAuthPlatformAdapter] supplied at construction time.  It contains no
/// `google_sign_in` dependency, no PKCE logic, and no platform `if`-trees.
///
/// Construction:
/// - Use [GoogleAuthAdapter.new] when you want to inject a specific platform
///   adapter (testing, custom platforms, mocks).
/// - Use [GoogleAuthAdapter.fromPlatform] for the common case — it picks the
///   right concrete adapter based on the host OS.
final class GoogleAuthAdapter implements ProviderAuthAdapter {
  /// Inject a specific platform adapter.  Prefer this in tests.
  const GoogleAuthAdapter({required GoogleAuthPlatformAdapter platformAdapter})
    : _platform = platformAdapter;

  /// Convenience factory — selects the platform adapter based on the host OS.
  ///
  /// | Platform              | Adapter                  | Notes |
  /// |-----------------------|--------------------------|-------|
  /// | Web                   | [GoogleWebAuthAdapter]   | OAuth popup via `google_sign_in_web`; [browserLauncher] ignored |
  /// | Android / iOS         | [GoogleMobileAuthAdapter]| Native plugin; [browserLauncher] ignored |
  /// | Windows / macOS / Linux | [GoogleDesktopAuthAdapter] | PKCE via [browserLauncher] |
  ///
  /// This factory is the **only** place in the SDK that performs Google
  /// platform detection.
  factory GoogleAuthAdapter.fromPlatform({
    required GoogleAuthConfig config,
    AuthBrowserLauncher? browserLauncher,
  }) {
    return GoogleAuthAdapter(
      platformAdapter: _selectPlatform(config, browserLauncher),
    );
  }

  final GoogleAuthPlatformAdapter _platform;

  // ── Static deep-link bridge ───────────────────────────────────────────────

  /// Forward deep-link URIs from your app's link handler when using
  /// [GoogleAuthConfig.useWebFlow] on mobile (Android / iOS).
  ///
  /// This is a convenience delegate for [ExternalBrowserLauncher.handleDeepLinkCallback].
  ///
  /// ```dart
  /// // e.g. with package:app_links
  /// _appLinks.uriLinkStream.listen(GoogleAuthAdapter.handleDeepLinkCallback);
  /// ```
  static void handleDeepLinkCallback(Uri uri) =>
      ExternalBrowserLauncher.handleDeepLinkCallback(uri);

  // ── ProviderAuthAdapter ───────────────────────────────────────────────────

  @override
  AuthProvider get provider => AuthProvider.google;

  @override
  Future<ProviderAuthResult> signIn({List<String> scopes = const []}) =>
      _platform.signIn(scopes: scopes);

  @override
  Future<ProviderAuthResult> refresh({List<String> scopes = const []}) =>
      _platform.refresh(scopes: scopes);

  @override
  Future<void> signOut() => _platform.signOut();

  // ── Internals ─────────────────────────────────────────────────────────────

  static GoogleAuthPlatformAdapter _selectPlatform(
    GoogleAuthConfig config,
    AuthBrowserLauncher? launcher,
  ) {
    // kIsWeb must be checked before any Platform.* call — the dart:io Platform
    // stub on web throws UnsupportedError at runtime.
    if (kIsWeb) {
      return GoogleWebAuthAdapter(config: config);
    }
    // When the consumer opts into the browser-based PKCE flow on native
    // platforms, use GoogleDesktopAuthAdapter everywhere.  On mobile the
    // redirect URI is typically an app-scheme URI rather than a loopback URL,
    // so loopback validation is skipped.
    if (config.useWebFlow) {
      final isMobile = Platform.isAndroid || Platform.isIOS;
      return GoogleDesktopAuthAdapter(
        config: config,
        browserLauncher: launcher,
        requireLoopbackRedirect: !isMobile,
      );
    }
    if (Platform.isAndroid || Platform.isIOS) {
      return GoogleMobileAuthAdapter(config: config);
    }
    if (Platform.isMacOS || Platform.isLinux || Platform.isWindows) {
      return GoogleDesktopAuthAdapter(
        config: config,
        browserLauncher: launcher,
      );
    }
    throw const UidsProviderSignInException(
      'Google sign-in is not supported on this platform.',
    );
  }
}
