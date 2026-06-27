import '../browser/auth_browser_launcher.dart';
import '../logging/uids_log_callback.dart';
import '../logging/uids_log_level.dart';
import 'github_auth_config.dart';
import 'google_auth_config.dart';
import 'microsoft_auth_config.dart';

/// Top-level configuration passed to [UidsAuthSdk.initialize].
///
/// All credentials and URLs are supplied by the consumer app — the SDK never
/// hard-codes any values.
final class UidsSdkConfig {
  const UidsSdkConfig({
    required this.apiBaseUrl,
    required this.authBaseUrl,
    required this.clientId,
    this.clientSecret,
    this.audience,
    this.autoRefresh = true,
    this.refreshBeforeExpiry = const Duration(minutes: 5),
    this.google,
    this.microsoft,
    this.github,
    this.browserLauncher,
    this.onLog,
    this.minLogLevel = UidsLogLevel.debug,
  });

  /// Base URL for the consumer's main API (used for device endpoints, etc.).
  final Uri apiBaseUrl;

  /// Base URL for the authentication/token service.
  final Uri authBaseUrl;

  /// OAuth 2.0 client ID registered with the backend.
  final String clientId;

  /// OAuth 2.0 client secret (omit for public clients / PKCE flows).
  final String? clientSecret;

  /// OAuth 2.0 audience claim expected by the backend.
  final String? audience;

  /// Whether the SDK should automatically schedule a token refresh before
  /// expiry.  Set to `false` if you prefer manual refresh via
  /// [UidsAuthSdk.refreshSession].
  final bool autoRefresh;

  /// How far before [AuthSession.expiresAt] the SDK proactively refreshes the
  /// token when [autoRefresh] is `true`.
  final Duration refreshBeforeExpiry;

  /// Google Sign-In configuration.  Required if you call
  /// [UidsAuthSdk.signInWithProvider] with [AuthProvider.google].
  final GoogleAuthConfig? google;

  /// Microsoft authentication configuration.  Required if you call
  /// [UidsAuthSdk.signInWithProvider] with [AuthProvider.microsoft].
  final MicrosoftAuthConfig? microsoft;

  /// GitHub OAuth App configuration.  Required if you call
  /// [UidsAuthSdk.signInWithProvider] with [AuthProvider.github].
  final GitHubAuthConfig? github;

  /// Controls how OAuth authorization URLs are opened and how the callback is
  /// captured.
  ///
  /// - `null` (default): uses [ExternalBrowserLauncher], which opens the
  ///   system browser.  This is the same behavior as previous SDK versions —
  ///   no migration needed.
  ///
  /// - Any custom [AuthBrowserLauncher] implementation for advanced use cases.
  final AuthBrowserLauncher? browserLauncher;

  /// Optional consumer log sink. The SDK never prints on its own — wire
  /// `debugPrint`, your app logger, or analytics here.
  ///
  /// ```dart
  /// onLog: (level, message, [data]) {
  ///   debugPrint('[uids][${level.name}] $message ${data ?? ''}');
  /// },
  /// ```
  final UidsLogCallback? onLog;

  /// Minimum severity forwarded to [onLog]. Defaults to [UidsLogLevel.debug].
  final UidsLogLevel minLogLevel;
}
