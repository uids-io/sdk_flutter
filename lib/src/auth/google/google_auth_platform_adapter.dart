import '../../models/provider_auth_result.dart';
import '../../models/provider_sign_in_options.dart';

/// Platform-level Google sign-in port.
///
/// One concrete implementation per OS family:
/// - [GoogleMobileAuthAdapter]  — Android & iOS (uses `google_sign_in`)
/// - [GoogleDesktopAuthAdapter] — Windows / macOS / Linux (PKCE loopback)
///
/// Implementations MUST:
/// - Only talk to Google.  No backend calls.
/// - Never persist tokens.  At most, hold credentials in memory for the
///   lifetime of the adapter (required to support [refresh]).
/// - Be free of `BuildContext`, navigation, and dialogs.
abstract interface class GoogleAuthPlatformAdapter {
  /// Interactive sign-in.  Throws `UidsProviderCancelledException` when the
  /// user dismisses the flow, `UidsProviderSignInException` for any other
  /// failure.
  Future<ProviderAuthResult> signIn({
    List<String> scopes = const [],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  });

  /// Silent re-acquisition of a fresh credential without showing UI.
  ///
  /// Throws `UidsProviderSignInException` when no usable cached credential is
  /// available — callers should fall back to interactive [signIn].
  Future<ProviderAuthResult> refresh({List<String> scopes = const []});

  /// Drops any in-memory or platform-cached credential.  Idempotent.
  Future<void> signOut();
}
