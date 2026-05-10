/// Abstraction for launching an OAuth authorization flow and capturing the
/// redirect callback.
///
/// Implementations are responsible for:
/// 1. Opening [authUrl] in some browser surface.
/// 2. Detecting when the provider redirects back to [redirectUri].
/// 3. Returning the full callback [Uri] (with `code`, `state`, and any other
///    query parameters sent by the provider).
///
/// The returned URI is passed back to the calling adapter, which validates
/// `state`, checks for provider errors, extracts `code`, and exchanges it for
/// tokens.  The launcher itself performs no OAuth-specific validation — it is
/// completely provider-agnostic.
///
/// Two built-in implementations are provided:
/// - [ExternalBrowserLauncher]: opens the system browser (the default).
///
/// Usage in [UidsSdkConfig]:
/// ```dart
/// // Default: external system browser (no change needed)
/// UidsSdkConfig(...)
/// ```
abstract interface class AuthBrowserLauncher {
  /// Opens [authUrl] and waits for the OAuth redirect to [redirectUri].
  ///
  /// Returns the full callback [Uri] containing the authorization code and any
  /// other query parameters sent by the provider.
  ///
  /// Throws a cancellation error when the user dismisses the flow.
  /// Throws a sign-in error on timeout or unrecoverable failures.
  Future<Uri> launch({
    required Uri authUrl,
    required Uri redirectUri,
    required Duration timeout,
  });
}
