import '../models/auth_provider.dart';
import '../models/provider_auth_result.dart';
import '../models/provider_sign_in_options.dart';

/// Contract that every provider adapter must implement.
///
/// Rules:
/// - Adapters ONLY interact with the identity provider.
/// - Adapters MUST NOT call the backend.
/// - Adapters MUST NOT store tokens.
/// - Adapters MUST NOT use BuildContext / navigation.
abstract interface class ProviderAuthAdapter {
  /// The provider this adapter handles.
  AuthProvider get provider;

  /// Initiates the sign-in flow and returns a [ProviderAuthResult] on success.
  ///
  /// Throws [UidsProviderCancelledException] if the user dismisses the UI.
  /// Throws [UidsAuthException] for any other failure.
  Future<ProviderAuthResult> signIn({
    List<String> scopes = const [],
    ProviderSignInOptions options = ProviderSignInOptions.none,
  });

  /// Silently re-acquires a fresh provider credential without showing UI.
  ///
  /// Implementations should:
  /// - Use the provider's silent / cached refresh path (e.g. Google's
  ///   `signInSilently`, MSAL's `acquireTokenSilent`).
  /// - Return a [ProviderAuthResult] containing a fresh `idToken` (and an
  ///   `accessToken` when applicable).
  ///
  /// Throws [UidsProviderSignInException] when no cached credential is
  /// available or the silent refresh is rejected by the provider — callers
  /// should treat this as "interactive sign-in required" and fall back to
  /// [signIn].
  ///
  /// Like [signIn], this method MUST NOT call the backend or persist tokens.
  Future<ProviderAuthResult> refresh({List<String> scopes = const []});

  /// Signs the user out of the provider (clears any locally cached provider
  /// credential).  Does NOT revoke the backend session.
  Future<void> signOut();
}
