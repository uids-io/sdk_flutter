/// Base exception for all UIDS Auth SDK errors.
sealed class UidsAuthException implements Exception {
  const UidsAuthException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() => '$runtimeType: $message${cause != null ? ' (cause: $cause)' : ''}';
}

/// Thrown when a network request fails (non-2xx, timeout, DNS, etc.).
final class UidsNetworkException extends UidsAuthException {
  const UidsNetworkException(
    super.message, {
    super.cause,
    this.statusCode,
  });

  final int? statusCode;
}

/// Thrown when the backend access token has expired and cannot be used.
final class UidsSessionExpiredException extends UidsAuthException {
  const UidsSessionExpiredException([super.message = 'Session has expired.']);
}

/// Thrown when the refresh token is invalid, revoked, or expired.
final class UidsRefreshTokenExpiredException extends UidsAuthException {
  const UidsRefreshTokenExpiredException(
      [super.message = 'Refresh token has expired or been revoked.']);
}

/// Thrown when the user cancels the provider sign-in flow.
final class UidsProviderCancelledException extends UidsAuthException {
  const UidsProviderCancelledException(
      [super.message = 'User cancelled the sign-in flow.']);
}

/// Thrown when a provider sign-in flow fails after it starts.
final class UidsProviderSignInException extends UidsAuthException {
  const UidsProviderSignInException(super.message, {super.cause});
}

/// Thrown when device registration or validation fails.
final class UidsDeviceRegistrationException extends UidsAuthException {
  const UidsDeviceRegistrationException(super.message, {super.cause});
}

/// Thrown when the SDK is used before [UidsAuthSdk.initialize] is called.
final class UidsNotInitializedException extends UidsAuthException {
  const UidsNotInitializedException(
      [super.message = 'SDK has not been initialized. Call initialize() first.']);
}

/// Thrown when a requested auth provider is not configured.
final class UidsProviderNotConfiguredException extends UidsAuthException {
  const UidsProviderNotConfiguredException(super.message);
}

/// Thrown when email/password credentials are rejected by the backend.
final class UidsInvalidCredentialsException extends UidsAuthException {
  const UidsInvalidCredentialsException(super.message);
}

/// Thrown when a registration password does not meet the strength policy.
final class UidsWeakPasswordException extends UidsAuthException {
  const UidsWeakPasswordException(super.message);
}

/// Thrown when a username is already taken during registration.
final class UidsUsernameUnavailableException extends UidsAuthException {
  const UidsUsernameUnavailableException(super.message);
}

/// Thrown when a TOTP code is invalid or expired.
final class UidsInvalidOtpException extends UidsAuthException {
  const UidsInvalidOtpException(super.message);
}

/// Thrown when the account has no accessible tenants.
final class UidsNoTenantsAvailableException extends UidsAuthException {
  const UidsNoTenantsAvailableException([
    super.message = 'No tenants available for this account.',
  ]);
}

/// Thrown for API client errors (4xx) with a server-provided message.
final class UidsClientException extends UidsAuthException {
  const UidsClientException(
    super.message, {
    this.statusCode,
  });

  final int? statusCode;
}

/// Thrown when registration is attempted with an email that already exists.
final class UidsEmailAlreadyRegisteredException extends UidsAuthException {
  const UidsEmailAlreadyRegisteredException(super.message);
}

/// Thrown when the email verification code is invalid or expired.
final class UidsInvalidEmailVerificationException extends UidsAuthException {
  const UidsInvalidEmailVerificationException(super.message);
}

/// Thrown when the requested tenant is not in the user's entity list.
final class UidsTenantNotFoundException extends UidsAuthException {
  const UidsTenantNotFoundException(super.message);
}

/// Thrown when the user has multiple tenants and none was specified.
final class UidsTenantSelectionRequiredException extends UidsAuthException {
  const UidsTenantSelectionRequiredException(
    this.tenants, [
    super.message =
        'Multiple tenants available. Pass tenant to completeEmailSignIn.',
  ]);

  final List<String> tenants;
}
