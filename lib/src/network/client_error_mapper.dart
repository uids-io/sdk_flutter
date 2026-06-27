import '../errors/uids_auth_exception.dart';

UidsAuthException mapUidsClientException({
  required int statusCode,
  required String message,
}) {
  final lower = message.toLowerCase();

  if (lower.contains('email') &&
      (lower.contains('already') || lower.contains('in use'))) {
    return UidsEmailAlreadyRegisteredException(message);
  }

  if (lower.contains('username') &&
      (lower.contains('already') || lower.contains('taken'))) {
    return UidsUsernameUnavailableException(message);
  }

  if (lower.contains('email verification') ||
      lower.contains('verification code')) {
    return UidsInvalidEmailVerificationException(message);
  }

  if (lower.contains('invalid otp')) {
    return UidsInvalidOtpException(message);
  }

  if (lower.contains('password must') ||
      lower.contains('special character')) {
    return UidsWeakPasswordException(message);
  }

  if (lower.contains('credentials') ||
      lower.contains('password') ||
      lower.contains('user not found') ||
      lower.contains('not valid')) {
    return UidsInvalidCredentialsException(message);
  }

  if (lower.contains('idp configuration')) {
    return UidsClientException(message, statusCode: statusCode);
  }

  return UidsClientException(message, statusCode: statusCode);
}

Never throwUidsHttpError(int statusCode, String message) {
  if (statusCode >= 400 && statusCode < 500) {
    throw mapUidsClientException(statusCode: statusCode, message: message);
  }

  throw UidsNetworkException(message, statusCode: statusCode);
}
