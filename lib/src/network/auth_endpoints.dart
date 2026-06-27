/// Resolves all API endpoint paths relative to the configured base URLs.
///
/// Paths are intentionally kept separate from the HTTP client so they can be
/// unit-tested without network access.
final class AuthEndpoints {
  const AuthEndpoints({required this.authBaseUrl, required this.apiBaseUrl});

  final Uri authBaseUrl;
  final Uri apiBaseUrl;

  // ── Auth / token endpoints ────────────────────────────────────────────────

  /// Exchange a provider ID/access token for a backend session.
  // Uri get exchangeToken =>
  //     authBaseUrl.replace(path: '${authBaseUrl.path}/v1/auth/exchange');
  Uri get exchangeToken => authBaseUrl.replace(path: '${apiBaseUrl.path}/auth');

  /// Use a refresh token to obtain a new access token.
  // Uri get refreshToken =>
  // authBaseUrl.replace(path: '${authBaseUrl.path}/v1/auth/refresh');
  Uri get refreshToken =>
      authBaseUrl.replace(path: '${authBaseUrl.path}/refresh');

  // ── Email / password endpoints ────────────────────────────────────────────

  Uri checkUsername(String username) => authBaseUrl.replace(
    path: '${authBaseUrl.path}/checkUsername',
    queryParameters: {'username': username},
  );

  Uri get register => authBaseUrl.replace(path: '${authBaseUrl.path}/register');

  Uri get registerSendEmailOtp =>
      authBaseUrl.replace(path: '${authBaseUrl.path}/register/sendEmailOtp');

  Uri get login => authBaseUrl.replace(path: '${authBaseUrl.path}/login');

  Uri get otpVerify =>
      authBaseUrl.replace(path: '${authBaseUrl.path}/otpVerify');

  Uri get aud => authBaseUrl.replace(path: '${authBaseUrl.path}/aud');

  // ── Device endpoints ──────────────────────────────────────────────────────

  /// Register a new device.
  // Uri get registerDevice => apiBaseUrl.replace(path: '${apiBaseUrl.path}/v1/devices');
  Uri get registerDevice =>
      apiBaseUrl.replace(path: '${apiBaseUrl.path}/registerDevice');

  /// Update an existing device (PATCH /{id}).
  Uri updateDevice(String deviceId) =>
      apiBaseUrl.replace(path: '${apiBaseUrl.path}/v1/devices/$deviceId');

  /// Delete / unregister a device (DELETE /{id}).
  Uri unregisterDevice(String deviceId) =>
      apiBaseUrl.replace(path: '${apiBaseUrl.path}/v1/devices/$deviceId');

  /// Validate a registered device (GET /{id}).
  Uri validateDevice(String deviceId) =>
      apiBaseUrl.replace(path: '${apiBaseUrl.path}/v1/devices/$deviceId');
}
