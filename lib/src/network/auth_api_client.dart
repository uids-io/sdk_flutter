import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/uids_sdk_config.dart';
import '../errors/uids_auth_exception.dart';
import '../logging/sdk_logger.dart';
import '../models/auth_session.dart';
import '../models/device_models.dart';
import '../models/email_auth_models.dart';
import '../models/provider_auth_result.dart';
import 'auth_endpoints.dart';
import 'client_error_mapper.dart';
import 'network_failure_message.dart';

/// HTTP client that communicates with the UIDS authentication backend.
///
/// All public methods convert HTTP / network errors into typed
/// [UidsAuthException] subclasses so callers never deal with raw Dio/http
/// exceptions.
final class AuthApiClient {
  AuthApiClient({
    required UidsSdkConfig config,
    http.Client? httpClient,
    SdkLogger? logger,
  }) : _http = httpClient ?? http.Client(),
       _log = logger ?? SdkLogger.fromConfig(config, namespace: 'network'),
       _endpoints = AuthEndpoints(
         authBaseUrl: config.authBaseUrl,
         apiBaseUrl: config.apiBaseUrl,
       );

  final http.Client _http;
  final SdkLogger _log;
  final AuthEndpoints _endpoints;

  // ── Auth ──────────────────────────────────────────────────────────────────

  /// Exchange a [ProviderAuthResult] for a backend [AuthSession].
  Future<AuthSession> exchangeProviderToken(ProviderAuthResult result) async {
    // final body = <String, dynamic>{
    //   'provider': result.provider.name,
    //   'id_token': result.idToken,
    //   'client_id': _config.clientId,
    //   if (_config.clientSecret != null) 'client_secret': _config.clientSecret,
    //   if (_config.audience != null) 'audience': _config.audience,
    //   if (result.accessToken != null)
    //     'provider_access_token': result.accessToken,
    //   if (result.serverAuthCode != null)
    //     'server_auth_code': result.serverAuthCode,
    // };
    final body = <String, dynamic>{
      'accessToken': result.accessToken,
      'idpName': result.provider.label,
      'tokenType': 'Bearer',
      'idToken': result.idToken,
    };

    final json = await _post(_endpoints.exchangeToken, body, authToken: null);
    return AuthSession.fromJson(json);
  }

  /// Use [refreshToken] to obtain a refreshed [AuthSession].
  ///
  /// [username] and [provider] are sent as compatibility hints and also used
  /// as local fallbacks in case older backend responses omit them.
  Future<AuthSession> refreshToken(
    String refreshToken, {
    required String username,
    required String provider,
  }) async {
    final body = <String, dynamic>{
      // Backend contract: refreshToken (camelCase).
      'refreshToken': refreshToken,
      // Optional compatibility context for backend/client fallback handling.
      'username': username,
      'idpName': provider,
    };

    try {
      final json = await _post(_endpoints.refreshToken, body, authToken: null);
      _normalizeSessionJson(json, username: username, provider: provider);
      _log.info('Refresh token exchange succeeded', {
        'user': username,
        'provider': provider,
      });
      return AuthSession.fromJson(json);
    } on UidsClientException catch (e) {
      _log.warn(
        'Refresh token exchange rejected',
        error: e,
        data: {
          'user': username,
          'provider': provider,
          'statusCode': e.statusCode,
        },
      );
      if (e.statusCode == 401 || e.statusCode == 400) {
        throw const UidsRefreshTokenExpiredException();
      }
      rethrow;
    } on UidsNetworkException catch (e) {
      _log.warn(
        'Refresh token network failure',
        error: e,
        data: {
          'user': username,
          'provider': provider,
          'statusCode': e.statusCode,
        },
      );
      if (e.statusCode == 401 || e.statusCode == 400) {
        throw const UidsRefreshTokenExpiredException();
      }
      rethrow;
    }
  }

  // ── Email / password ──────────────────────────────────────────────────────

  /// Returns whether [username] is available for email registration.
  Future<UsernameAvailabilityResult> checkUsernameAvailable(
    String username,
  ) async {
    final trimmed = username.trim();
    if (trimmed.isEmpty) {
      throw ArgumentError.value(username, 'username', 'Username cannot be empty.');
    }

    final json = await _get(
      _endpoints.checkUsername(trimmed),
      authToken: null,
    );
    return UsernameAvailabilityResult.fromJson(json);
  }

  /// Sends a one-time verification code to [email] before registration.
  Future<void> sendRegisterEmailOtp({required String email}) async {
    await _post(
      _endpoints.registerSendEmailOtp,
      <String, dynamic>{'email': email.trim()},
      authToken: null,
    );
  }

  /// Register a new account with username, email, password, and email OTP.
  Future<EmailRegistrationResult> registerWithEmail({
    required String username,
    required String email,
    required String password,
    required String emailOtp,
  }) async {
    final body = <String, dynamic>{
      'username': username.trim(),
      'email': email.trim(),
      'password': password,
      'emailOtp': emailOtp.trim(),
    };

    final json = await _post(_endpoints.register, body, authToken: null);
    return EmailRegistrationResult.fromJson(
      json,
      email: email.trim(),
      username: username.trim(),
    );
  }

  /// Step 1 of email sign-in — validates credentials and returns a pending token.
  Future<EmailLoginResult> loginWithEmail({
    required String email,
    required String password,
  }) async {
    final body = <String, dynamic>{
      'email': email,
      'password': password,
    };

    try {
      final json = await _post(_endpoints.login, body, authToken: null);
      return EmailLoginResult.fromJson(json, email: email);
    } on UidsAuthException {
      rethrow;
    }
  }

  /// Step 2 — verify the authenticator TOTP code.
  Future<EmailOtpResult> verifyEmailOtp({
    required String otp,
    required String pendingAccessToken,
  }) async {
    try {
      final json = await _post(
        _endpoints.otpVerify,
        <String, dynamic>{'otp': otp},
        authToken: pendingAccessToken,
      );
      return EmailOtpResult.fromJson(json);
    } on UidsNetworkException catch (e) {
      if (e.statusCode == 400) {
        throw UidsInvalidOtpException(e.message);
      }
      rethrow;
    }
  }

  /// Step 3 — exchange tenant credentials for a fully-scoped API session.
  Future<AuthSession> exchangeAud({
    required String tenant,
    required String username,
    required String refreshToken,
    String idpName = 'Email',
    String? deviceId,
  }) async {
    final body = <String, dynamic>{
      'tenant': tenant,
      'username': username,
      'refreshToken': refreshToken,
      'idpName': idpName,
      if (deviceId != null) 'deviceId': deviceId,
    };

    final json = await _post(_endpoints.aud, body, authToken: null);
    _normalizeSessionJson(
      json,
      username: username,
      provider: idpName,
    );
    return AuthSession.fromJson(json);
  }

  // ── Device ────────────────────────────────────────────────────────────────

  /// Register a new device; returns the [RegisteredDevice] from the backend.
  Future<RegisteredDevice> registerDevice(
    DeviceRegisterRequest request,
    String accessToken,
  ) async {
    final json = await _post(
      _endpoints.registerDevice,
      request.toJson(),
      authToken: accessToken,
    );
    return RegisteredDevice.fromJson(json);
  }

  /// Update an existing device.
  Future<RegisteredDevice> updateDevice(
    String deviceId,
    DeviceUpdateRequest request,
    String accessToken,
  ) async {
    final json = await _patch(
      _endpoints.updateDevice(deviceId),
      request.toJson(),
      authToken: accessToken,
    );
    return RegisteredDevice.fromJson(json);
  }

  /// Unregister (delete) a device.
  Future<void> unregisterDevice(String deviceId, String accessToken) async {
    await _delete(
      _endpoints.unregisterDevice(deviceId),
      authToken: accessToken,
    );
  }

  /// Fetch and validate a registered device by ID.
  Future<RegisteredDevice> validateDevice(
    String deviceId,
    String accessToken,
  ) async {
    final json = await _get(
      _endpoints.validateDevice(deviceId),
      authToken: accessToken,
    );
    return RegisteredDevice.fromJson(json);
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  Map<String, String> _headers({String? authToken}) => {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    if (authToken != null) 'Authorization': 'Bearer $authToken',
  };

  Future<Map<String, dynamic>> _post(
    Uri uri,
    Map<String, dynamic> body, {
    required String? authToken,
  }) async {
    return _send(
      method: 'POST',
      uri: uri,
      send: () => _http.post(
        uri,
        headers: _headers(authToken: authToken),
        body: jsonEncode(body),
      ),
    );
  }

  Future<Map<String, dynamic>> _patch(
    Uri uri,
    Map<String, dynamic> body, {
    required String? authToken,
  }) async {
    return _send(
      method: 'PATCH',
      uri: uri,
      send: () => _http.patch(
        uri,
        headers: _headers(authToken: authToken),
        body: jsonEncode(body),
      ),
    );
  }

  Future<Map<String, dynamic>> _get(
    Uri uri, {
    required String? authToken,
  }) async {
    return _send(
      method: 'GET',
      uri: uri,
      send: () => _http.get(
        uri,
        headers: _headers(authToken: authToken),
      ),
    );
  }

  Future<void> _delete(Uri uri, {required String? authToken}) async {
    await _sendVoid(
      method: 'DELETE',
      uri: uri,
      send: () => _http.delete(
        uri,
        headers: _headers(authToken: authToken),
      ),
    );
  }

  Future<Map<String, dynamic>> _send({
    required String method,
    required Uri uri,
    required Future<http.Response> Function() send,
  }) async {
    final started = DateTime.now();
    _log.debug(
      'HTTP request started',
      httpRequestContext(method: method, uri: uri),
    );

    try {
      final response = await send();
      final durationMs = DateTime.now().difference(started).inMilliseconds;
      final context = httpRequestContext(
        method: method,
        uri: uri,
        statusCode: response.statusCode,
        durationMs: durationMs,
      );

      if (response.statusCode >= 200 && response.statusCode < 300) {
        _log.debug('HTTP request completed', context);
        if (response.body.isEmpty) return {};
        return jsonDecode(response.body) as Map<String, dynamic>;
      }

      final message = _readErrorMessage(response);
      _log.warn('HTTP request failed', data: {...context, 'message': message});
      throwUidsHttpError(response.statusCode, message);
    } on UidsAuthException {
      rethrow;
    } catch (e, st) {
      final durationMs = DateTime.now().difference(started).inMilliseconds;
      throw _failTransport(
        method: method,
        uri: uri,
        durationMs: durationMs,
        error: e,
        stackTrace: st,
      );
    }
  }

  Future<void> _sendVoid({
    required String method,
    required Uri uri,
    required Future<http.Response> Function() send,
  }) async {
    final started = DateTime.now();
    _log.debug(
      'HTTP request started',
      httpRequestContext(method: method, uri: uri),
    );

    try {
      final response = await send();
      final durationMs = DateTime.now().difference(started).inMilliseconds;
      final context = httpRequestContext(
        method: method,
        uri: uri,
        statusCode: response.statusCode,
        durationMs: durationMs,
      );

      if (response.statusCode >= 400) {
        _log.warn(
          'HTTP request failed',
          data: {
            ...context,
            'message':
                'DELETE failed with status ${response.statusCode}',
          },
        );
        throw UidsNetworkException(
          '$method $uri failed with status ${response.statusCode}',
          statusCode: response.statusCode,
        );
      }

      _log.debug('HTTP request completed', context);
    } on UidsAuthException {
      rethrow;
    } catch (e, st) {
      final durationMs = DateTime.now().difference(started).inMilliseconds;
      throw _failTransport(
        method: method,
        uri: uri,
        durationMs: durationMs,
        error: e,
        stackTrace: st,
      );
    }
  }

  Never _failTransport({
    required String method,
    required Uri uri,
    required int durationMs,
    required Object error,
    StackTrace? stackTrace,
  }) {
    final userMessage = networkFailureUserMessage(error, uri: uri);
    final context = {
      ...httpRequestContext(
        method: method,
        uri: uri,
        durationMs: durationMs,
      ),
      'userMessage': userMessage,
    };

    if (isExpectedTransportFailure(error)) {
      _log.warn('HTTP request could not reach server', data: context);
    } else {
      _log.warn(
        'HTTP transport error',
        data: context,
        error: error,
        stackTrace: stackTrace,
      );
    }

    throw UidsNetworkException(userMessage, cause: error);
  }

  String _readErrorMessage(http.Response response) {
    final fallback =
        'HTTP ${response.statusCode}: ${response.reasonPhrase ?? 'Unknown error'}';

    if (response.body.isEmpty) return fallback;

    try {
      final body = jsonDecode(response.body);
      if (body is Map) {
        final message = body['message'] ?? body['errorDetails'];
        if (message is String && message.isNotEmpty) return message;
      }
    } catch (_) {
      // Fall back to generic HTTP message.
    }

    return fallback;
  }

  void _normalizeSessionJson(
    Map<String, dynamic> json, {
    required String username,
    required String provider,
  }) {
    json['username'] ??= username;
    json['idpName'] ??= provider;
    if (json['accessToken'] == null && json['token'] != null) {
      json['accessToken'] = json['token'];
    }
  }
}
