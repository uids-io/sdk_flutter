import 'package:flutter_test/flutter_test.dart';
import 'package:uids_io_sdk_flutter/uids_io_sdk_flutter.dart';

void main() {
  test('uids sdk config stores required values', () {
    final config = UidsSdkConfig(
      apiBaseUrl: Uri.parse('https://api.example.com'),
      authBaseUrl: Uri.parse('https://auth.example.com'),
      clientId: 'client-id',
      audience: 'audience',
      google: const GoogleAuthConfig(webClientId: 'web-id'),
    );

    expect(config.apiBaseUrl, Uri.parse('https://api.example.com'));
    expect(config.authBaseUrl, Uri.parse('https://auth.example.com'));
    expect(config.clientId, 'client-id');
    expect(config.audience, 'audience');
    expect(config.google?.webClientId, 'web-id');
  });

  test('auth session parses backend auth payload', () {
    final session = AuthSession.fromJson({
      'accessToken': 'jwt',
      'refreshToken': 'refresh',
      'accessTokenExpiresAt': '2030-01-01T00:00:00.000Z',
      'refreshTokenExpiresAt': '2030-02-01T00:00:00.000Z',
      'username': 'a@b.com',
      'idpName': 'Gmail',
    });

    expect(session.accessToken, 'jwt');
    expect(session.refreshToken, 'refresh');
    expect(session.user.email, 'a@b.com');
    expect(session.provider, AuthProvider.google);
    expect(session.authorizationHeader, 'Bearer jwt');
  });

  test('auth session parses email /aud token payload', () {
    final session = AuthSession.fromJson({
      'token': 'scoped-jwt',
      'refreshToken': 'db-refresh-hex',
      'username': 'user@example.com',
      'idpName': 'Email',
    });

    expect(session.accessToken, 'scoped-jwt');
    expect(session.refreshToken, 'db-refresh-hex');
    expect(session.provider, AuthProvider.email);
    expect(session.isRefreshTokenExpired, isFalse);
  });

  test('email otp result parses tenant entities', () {
    final result = EmailOtpResult.fromJson({
      'username': 'user@example.com',
      'idpName': 'Email',
      'entities': [
        {
          'tenant': 'owner@example.com',
          'refresh_token': 'abc123',
          'authorizations': {'roles': ['all']},
        },
      ],
    });

    expect(result.username, 'user@example.com');
    expect(result.entities, hasLength(1));
    expect(result.entities.first.tenant, 'owner@example.com');
    expect(result.entities.first.refreshToken, 'abc123');
    expect(result.entities.first.roles, ['all']);
  });

  test('email registration result parses backend payload', () {
    final result = EmailRegistrationResult.fromJson(
      {
        'accessToken': 'pending-jwt',
        'qrCodeDataURL': 'data:image/png;base64,abc',
        'message': 'User registered successfully',
        'username': 'newuser',
        'email': 'new@example.com',
      },
      email: 'new@example.com',
      username: 'newuser',
    );

    expect(result.pendingAccessToken, 'pending-jwt');
    expect(result.qrCodeDataUrl, startsWith('data:image/png'));
    expect(result.email, 'new@example.com');
    expect(result.username, 'newuser');
  });

  test('username availability parses backend payload', () {
    final result = UsernameAvailabilityResult.fromJson({
      'username': 'newuser',
      'available': true,
      'isSuccess': true,
    });

    expect(result.username, 'newuser');
    expect(result.available, isTrue);
  });

  test('registered device parses backend payload', () {
    final device = RegisteredDevice.fromJson({
      'id': 'device-1',
      'stable_device_key': 'stable-key',
      'platform': 'windows',
      'device_name': 'Workstation',
      'registered_at': '2030-01-01T00:00:00.000Z',
    });

    expect(device.id, 'device-1');
    expect(device.stableDeviceKey, 'stable-key');
    expect(device.platform, 'windows');
    expect(device.deviceName, 'Workstation');
  });
}
