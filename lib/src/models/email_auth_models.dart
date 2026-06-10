/// Result of [UidsAuthSdk.checkUsernameAvailable].
final class UsernameAvailabilityResult {
  const UsernameAvailabilityResult({
    required this.username,
    required this.available,
  });

  final String username;
  final bool available;

  factory UsernameAvailabilityResult.fromJson(Map<String, dynamic> json) {
    return UsernameAvailabilityResult(
      username: json['username'] as String,
      available: json['available'] as bool? ?? false,
    );
  }
}

/// A tenant the user can access after email 2FA verification.
final class EmailTenantEntity {
  const EmailTenantEntity({
    required this.tenant,
    required this.refreshToken,
    this.roles = const [],
  });

  final String tenant;
  final String refreshToken;
  final List<String> roles;

  factory EmailTenantEntity.fromJson(Map<String, dynamic> json) {
    final authorizations = json['authorizations'];
    final roles = authorizations is Map
        ? (authorizations['roles'] as List?)?.cast<String>() ?? const []
        : const <String>[];

    return EmailTenantEntity(
      tenant: json['tenant'] as String,
      refreshToken: json['refresh_token'] as String,
      roles: roles,
    );
  }
}

/// Result of [UidsAuthSdk.registerWithEmail].
///
/// Contains a QR code for setting up the authenticator app and a pending
/// access token. Pass the token and a TOTP code to [UidsAuthSdk.completeEmailSignIn].
final class EmailRegistrationResult {
  const EmailRegistrationResult({
    required this.pendingAccessToken,
    required this.qrCodeDataUrl,
    required this.email,
    required this.username,
    this.message,
  });

  /// Short-lived JWT used for the 2FA step (`Authorization: Bearer …`).
  final String pendingAccessToken;

  /// Base64 data-URL of the authenticator QR code image.
  final String qrCodeDataUrl;

  final String email;
  final String username;
  final String? message;

  factory EmailRegistrationResult.fromJson(
    Map<String, dynamic> json, {
    required String email,
    required String username,
  }) {
    return EmailRegistrationResult(
      pendingAccessToken: json['accessToken'] as String,
      qrCodeDataUrl: json['qrCodeDataURL'] as String,
      email: json['email'] as String? ?? email,
      username: json['username'] as String? ?? username,
      message: json['message'] as String?,
    );
  }
}

/// Result of [UidsAuthSdk.loginWithEmail] (step 1 of email sign-in).
final class EmailLoginResult {
  const EmailLoginResult({
    required this.pendingAccessToken,
    required this.email,
    this.message,
  });

  /// Short-lived JWT used for the 2FA step (`Authorization: Bearer …`).
  final String pendingAccessToken;
  final String email;
  final String? message;

  factory EmailLoginResult.fromJson(
    Map<String, dynamic> json, {
    required String email,
  }) {
    return EmailLoginResult(
      pendingAccessToken: json['accessToken'] as String,
      email: email,
      message: json['message'] as String?,
    );
  }
}

/// Result of OTP verification before tenant token exchange.
final class EmailOtpResult {
  const EmailOtpResult({
    required this.username,
    required this.entities,
    required this.idpName,
  });

  final String username;
  final List<EmailTenantEntity> entities;
  final String idpName;

  factory EmailOtpResult.fromJson(Map<String, dynamic> json) {
    final rawEntities = json['entities'] as List? ?? const [];
    return EmailOtpResult(
      username: json['username'] as String,
      entities: rawEntities
          .cast<Map<String, dynamic>>()
          .map(EmailTenantEntity.fromJson)
          .toList(),
      idpName: json['idpName'] as String? ?? 'Email',
    );
  }
}
