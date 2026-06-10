import '../utils/jwt_token_utils.dart';
import 'auth_provider.dart';
import 'auth_user.dart';

/// Backend session returned after successful provider token exchange.
final class AuthSession {
  const AuthSession({
    required this.accessToken,
    required this.refreshToken,
    required this.user,
    required this.provider,
    this.tokenType = 'Bearer',
  });

  final String accessToken;
  final String refreshToken;

  /// Access-token expiry derived directly from JWT `exp`.
  DateTime get accessTokenExpiresAt => readJwtExpiry(accessToken);

  /// Refresh-token expiry derived from JWT `exp`, or a far-future date for
  /// opaque DB refresh tokens used by email/password auth.
  DateTime get refreshTokenExpiresAt {
    try {
      return readJwtExpiry(refreshToken);
    } on FormatException {
      return DateTime.utc(2099);
    }
  }

  final AuthUser user;
  final AuthProvider provider;
  final String tokenType;

  bool get isExpired =>
      DateTime.now().toUtc().isAfter(accessTokenExpiresAt.toUtc());

  bool get isRefreshTokenExpired =>
      DateTime.now().toUtc().isAfter(refreshTokenExpiresAt.toUtc());

  bool isExpiredWithBuffer(Duration buffer) {
    final expiryWithBuffer = accessTokenExpiresAt.toUtc().subtract(buffer);
    return DateTime.now().toUtc().isAfter(expiryWithBuffer);
  }

  String get authorizationHeader => '$tokenType $accessToken';

  factory AuthSession.fromJson(Map<String, dynamic> json) {
    final accessToken =
        json['accessToken'] as String? ?? json['token'] as String?;
    final refreshToken = json['refreshToken'] as String?;
    final username =
        json['username'] as String? ?? json['sub'] as String? ?? '';

    if (accessToken == null || refreshToken == null) {
      throw FormatException(
        'Session response is missing accessToken/token or refreshToken',
      );
    }

    return AuthSession(
      accessToken: accessToken,
      refreshToken: refreshToken,
      user: AuthUser.temp(username),
      provider: _readProvider(json['idpName'] ?? json['provider']),
      tokenType: json['tokenType'] as String? ?? 'Bearer',
    );
  }

  static AuthProvider _readProvider(Object? value) {
    final provider = value?.toString().toLowerCase().trim();

    switch (provider) {
      case 'google':
      case 'gmail':
        return AuthProvider.google;

      case 'microsoft':
      case 'outlook':
        return AuthProvider.microsoft;

      case 'github':
        return AuthProvider.github;

      case 'email':
        return AuthProvider.email;

      default:
        throw FormatException('Unknown provider: $value');
    }
  }

  /// Serialises the session for secure-storage caching.
  Map<String, dynamic> toJson() => {
    'accessToken': accessToken,
    'refreshToken': refreshToken,
    'username': user.email,
    'provider': provider.name,
    'tokenType': tokenType,
  };

  // ── Display helpers ────────────────────────────────────────────────────────

  /// Remaining time until the access token expires.
  /// Returns [Duration.zero] if already expired.
  Duration get timeUntilExpiry {
    final remaining = accessTokenExpiresAt.toUtc().difference(
      DateTime.now().toUtc(),
    );
    return remaining.isNegative ? Duration.zero : remaining;
  }

  /// Human-readable remaining time, e.g. "1h 58m" or "45s".
  String get expiresIn {
    final d = timeUntilExpiry;
    if (d == Duration.zero) return 'expired';
    if (d.inHours >= 1) {
      return '${d.inHours}h ${d.inMinutes.remainder(60)}m';
    }
    if (d.inMinutes >= 1) {
      return '${d.inMinutes}m ${d.inSeconds.remainder(60)}s';
    }
    return '${d.inSeconds}s';
  }

  /// Access-token expiry as a clean local-time string, e.g. "08 May 2026 16:51".
  ///
  /// Converts the stored UTC value to the device's local timezone so the
  /// displayed time matches what the user sees on their clock.
  String get formattedExpiresAt {
    final local = accessTokenExpiresAt.toLocal();
    final d = local.day.toString().padLeft(2, '0');
    final mon = _monthAbbr(local.month);
    final h = local.hour.toString().padLeft(2, '0');
    final m = local.minute.toString().padLeft(2, '0');
    return '$d $mon ${local.year} $h:$m';
  }

  static String _monthAbbr(int month) => const [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ][month - 1];

  AuthSession copyWith({
    String? accessToken,
    String? refreshToken,
    AuthUser? user,
    AuthProvider? provider,
    String? tokenType,
  }) {
    return AuthSession(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      user: user ?? this.user,
      provider: provider ?? this.provider,
      tokenType: tokenType ?? this.tokenType,
    );
  }

  @override
  String toString() {
    return 'AuthSession(user: ${user.email}, '
        'accessTokenExpiresAt: $accessTokenExpiresAt, '
        'refreshTokenExpiresAt: $refreshTokenExpiresAt, '
        'expired: $isExpired)';
  }
}
