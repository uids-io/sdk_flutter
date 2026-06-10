import 'dart:async';
import 'dart:convert';

import '../errors/uids_auth_exception.dart';
import '../models/auth_session.dart';
import '../network/auth_api_client.dart';
import '../storage/sdk_storage.dart';
import '../storage/storage_keys.dart';

/// Manages the lifecycle of an [AuthSession].
///
/// Responsibilities:
/// - Memory-first / secure-storage fallback reads.
/// - Token expiry checks with configurable buffer.
/// - A single scheduled auto-refresh timer (no polling).
/// - Manual refresh (e.g. after a 401).
/// - Broadcasting session changes via [sessionChanges].
final class SessionManager {
  SessionManager({
    required AuthApiClient apiClient,
    required SdkStorage storage,
    required Duration refreshBeforeExpiry,
    required bool autoRefresh,
  }) : _api = apiClient,
       _storage = storage,
       _refreshBeforeExpiry = refreshBeforeExpiry,
       _autoRefresh = autoRefresh;

  final AuthApiClient _api;
  final SdkStorage _storage;
  final Duration _refreshBeforeExpiry;
  final bool _autoRefresh;

  AuthSession? _memoryCache;
  Timer? _refreshTimer;
  Future<AuthSession>? _activeRefresh;

  final _sessionController = StreamController<AuthSession?>.broadcast();

  /// Stream of session changes.  Emits `null` on sign-out.
  Stream<AuthSession?> get sessionChanges => _sessionController.stream;

  // ── Public API ────────────────────────────────────────────────────────────

  /// Returns the cached session (memory → secure storage), or `null`.
  Future<AuthSession?> currentSession() async {
    if (_memoryCache != null) return _memoryCache;
    return _loadFromStorage();
  }

  /// Returns a valid session, refreshing if expired or near expiry.
  Future<AuthSession> getValidSession() async {
    final session = await currentSession();
    if (session == null) throw const UidsSessionExpiredException();

    bool shouldRefresh;
    try {
      shouldRefresh = session.isExpiredWithBuffer(_refreshBeforeExpiry);
    } on FormatException {
      // If token claims cannot be decoded locally, force a backend refresh.
      shouldRefresh = true;
    }

    if (shouldRefresh) {
      return refreshSession();
    }
    return session;
  }

  /// Persists [session] in memory and secure storage, schedules auto-refresh.
  Future<void> saveSession(AuthSession session) async {
    _memoryCache = session;
    await _storage.write(StorageKeys.session, jsonEncode(session.toJson()));
    _sessionController.add(session);
    _scheduleAutoRefresh(session);
  }

  Future<AuthSession> refreshSession() async {
    if (_activeRefresh != null) return _activeRefresh!;

    _activeRefresh = _doRefresh();
    try {
      return await _activeRefresh!;
    } finally {
      _activeRefresh = null;
    }
  }

  Future<AuthSession> _doRefresh() async {
    final session = await currentSession();
    if (session == null) throw const UidsSessionExpiredException();

    try {
      final refreshed = await _api.refreshToken(
        session.refreshToken,
        username: session.user.email,
        provider: session.provider.label,
      );
      await saveSession(refreshed);
      return refreshed;
    } on UidsRefreshTokenExpiredException {
      await clearSession();
      rethrow;
    }
  }

  /// Clears memory cache and secure storage, cancels refresh timer.
  Future<void> clearSession() async {
    _memoryCache = null;
    _refreshTimer?.cancel();
    _refreshTimer = null;
    await _storage.delete(StorageKeys.session);
    _sessionController.add(null);
  }

  /// Clears only the memory cache.  Secure storage is untouched.
  void clearMemoryCache() {
    _memoryCache = null;
    _refreshTimer?.cancel();
    _refreshTimer = null;
  }

  void dispose() {
    _refreshTimer?.cancel();
    _sessionController.close();
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  Future<AuthSession?> _loadFromStorage() async {
    final raw = await _storage.read(StorageKeys.session);

    if (raw == null) return null;
    try {
      final session = AuthSession.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );

      _memoryCache = session;
      _scheduleAutoRefresh(session, refreshIfDue: false);
      return session;
    } catch (_) {
      // Corrupted storage — treat as missing.
      await _storage.delete(StorageKeys.session);
      return null;
    }
  }

  void _scheduleAutoRefresh(AuthSession session, {bool refreshIfDue = true}) {
    if (!_autoRefresh) return;
    _refreshTimer?.cancel();

    DateTime accessExpiry;
    try {
      accessExpiry = session.accessTokenExpiresAt.toUtc();
    } on FormatException {
      if (!refreshIfDue) return;
      _refreshTimer = Timer(Duration.zero, _triggerRefresh);
      return;
    }

    final delay = accessExpiry
        .subtract(_refreshBeforeExpiry)
        .difference(DateTime.now().toUtc());

    if (delay.isNegative) {
      if (!refreshIfDue) return;
      _refreshTimer = Timer(Duration.zero, _triggerRefresh);
      return;
    }

    _refreshTimer = Timer(delay, _triggerRefresh);
  }

  void _triggerRefresh() {
    refreshSession().ignore();
  }
}
