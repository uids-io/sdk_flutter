import 'dart:async';
import 'dart:convert';

import '../errors/uids_auth_exception.dart';
import '../logging/sdk_logger.dart';
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
    SdkLogger? logger,
  }) : _api = apiClient,
       _storage = storage,
       _refreshBeforeExpiry = refreshBeforeExpiry,
       _autoRefresh = autoRefresh,
       _log = logger ?? SdkLogger(onLog: null);

  final AuthApiClient _api;
  final SdkStorage _storage;
  final Duration _refreshBeforeExpiry;
  final bool _autoRefresh;
  final SdkLogger _log;

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
    if (session == null) {
      _log.warn('getValidSession: no session in cache or storage');
      throw const UidsSessionExpiredException();
    }

    bool shouldRefresh;
    try {
      shouldRefresh = session.isExpiredWithBuffer(_refreshBeforeExpiry);
    } on FormatException catch (e, st) {
      _log.warn(
        'getValidSession: could not decode access token expiry; forcing refresh',
        error: e,
        stackTrace: st,
        data: {'user': session.user.email, 'provider': session.provider.label},
      );
      shouldRefresh = true;
    }

    if (shouldRefresh) {
      _log.debug('getValidSession: refresh required', {
        'user': session.user.email,
        'provider': session.provider.label,
        'expiresIn': session.expiresIn,
      });
      return refreshSession();
    }

    _log.trace('getValidSession: using cached session', {
      'user': session.user.email,
      'expiresIn': session.expiresIn,
    });
    return session;
  }

  /// Persists [session] in memory and secure storage, schedules auto-refresh.
  Future<void> saveSession(AuthSession session) async {
    _memoryCache = session;
    await _storage.write(StorageKeys.session, jsonEncode(session.toJson()));
    _sessionController.add(session);
    _log.info('Session saved', {
      'user': session.user.email,
      'provider': session.provider.label,
      'expiresIn': session.expiresIn,
      'autoRefreshEnabled': _autoRefresh,
    });
    _scheduleAutoRefresh(session);
  }

  Future<AuthSession> refreshSession() async {
    if (_activeRefresh != null) {
      _log.debug('refreshSession: coalescing with in-flight refresh');
      return _activeRefresh!;
    }

    _log.info('refreshSession: starting');
    _activeRefresh = _doRefresh();
    try {
      final session = await _activeRefresh!;
      _log.info('refreshSession: succeeded', {
        'user': session.user.email,
        'provider': session.provider.label,
        'expiresIn': session.expiresIn,
      });
      return session;
    } catch (e, st) {
      _log.warn(
        'refreshSession: failed',
        error: e,
        stackTrace: st,
      );
      rethrow;
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
    } on UidsRefreshTokenExpiredException catch (e) {
      _log.warn(
        'Refresh token rejected by backend; clearing local session',
        error: e,
        data: {
          'user': session.user.email,
          'provider': session.provider.label,
        },
      );
      await clearSession();
      rethrow;
    }
  }

  /// Clears memory cache and secure storage, cancels refresh timer.
  Future<void> clearSession() async {
    _log.info('Session cleared');
    _memoryCache = null;
    _refreshTimer?.cancel();
    _refreshTimer = null;
    await _storage.delete(StorageKeys.session);
    _sessionController.add(null);
  }

  /// Clears only the memory cache.  Secure storage is untouched.
  void clearMemoryCache() {
    _log.debug('Session memory cache cleared');
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
      _log.debug('Session loaded from secure storage', {
        'user': session.user.email,
        'provider': session.provider.label,
        'expiresIn': session.expiresIn,
      });
      _scheduleAutoRefresh(session, refreshIfDue: false);
      return session;
    } catch (e, st) {
      _log.warn(
        'Corrupted session in secure storage; deleting',
        error: e,
        stackTrace: st,
      );
      await _storage.delete(StorageKeys.session);
      return null;
    }
  }

  void _scheduleAutoRefresh(AuthSession session, {bool refreshIfDue = true}) {
    if (!_autoRefresh) {
      _log.trace('Auto-refresh disabled; timer not scheduled');
      return;
    }
    _refreshTimer?.cancel();

    DateTime accessExpiry;
    try {
      accessExpiry = session.accessTokenExpiresAt.toUtc();
    } on FormatException catch (e, st) {
      if (!refreshIfDue) return;
      _log.warn(
        'Could not schedule auto-refresh; triggering immediate refresh',
        error: e,
        stackTrace: st,
      );
      _refreshTimer = Timer(Duration.zero, _triggerRefresh);
      return;
    }

    final delay = accessExpiry
        .subtract(_refreshBeforeExpiry)
        .difference(DateTime.now().toUtc());

    if (delay.isNegative) {
      if (!refreshIfDue) {
        _log.trace('Session near expiry on load; refresh deferred');
        return;
      }
      _log.debug('Access token near expiry; scheduling immediate auto-refresh');
      _refreshTimer = Timer(Duration.zero, _triggerRefresh);
      return;
    }

    _log.debug('Auto-refresh scheduled', {
      'inSeconds': delay.inSeconds,
      'user': session.user.email,
    });
    _refreshTimer = Timer(delay, _triggerRefresh);
  }

  void _triggerRefresh() {
    _log.debug('Auto-refresh timer fired');
    refreshSession().ignore();
  }
}
