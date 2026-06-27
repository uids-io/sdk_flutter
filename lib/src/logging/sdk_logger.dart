import '../config/uids_sdk_config.dart';
import 'uids_log_callback.dart';
import 'uids_log_level.dart';

/// Internal structured logger. Forwards to [UidsSdkConfig.onLog] when set.
final class SdkLogger {
  SdkLogger({
    required UidsLogCallback? onLog,
    UidsLogLevel minLevel = UidsLogLevel.debug,
    String namespace = 'sdk',
  }) : _onLog = onLog,
       _minLevel = minLevel,
       _namespace = namespace;

  factory SdkLogger.fromConfig(
    UidsSdkConfig config, {
    String namespace = 'sdk',
  }) {
    return SdkLogger(
      onLog: config.onLog,
      minLevel: config.minLogLevel,
      namespace: namespace,
    );
  }

  final UidsLogCallback? _onLog;
  final UidsLogLevel _minLevel;
  final String _namespace;

  SdkLogger scoped(String namespace) {
    return SdkLogger(
      onLog: _onLog,
      minLevel: _minLevel,
      namespace: namespace,
    );
  }

  void trace(String message, [Map<String, Object?>? data]) =>
      _emit(UidsLogLevel.trace, message, data);

  void debug(String message, [Map<String, Object?>? data]) =>
      _emit(UidsLogLevel.debug, message, data);

  void info(String message, [Map<String, Object?>? data]) =>
      _emit(UidsLogLevel.info, message, data);

  void warn(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    Map<String, Object?>? data,
  }) {
    _emit(
      UidsLogLevel.warn,
      message,
      _mergeData(
        data,
        error: error,
        stackTrace: stackTrace,
      ),
    );
  }

  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    Map<String, Object?>? data,
  }) {
    _emit(
      UidsLogLevel.error,
      message,
      _mergeData(
        data,
        error: error,
        stackTrace: stackTrace,
      ),
    );
  }

  void _emit(
    UidsLogLevel level,
    String message,
    Map<String, Object?>? data,
  ) {
    final onLog = _onLog;
    if (onLog == null) return;
    if (!_minLevel.allows(level)) return;

    final payload = <String, Object?>{
      'namespace': _namespace,
      if (data != null) ..._sanitizeMap(data),
    };

    onLog(level, message, payload.isEmpty ? null : payload);
  }

  Map<String, Object?> _mergeData(
    Map<String, Object?>? data, {
    Object? error,
    StackTrace? stackTrace,
  }) {
    final merged = <String, Object?>{...?data};
    if (error != null) {
      merged['error'] = error.toString();
    }
    if (stackTrace != null) {
      merged['stackTrace'] = stackTrace.toString();
    }
    return merged;
  }
}

const _sensitiveKeyFragments = <String>{
  'accesstoken',
  'refreshtoken',
  'token',
  'password',
  'idtoken',
  'clientsecret',
  'otp',
  'emailotp',
  'authorization',
  'pendingaccesstoken',
  'provideraccesstoken',
  'serverauthcode',
  'bearertoken',
};

Map<String, Object?> _sanitizeMap(Map<String, Object?> source) {
  final out = <String, Object?>{};

  for (final entry in source.entries) {
    out[entry.key] = _sanitizeValue(entry.key, entry.value);
  }

  return out;
}

Object? _sanitizeValue(String key, Object? value) {
  if (_isSensitiveKey(key)) {
    return '[Redacted]';
  }

  if (value is Map) {
    return value.map(
      (k, v) => MapEntry(
        k.toString(),
        _sanitizeValue(k.toString(), v),
      ),
    );
  }

  if (value is Iterable && value is! String) {
    return value.map((item) {
      if (item is MapEntry) {
        return MapEntry(
          item.key.toString(),
          _sanitizeValue(item.key.toString(), item.value),
        );
      }
      return item;
    }).toList();
  }

  return value;
}

bool _isSensitiveKey(String key) {
  final normalized = key.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
  for (final fragment in _sensitiveKeyFragments) {
    if (normalized.contains(fragment)) return true;
  }
  return false;
}

/// Safe URI summary for HTTP logs (scheme, host, port, path — no query secrets).
Map<String, Object?> httpRequestContext({
  required String method,
  required Uri uri,
  int? statusCode,
  int? durationMs,
}) {
  final base = uri.hasPort ? uri.origin : '${uri.scheme}://${uri.host}';

  return {
    'method': method,
    'url': '$base${uri.path}',
    if (statusCode != null) 'statusCode': statusCode,
    if (durationMs != null) 'durationMs': durationMs,
  };
}
