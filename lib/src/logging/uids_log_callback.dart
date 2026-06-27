import 'uids_log_level.dart';

/// Consumer-controlled sink for SDK diagnostics.
///
/// The SDK never prints on its own. Wire this in [UidsSdkConfig.onLog], e.g.:
///
/// ```dart
/// UidsSdkConfig(
///   onLog: (level, message, [data]) {
///     debugPrint('[uids][${level.name}] $message ${data ?? ''}');
///   },
///   // ...
/// );
/// ```
typedef UidsLogCallback =
    void Function(
      UidsLogLevel level,
      String message, [
      Map<String, Object?>? data,
    ]);
