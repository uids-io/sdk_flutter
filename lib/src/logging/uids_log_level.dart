/// Severity for SDK log events forwarded to [UidsSdkConfig.onLog].
enum UidsLogLevel {
  trace,
  debug,
  info,
  warn,
  error;

  /// Whether events at [other] should be emitted when this is the minimum level.
  bool allows(UidsLogLevel other) => other.index >= index;
}
