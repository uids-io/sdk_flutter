/// UIDS Auth SDK public barrel for the legacy package name.
///
/// Import either:
/// - `package:uids_io_sdk_flutter/uids_io_sdk_flutter.dart`
/// - `package:uids_io_sdk_flutter/uids_auth_sdk.dart`
library uids_auth_sdk;

// Browser launcher
export 'src/browser/auth_browser_launcher.dart';
export 'src/browser/external_browser_launcher.dart';
export 'src/browser/oauth_loopback_coordinator.dart';

// Config
export 'src/config/github_auth_config.dart';
export 'src/config/google_auth_config.dart';
export 'src/config/microsoft_auth_config.dart';
export 'src/config/uids_sdk_config.dart';

// Logging (consumer-controlled via UidsSdkConfig.onLog)
export 'src/logging/uids_log_callback.dart';
export 'src/logging/uids_log_level.dart';

// Errors
export 'src/errors/uids_auth_exception.dart';

// Public models
export 'src/models/auth_provider.dart';
export 'src/models/auth_session.dart';
export 'src/models/auth_user.dart';
export 'src/models/device_models.dart';
export 'src/models/email_auth_models.dart';
export 'src/models/provider_sign_in_options.dart';

// Public SDK interface (includes factory UidsAuthSdk.create())
export 'src/sdk/uids_auth_sdk_public.dart';

// Validation helpers
export 'src/utils/password_validation.dart';

// Network error helpers
export 'src/network/network_failure_message.dart';

// Storage — implement SdkStorage to supply a custom persistence layer
export 'src/storage/sdk_storage.dart';
export 'src/storage/secure_sdk_storage.dart';
