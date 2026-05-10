/// UIDS Auth SDK public barrel for the legacy package name.
///
/// Import either:
/// - `package:uids_io_sdk_flutter/uids_io_sdk_flutter.dart`
/// - `package:uids_io_sdk_flutter/uids_auth_sdk.dart`
library uids_auth_sdk;

// Browser launcher
export 'src/browser/auth_browser_launcher.dart';
export 'src/browser/external_browser_launcher.dart';

// Config
export 'src/config/github_auth_config.dart';
export 'src/config/google_auth_config.dart';
export 'src/config/microsoft_auth_config.dart';
export 'src/config/uids_sdk_config.dart';

// Errors
export 'src/errors/uids_auth_exception.dart';

// Public models
export 'src/models/auth_provider.dart';
export 'src/models/auth_session.dart';
export 'src/models/auth_user.dart';
export 'src/models/device_models.dart';

// Public SDK interface (includes factory UidsAuthSdk.create())
export 'src/sdk/uids_auth_sdk_public.dart';
