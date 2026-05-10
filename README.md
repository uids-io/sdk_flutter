# UIDS Auth SDK — `uids_io_sdk_flutter`

A Flutter authentication SDK supporting Google, Microsoft, and GitHub sign-in with backend token exchange, session management, and device registration.

## Features

- Provider sign-in: Google, Microsoft, GitHub
- Backend token exchange and session management
- Silent provider refresh and session refresh
- Device registration as an independent flow
- Secure storage-backed session persistence
- Configurable authentication browser: **system browser** or **in-app WebView**
- Zero bundled navigation or UI outside the optional WebView dialog

## Installation

```yaml
dependencies:
  uids_io_sdk_flutter: ^0.2.0
```

```dart
import 'package:uids_io_sdk_flutter/uids_io_sdk_flutter.dart';
```

## Quick Start

```dart
final sdk = UidsAuthSdk.create();

await sdk.initialize(
  UidsSdkConfig(
    apiBaseUrl:  Uri.parse('https://api.example.com'),
    authBaseUrl: Uri.parse('https://auth.example.com'),
    clientId: 'backend-client-id',
    google: GoogleAuthConfig(
      webClientId:          'google-web-client-id',
      androidClientId:      'google-android-client-id',
      iosClientId:          'google-ios-client-id',
      desktopClientId:      'google-desktop-client-id',
      desktopClientSecret:  'google-desktop-secret',
      desktopRedirectUri:   'http://localhost:8585/callback',
    ),
    microsoft: MicrosoftAuthConfig(
      clientId:    'azure-app-client-id',
      tenantId:    'common',
      redirectUri: 'http://localhost:9000/auth',   // desktop
      // redirectUri: 'msauth://com.example.app/callback', // mobile
    ),
    github: GitHubAuthConfig(
      clientId:     'github-oauth-app-client-id',
      clientSecret: 'github-oauth-app-secret',
      redirectUri:  'http://localhost:9100/auth',  // desktop
      // redirectUri: 'com.example.app://auth/github', // mobile
    ),
  ),
);

final session = await sdk.signInWithProvider(provider: AuthProvider.google);
print(session.user.email);
```

---

## Authentication Browser

By default the SDK opens the system browser for all OAuth flows. You can switch to an in-app WebView dialog by setting `UidsSdkConfig.browserLauncher`.

### Option 1 — External browser (default)

No configuration required. The existing behavior is unchanged.

```dart
UidsSdkConfig(
  // no browserLauncher → ExternalBrowserLauncher() is used automatically
  ...
)
```

**Desktop** (Windows / macOS / Linux): a transient loopback HTTP server on the port in your `redirectUri` captures the OAuth callback.

**Mobile** (Android / iOS): your app must forward deep-link URIs to the SDK. Set up a link-handler package (e.g. `app_links`) and forward every incoming URI:

```dart
// main.dart or wherever you initialise link handling
_appLinks.uriLinkStream.listen(ExternalBrowserLauncher.handleDeepLinkCallback);

// Legacy per-adapter delegates also work unchanged:
// MicrosoftAuthAdapter.handleDeepLinkCallback(uri)
// GitHubAuthAdapter.handleDeepLinkCallback(uri)
```

Register each provider's redirect URI scheme in `AndroidManifest.xml` / `Info.plist` as required by the provider.

---

### Custom launcher

Implement `AuthBrowserLauncher` for any other browser surface:

```dart
final class MyCustomLauncher implements AuthBrowserLauncher {
  @override
  Future<Uri> launch({
    required Uri authUrl,
    required Uri redirectUri,
    required Duration timeout,
  }) async {
    // open authUrl, wait for redirect to redirectUri, return callback Uri
  }
}
```

Pass it the same way:

```dart
UidsSdkConfig(browserLauncher: MyCustomLauncher(), ...)
```

---

## Providers

### Google

| Platform | Adapter | Notes |
|---|---|---|
| Web | `GoogleWebAuthAdapter` | OAuth popup via `google_sign_in_web` |
| Android / iOS | `GoogleMobileAuthAdapter` | Native `google_sign_in` plugin |
| Desktop | `GoogleDesktopAuthAdapter` | OAuth 2.0 PKCE via `AuthBrowserLauncher` |

```dart
GoogleAuthConfig(
  webClientId:         'YOUR_WEB_CLIENT_ID',       // required for web & as mobile fallback
  androidClientId:     'YOUR_ANDROID_CLIENT_ID',   // optional
  iosClientId:         'YOUR_IOS_CLIENT_ID',        // optional
  desktopClientId:     'YOUR_DESKTOP_CLIENT_ID',
  desktopClientSecret: 'YOUR_DESKTOP_SECRET',
  desktopRedirectUri:  'http://localhost:8585/callback',
)
```

#### Web setup

1. Add both packages to your app's `pubspec.yaml`:

```yaml
dependencies:
  google_sign_in: ^7.2.0
  google_sign_in_web: ^1.1.3
```

2. Add the Google Identity Services script to `web/index.html` **before** `main.dart.js`:

```html
<head>
  ...
  <script src="https://accounts.google.com/gsi/client"></script>
</head>
```

3. Create a **Web application** OAuth 2.0 client in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials) and add your app's origin to the allowed JavaScript origins (e.g. `http://localhost:PORT` for local dev).  Pass that client ID as `webClientId`.

> **Note:** On web the `AuthBrowserLauncher` setting has no effect for Google — the plugin handles the OAuth popup internally.
```

### Microsoft

Full OAuth 2.0 Authorization Code flow on all platforms via `AuthBrowserLauncher`.

```dart
MicrosoftAuthConfig(
  clientId:    'YOUR_AZURE_CLIENT_ID',
  tenantId:    'common',            // or specific tenant GUID
  redirectUri: 'http://localhost:9000/auth',  // desktop loopback
  // redirectUri: 'msauth://com.example.app/callback', // mobile custom scheme
)
```

### GitHub

OAuth 2.0 + PKCE on all platforms via `AuthBrowserLauncher`.

```dart
GitHubAuthConfig(
  clientId:     'YOUR_GITHUB_CLIENT_ID',
  clientSecret: 'YOUR_GITHUB_CLIENT_SECRET',
  redirectUri:  'http://localhost:9100/auth',        // desktop loopback
  // redirectUri: 'com.example.app://auth/github',  // mobile custom scheme
)
```

---

## Session management

```dart
// Check sign-in state
final signedIn = await sdk.isSignedIn();

// Get current session (null if not signed in)
final session = await sdk.currentSession();

// Get a valid (non-expired) session — refreshes automatically if needed
final session = await sdk.getValidSession();

// Get the raw access token
final token = await sdk.accessToken();

// Get Authorization header map
final headers = await sdk.authHeaders();
// → {'Authorization': 'Bearer <token>'}

// Manual refresh
await sdk.refreshSession(force: true);

// Silent provider refresh (re-exchanges provider credential for a new session)
await sdk.refreshProviderSession(provider: AuthProvider.microsoft);

// Sign out (clears session, does not touch device state)
await sdk.signOut();
```

### Reactive updates

```dart
sdk.sessionChanges.listen((session) {
  // session is null when signed out
});
```

---

## Device registration

Device registration is independent of authentication. Sign-in does not register a device; sign-out does not unregister one.

```dart
// Register (or retrieve cached) device
final device = await sdk.ensureDeviceRegistered(
  DeviceRegisterRequest(
    stableDeviceKey: 'your-stable-device-uuid',
    platform: 'android',
  ),
);

// Update device metadata
await sdk.updateDevice(DeviceUpdateRequest(pushToken: 'new-fcm-token'));

// Unregister
await sdk.unregisterDevice();
```

---

## Architecture

```
UidsAuthSdk (public facade)
 ├── AuthManager          → ProviderAuthAdapter → AuthBrowserLauncher
 │                                                └── ExternalBrowserLauncher (default)
 ├── SessionManager       → AuthApiClient, SecureSdkStorage
 └── DeviceManager        → AuthApiClient, SecureSdkStorage
```

- Adapters are UI-agnostic — they call the launcher and validate the returned URI.
- The launcher decides how to open the auth URL and capture the callback.
- Session and device flows are orthogonal; neither depends on the other.

---

## Error handling

All SDK errors extend `UidsAuthException`:

| Type | When |
|---|---|
| `UidsProviderCancelledException` | User cancelled the sign-in flow |
| `UidsProviderSignInException` | Provider flow failed or timed out |
| `UidsNetworkException` | HTTP failure talking to the backend |
| `UidsSessionExpiredException` | Access token expired |
| `UidsRefreshTokenExpiredException` | Refresh token revoked |
| `UidsProviderNotConfiguredException` | Config missing for the requested provider |
| `UidsNotInitializedException` | `initialize()` was not called first |

```dart
try {
  final session = await sdk.signInWithProvider(provider: AuthProvider.github);
} on UidsProviderCancelledException {
  // user dismissed the dialog
} on UidsProviderSignInException catch (e) {
  print('Sign-in failed: $e');
}
```
