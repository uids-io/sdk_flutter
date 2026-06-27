import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:url_launcher/url_launcher.dart' as launcher;

import '../errors/uids_auth_exception.dart';
import 'auth_browser_launcher.dart';
import 'oauth_loopback_coordinator.dart';

/// Launches OAuth authentication in the system browser (default behavior).
///
/// Desktop uses [OAuthLoopbackCoordinator] — one loopback listener per port,
/// callbacks routed by OAuth `state`.
final class ExternalBrowserLauncher implements AuthBrowserLauncher {
  const ExternalBrowserLauncher();

  static final StreamController<Uri> _deepLinkController =
      StreamController<Uri>.broadcast();

  static void handleDeepLinkCallback(Uri uri) => _deepLinkController.add(uri);

  @override
  Future<Uri> launch({
    required Uri authUrl,
    required Uri redirectUri,
    required Duration timeout,
  }) {
    if (_isMobile) {
      return _launchMobile(
        authUrl: authUrl,
        redirectUri: redirectUri,
        timeout: timeout,
      );
    }
    return _launchDesktop(
      authUrl: authUrl,
      redirectUri: redirectUri,
      timeout: timeout,
    );
  }

  Future<Uri> _launchDesktop({
    required Uri authUrl,
    required Uri redirectUri,
    required Duration timeout,
  }) async {
    try {
      return await OAuthLoopbackCoordinator.waitForCallback(
        authUrl: authUrl,
        redirectUri: redirectUri,
        timeout: timeout,
        onReady: () async {
          final launched = await launcher.launchUrl(
            authUrl,
            mode: launcher.LaunchMode.externalApplication,
          );
          if (!launched) {
            throw const UidsProviderSignInException(
              'Could not open the system browser for authentication.',
            );
          }
        },
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Browser authentication failed.',
        cause: e,
      );
    }
  }

  Future<Uri> _launchMobile({
    required Uri authUrl,
    required Uri redirectUri,
    required Duration timeout,
  }) async {
    final completer = Completer<Uri>();
    StreamSubscription<Uri>? sub;
    final expectedState = authUrl.queryParameters['state'];

    try {
      sub = _deepLinkController.stream.listen((uri) {
        if (!_matchesRedirectUri(uri, redirectUri)) return;

        final code = uri.queryParameters['code'];
        final error = uri.queryParameters['error'];
        if (code == null && error == null) return;

        if (expectedState != null &&
            expectedState.isNotEmpty &&
            uri.queryParameters['state'] != expectedState) {
          return;
        }
        if (!completer.isCompleted) completer.complete(uri);
      });

      final launched = await launcher.launchUrl(
        authUrl,
        mode: launcher.LaunchMode.externalApplication,
      );
      if (!launched) {
        throw const UidsProviderSignInException(
          'Could not open the browser for authentication.',
        );
      }

      return await completer.future.timeout(
        timeout,
        onTimeout: () {
          throw const UidsProviderSignInException(
            'Authentication timed out — no deep-link callback was received.',
          );
        },
      );
    } on UidsAuthException {
      rethrow;
    } catch (e) {
      throw UidsProviderSignInException(
        'Mobile browser authentication failed.',
        cause: e,
      );
    } finally {
      await sub?.cancel();
    }
  }

  bool get _isMobile => !kIsWeb && (Platform.isAndroid || Platform.isIOS);

  bool _matchesRedirectUri(Uri callback, Uri redirectUri) {
    if (redirectUri.scheme == 'http' || redirectUri.scheme == 'https') {
      return callback.scheme == redirectUri.scheme &&
          callback.host == redirectUri.host &&
          callback.port == redirectUri.port &&
          callback.path == redirectUri.path;
    }

    return callback.scheme == redirectUri.scheme &&
        callback.host == redirectUri.host &&
        callback.path == redirectUri.path;
  }
}
