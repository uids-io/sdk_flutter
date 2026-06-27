import 'dart:async';
import 'dart:io';

import '../auth/auth_callback_page.dart';
import '../errors/uids_auth_exception.dart';

typedef OAuthLoopbackResponder = Future<void> Function(
  HttpRequest request, {
  required bool isSuccess,
  required String message,
});

/// One loopback HTTP listener per port; routes OAuth callbacks by `state`.
///
/// Prevents cross-talk when multiple flows share the same redirect port (e.g.
/// mailbox and profile Microsoft both use `http://localhost:8085/auth`).
final class OAuthLoopbackCoordinator {
  OAuthLoopbackCoordinator._();

  static final _pendingByState = <String, _OAuthLoopbackWaiter>{};
  static final _serversByPort = <int, HttpServer>{};

  static Future<Uri> waitForCallback({
    required Uri authUrl,
    required Uri redirectUri,
    required Duration timeout,
    OAuthLoopbackResponder? respond,
    Future<void> Function()? onReady,
  }) async {
    final state = authUrl.queryParameters['state'];
    if (state == null || state.isEmpty) {
      throw const UidsProviderSignInException(
        'OAuth authorization URL is missing the state parameter.',
      );
    }

    final completer = Completer<Uri>();
    final expectedPath = redirectUri.path.isEmpty ? '/' : redirectUri.path;

    _pendingByState[state] = _OAuthLoopbackWaiter(
      completer: completer,
      redirectUri: redirectUri,
      expectedPath: expectedPath,
      respond: respond,
    );

    await _ensureServer(redirectUri.port);

    try {
      if (onReady != null) {
        await onReady();
      }

      return await completer.future.timeout(
        timeout,
        onTimeout: () {
          throw const UidsProviderSignInException(
            'Authentication timed out — the browser callback never arrived.',
          );
        },
      );
    } finally {
      _pendingByState.remove(state);
      await _maybeCloseServer(redirectUri.port);
    }
  }

  static Future<void> _ensureServer(int port) async {
    if (_serversByPort.containsKey(port)) return;

    final server = await HttpServer.bind(
      InternetAddress.loopbackIPv4,
      port,
      shared: true,
    );

    server.listen(
      _handleRequest,
      onError: (Object e) {
        for (final pending in _pendingByState.values) {
          if (!pending.completer.isCompleted) {
            pending.completer.completeError(
              UidsProviderSignInException(
                'Loopback server error during authentication.',
                cause: e,
              ),
            );
          }
        }
        _pendingByState.clear();
      },
    );

    _serversByPort[port] = server;
  }

  static Future<void> _maybeCloseServer(int port) async {
    if (_pendingByState.isNotEmpty) return;
    await _serversByPort.remove(port)?.close(force: true);
  }

  static Future<void> _handleRequest(HttpRequest request) async {
    final uri = request.uri;
    final code = uri.queryParameters['code'];
    final error = uri.queryParameters['error'];
    final state = uri.queryParameters['state'];

    // Ignore stray probes (no OAuth result yet).
    if (code == null && error == null) {
      request.response.statusCode = HttpStatus.notFound;
      await request.response.close();
      return;
    }

    if (state == null || state.isEmpty) {
      await _respond(
        request,
        status: HttpStatus.badRequest,
        message: 'Missing OAuth state in callback.',
        isSuccess: false,
      );
      return;
    }

    final pending = _pendingByState[state];
    if (pending == null) {
      await _respond(
        request,
        status: HttpStatus.badRequest,
        message: 'No matching sign-in session for this callback.',
        isSuccess: false,
      );
      return;
    }

    if (uri.path != pending.expectedPath) {
      await _respond(
        request,
        status: HttpStatus.notFound,
        message: 'Unknown callback path.',
        isSuccess: false,
      );
      return;
    }

    final isSuccess = error == null;
    final message = isSuccess
        ? 'Authentication complete. You may close this tab and return to the app.'
        : 'Sign-in was rejected by the provider: $error';

    if (pending.respond != null) {
      await pending.respond!(request, isSuccess: isSuccess, message: message);
    } else {
      await _respond(
        request,
        status: isSuccess ? HttpStatus.ok : HttpStatus.badRequest,
        message: message,
        isSuccess: isSuccess,
      );
    }

    if (!pending.completer.isCompleted) {
      pending.completer.complete(
        pending.redirectUri.replace(queryParameters: uri.queryParameters),
      );
    }
  }

  static Future<void> _respond(
    HttpRequest request, {
    required int status,
    required String message,
    required bool isSuccess,
  }) async {
    request.response
      ..statusCode = status
      ..headers.contentType = ContentType.html
      ..write(
        buildAuthCallbackHtml(
          title: isSuccess
              ? 'Authentication Complete'
              : 'Authentication Failed',
          message: message,
          isSuccess: isSuccess,
        ),
      );
    await request.response.close();
  }
}

final class _OAuthLoopbackWaiter {
  _OAuthLoopbackWaiter({
    required this.completer,
    required this.redirectUri,
    required this.expectedPath,
    this.respond,
  });

  final Completer<Uri> completer;
  final Uri redirectUri;
  final String expectedPath;
  final OAuthLoopbackResponder? respond;
}
