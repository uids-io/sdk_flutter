import 'dart:async';

import 'package:http/http.dart' as http;

/// Returns true for common transport failures (server down, timeout, offline).
bool isExpectedTransportFailure(Object error) {
  final root = _rootCause(error);
  final haystack = _errorText(root);
  return _looksLikeServerUnavailable(haystack) ||
      _looksLikeTimeout(root, haystack) ||
      _looksLikeDeviceOffline(haystack);
}

/// User-facing message for transport failures talking to the auth backend.
String networkFailureUserMessage(Object error, {Uri? uri}) {
  final root = _rootCause(error);
  final haystack = _errorText(root);

  if (_looksLikeServerUnavailable(haystack)) {
    return 'Our sign-in service is temporarily unavailable. Please try again in a moment.';
  }

  if (_looksLikeTimeout(root, haystack)) {
    return 'The sign-in server took too long to respond. Please try again.';
  }

  if (_looksLikeDeviceOffline(haystack)) {
    return 'Could not connect. Please check your internet connection and try again.';
  }

  return 'Could not reach the sign-in server. Please try again shortly.';
}

Object _rootCause(Object error) {
  if (error is http.ClientException) {
    return error.toString();
  }
  return error;
}

String _errorText(Object error) {
  if (error is String) return error.toLowerCase();
  return error.toString().toLowerCase();
}

bool _looksLikeServerUnavailable(String haystack) {
  const patterns = [
    'connection refused',
    'actively refused',
    'failed to connect',
    'failed host lookup',
    'connection reset',
    'connection closed before full header',
    'software caused connection abort',
    'cannot open socket',
    'no connection could be made',
    'target machine actively refused',
    'remote computer refused',
    'errno = 111',
    'errno: 111',
    'errno = 1225',
    'errno: 1225',
    'os error: connection refused',
  ];

  for (final pattern in patterns) {
    if (haystack.contains(pattern)) return true;
  }

  return false;
}

bool _looksLikeTimeout(Object root, String haystack) {
  if (root is TimeoutException) return true;
  return haystack.contains('timed out') || haystack.contains('timeout');
}

bool _looksLikeDeviceOffline(String haystack) {
  const patterns = [
    'network is unreachable',
    'no route to host',
    'no internet',
    'internet connection appears to be offline',
  ];

  for (final pattern in patterns) {
    if (haystack.contains(pattern)) return true;
  }

  return false;
}

/// True when [message] looks like an internal/debug transport string.
bool isInternalNetworkMessage(String message) {
  final trimmed = message.trim();
  if (trimmed.isEmpty) return true;

  return RegExp(r'^(GET|POST|PATCH|DELETE|PUT) ').hasMatch(trimmed) ||
      trimmed.endsWith(' failed') ||
      trimmed.startsWith('HTTP ') ||
      trimmed.startsWith('Network error:');
}

/// Resolves a user-facing message for app-layer [NetworkException] handling.
String resolveNetworkExceptionUserMessage({
  required String message,
  int? statusCode,
}) {
  if (statusCode != null && statusCode >= 500 && statusCode < 600) {
    if (message.isNotEmpty && !isInternalNetworkMessage(message)) {
      return message;
    }
    return 'The sign-in server encountered an error. Please try again shortly.';
  }

  if (message.isNotEmpty && !isInternalNetworkMessage(message)) {
    return message;
  }

  return 'Our sign-in service is temporarily unavailable. Please try again in a moment.';
}
