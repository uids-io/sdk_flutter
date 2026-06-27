/// Optional hints for an interactive provider sign-in.
final class ProviderSignInOptions {
  const ProviderSignInOptions({this.loginHint});

  /// Pre-selects the identity provider account (Google `login_hint`,
  /// Microsoft `login_hint`).
  final String? loginHint;

  static const none = ProviderSignInOptions();

  bool get hasLoginHint => loginHint != null && loginHint!.trim().isNotEmpty;

  String? get trimmedLoginHint {
    final hint = loginHint?.trim();
    if (hint == null || hint.isEmpty) return null;
    return hint;
  }
}
