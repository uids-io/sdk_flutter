/// Human-readable summary for registration UI.
const uidsRegistrationPasswordRequirements =
    '8–12 characters with uppercase, lowercase, a number, and a special character.';

const _minPasswordLength = 8;
const _maxPasswordLength = 12;

/// Live strength hint while the user types a registration password.
enum RegistrationPasswordStrength {
  none,
  weak,
  medium,
  strong,
}

/// Returns `null` when [password] meets registration policy, else an error.
String? validateRegistrationPassword(String? password) {
  if (password == null || password.isEmpty) {
    return 'Password is required';
  }

  if (password.trim().isEmpty) {
    return 'Password is required';
  }

  if (password.length < _minPasswordLength) {
    return 'Password must be at least 8 characters';
  }

  if (password.length > _maxPasswordLength) {
    return 'Password must be at most 12 characters';
  }

  if (!RegExp(r'[a-z]').hasMatch(password)) {
    return 'Password must contain at least one lowercase letter';
  }

  if (!RegExp(r'[A-Z]').hasMatch(password)) {
    return 'Password must contain at least one uppercase letter';
  }

  if (!RegExp(r'[0-9]').hasMatch(password)) {
    return 'Password must contain at least one number';
  }

  if (!RegExp(r'[^A-Za-z0-9]').hasMatch(password)) {
    return 'Password must contain at least one special character';
  }

  return null;
}

/// Scores [password] for UI feedback (weak / medium / strong).
RegistrationPasswordStrength evaluateRegistrationPasswordStrength(
  String password,
) {
  if (password.isEmpty) {
    return RegistrationPasswordStrength.none;
  }

  if (password.length > _maxPasswordLength) {
    return RegistrationPasswordStrength.weak;
  }

  var score = 0;
  if (password.length >= _minPasswordLength) score++;
  if (RegExp(r'[a-z]').hasMatch(password)) score++;
  if (RegExp(r'[A-Z]').hasMatch(password)) score++;
  if (RegExp(r'[0-9]').hasMatch(password)) score++;
  if (RegExp(r'[^A-Za-z0-9]').hasMatch(password)) score++;

  if (score >= 5) return RegistrationPasswordStrength.strong;
  if (score >= 3) return RegistrationPasswordStrength.medium;
  return RegistrationPasswordStrength.weak;
}

/// Basic password check for sign-in (existing accounts may predate policy).
String? validateSignInPassword(String? password) {
  if (password == null || password.isEmpty) {
    return 'Password is required';
  }

  if (password.trim().isEmpty) {
    return 'Password is required';
  }

  if (password.length > 512) {
    return 'Password is too long';
  }

  return null;
}
