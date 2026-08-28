use ferriskey_core::domain::common::entities::app_errors::CoreError;

/// Returns `true` only when the error represents a genuine credential/code
/// REJECTION — a wrong password, an unknown user, a wrong OTP, or a wrong
/// recovery code. These are the only outcomes that may increment a per-account
/// brute-force counter.
///
/// Infrastructure and session errors (database failures, internal errors,
/// service-unavailable, missing/expired sessions, etc.) must NOT count:
/// otherwise an attacker who can induce server errors — or a transient outage —
/// could drive a legitimate account into the throttle (lockout DoS).
pub fn is_credential_rejection(err: &CoreError) -> bool {
    matches!(
        err,
        // Login-form path (`/login-actions/authenticate`) wrong password / unknown user.
        CoreError::InvalidPassword
            | CoreError::InvalidUser
            // Token password-grant (ROPC) returns the generic `Invalid` for a wrong
            // password — see `password()` in core. It maps to HTTP 400 (a client-side
            // rejection), NOT a transient 5xx, so counting it does not reintroduce the
            // induced-error lockout DoS this guard exists to prevent.
            | CoreError::Invalid
            // MFA second factor.
            | CoreError::TotpVerificationFailed(_)
            | CoreError::RecoveryCodeBurnError(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_rejections_count() {
        assert!(is_credential_rejection(&CoreError::InvalidPassword));
        assert!(is_credential_rejection(&CoreError::InvalidUser));
        // Token password-grant wrong-password surfaces as the generic `Invalid`.
        assert!(is_credential_rejection(&CoreError::Invalid));
        assert!(is_credential_rejection(&CoreError::TotpVerificationFailed(
            "bad code".to_string()
        )));
        assert!(is_credential_rejection(&CoreError::RecoveryCodeBurnError(
            "bad code".to_string()
        )));
    }

    #[test]
    fn infrastructure_and_session_errors_do_not_count() {
        // The lockout-DoS-prone cases the reviewer flagged.
        assert!(!is_credential_rejection(&CoreError::InternalServerError));
        assert!(!is_credential_rejection(&CoreError::ServiceUnavailable(
            "down".to_string()
        )));
        assert!(!is_credential_rejection(&CoreError::Database(
            "timeout".to_string()
        )));
        assert!(!is_credential_rejection(&CoreError::SessionNotFound));
        assert!(!is_credential_rejection(&CoreError::SessionExpired));
        assert!(!is_credential_rejection(&CoreError::InvalidSession));
        assert!(!is_credential_rejection(&CoreError::InvalidRealm));
    }
}
