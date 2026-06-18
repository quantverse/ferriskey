use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use tracing::warn;

use crate::application::http::server::api_entities::api_error::ApiError;
use crate::args::SecurityArgs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaError {
    /// No token supplied but one is required.
    Missing,
    /// Token supplied but Cap rejected it.
    Invalid,
    /// Cap could not be reached / returned an unexpected response.
    Unavailable,
}

impl From<CaptchaError> for ApiError {
    fn from(err: CaptchaError) -> Self {
        match err {
            CaptchaError::Missing => ApiError::BadRequest("captcha token required".into()),
            CaptchaError::Invalid => ApiError::BadRequest("invalid captcha".into()),
            CaptchaError::Unavailable => {
                ApiError::ServiceUnavailable("captcha verification unavailable".into())
            }
        }
    }
}

#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    async fn verify(&self, token: Option<&str>) -> Result<(), CaptchaError>;
}

/// Used when `CAP_ENABLED=false`. Always succeeds.
pub struct NoopCaptchaVerifier;

#[async_trait]
impl CaptchaVerifier for NoopCaptchaVerifier {
    async fn verify(&self, _token: Option<&str>) -> Result<(), CaptchaError> {
        Ok(())
    }
}

#[derive(Serialize)]
struct SiteverifyBody<'a> {
    secret: &'a str,
    response: &'a str,
}

pub struct CapCaptchaVerifier {
    client: reqwest::Client,
    verify_url: String,
    site_key: String,
    secret: String,
    fail_open: bool,
}

impl CapCaptchaVerifier {
    pub fn new(verify_url: String, site_key: String, secret: String, fail_open: bool) -> Self {
        Self {
            client: reqwest::Client::new(),
            verify_url: verify_url.trim_end_matches('/').to_string(),
            site_key,
            secret,
            fail_open,
        }
    }

    /// `POST {verify_url}/{site_key}/siteverify`
    fn endpoint(&self) -> String {
        format!("{}/{}/siteverify", self.verify_url, self.site_key)
    }
}

#[async_trait]
impl CaptchaVerifier for CapCaptchaVerifier {
    async fn verify(&self, token: Option<&str>) -> Result<(), CaptchaError> {
        let token = match token {
            Some(t) if !t.is_empty() => t,
            _ => return Err(CaptchaError::Missing),
        };

        let body = SiteverifyBody { secret: &self.secret, response: token };

        let response = match self.client.post(self.endpoint()).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Cap siteverify request failed");
                return if self.fail_open { Ok(()) } else { Err(CaptchaError::Unavailable) };
            }
        };

        if !response.status().is_success() {
            warn!(status = %response.status(), "Cap siteverify non-success status");
            return if self.fail_open { Ok(()) } else { Err(CaptchaError::Unavailable) };
        }

        let parsed: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Cap siteverify body parse failed");
                return if self.fail_open { Ok(()) } else { Err(CaptchaError::Unavailable) };
            }
        };

        if parsed.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(CaptchaError::Invalid)
        }
    }
}

pub fn build_captcha_verifier(args: &SecurityArgs) -> Arc<dyn CaptchaVerifier> {
    if args.cap_enabled {
        Arc::new(CapCaptchaVerifier::new(
            args.cap_verify_url.clone(),
            args.cap_site_key.clone(),
            args.cap_secret.clone(),
            args.cap_fail_open,
        ))
    } else {
        Arc::new(NoopCaptchaVerifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_accepts_missing_token() {
        let v = NoopCaptchaVerifier;
        assert!(v.verify(None).await.is_ok());
    }

    #[tokio::test]
    async fn cap_missing_token_is_missing() {
        let v = CapCaptchaVerifier::new("http://127.0.0.1:1".into(), "sk".into(), "secret".into(), false);
        assert_eq!(v.verify(None).await, Err(CaptchaError::Missing));
        assert_eq!(v.verify(Some("")).await, Err(CaptchaError::Missing));
    }

    #[tokio::test]
    async fn cap_unreachable_fails_closed() {
        // Port 1 refuses connections -> Unavailable when fail_open=false.
        let v = CapCaptchaVerifier::new("http://127.0.0.1:1".into(), "sk".into(), "secret".into(), false);
        assert_eq!(v.verify(Some("tok")).await, Err(CaptchaError::Unavailable));
    }

    #[tokio::test]
    async fn cap_unreachable_fails_open_when_configured() {
        let v = CapCaptchaVerifier::new("http://127.0.0.1:1".into(), "sk".into(), "secret".into(), true);
        assert!(v.verify(Some("tok")).await.is_ok());
    }

    #[test]
    fn build_returns_noop_when_disabled() {
        let args = SecurityArgs::default();
        let _v = build_captcha_verifier(&args); // cap_enabled=false -> noop, must not panic
    }

    #[test]
    fn captcha_error_missing_maps_to_bad_request() {
        let api_err = ApiError::from(CaptchaError::Missing);
        assert!(matches!(api_err, ApiError::BadRequest(_)));
    }
}
