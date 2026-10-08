use axum::{Extension, extract::State, response::IntoResponse};
use axum_cookie::CookieManager;
use ferriskey_api_core::security::credential_failure::is_credential_rejection;
use ferriskey_api_core::{
    api_entities::{
        api_error::{ApiError, ApiErrorResponse, ValidateJson},
        response::Response,
    },
    app_state::AppState,
    sso_cookie,
    url::FullUrl,
};
use ferriskey_core::domain::authentication::value_objects::Identity;
use ferriskey_core::domain::trident::ports::{ChallengeOtpInput, TridentService};
use ferriskey_core::domain::user::entities::RequiredAction;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct ChallengeOtpRequest {
    #[validate(length(min = 6, max = 6, message = "OTP code must be exactly 6 digits"))]
    #[serde(default)]
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChallengeOtpResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub required_actions: Vec<RequiredAction>,
}

#[utoipa::path(
    post,
    path = "/login-actions/challenge-otp",
    tag = "auth",
    summary = "Challenge OTP for user authentication",
    description = "Challenges the user to provide a One-Time Password (OTP) for authentication. This is typically used in multi-factor authentication scenarios.",
    request_body = ChallengeOtpRequest,
    params(
        ("realm_name" = String, Path, description = "Name of the realm"),
    ),
    responses(
        (status = 200, description = "Successfully challenged OTP", body = ChallengeOtpResponse),
        (status = 400, description = "Invalid request payload", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid session cookie", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    )
)]
pub async fn challenge_otp(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    FullUrl(_, base_url): FullUrl,
    cookie: CookieManager,
    ValidateJson(payload): ValidateJson<ChallengeOtpRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let session_code = cookie
        .get("FERRISKEY_SESSION")
        .ok_or_else(|| ApiError::Unauthorized("Missing session cookie".into()))? // Ou un type d'erreur 401/403
        .value()
        .to_string();

    let bf_realm = Uuid::from(identity.realm_id()).to_string();
    let bf_key = format!("otp:{}", identity.id());

    if state.brute_force.check(&bf_realm, &bf_key) {
        return Err(ApiError::TooManyRequests {
            message: "too many incorrect codes, try again later".into(),
            retry_after_secs: state.args.security.login_throttle_secs,
        });
    }

    let result = match state
        .service
        .challenge_otp(
            identity,
            ChallengeOtpInput {
                code: payload.code,
                session_code,
            },
        )
        .await
    {
        Ok(result) => {
            state.brute_force.record_success(&bf_realm, &bf_key);
            result
        }
        Err(e) => {
            // Only an actual wrong code counts toward the per-account throttle;
            // infrastructure/session errors must not lock the account out.
            if is_credential_rejection(&e) {
                state.brute_force.record_failure(&bf_realm, &bf_key);
                // A wrong code is a bad request, not a failed authentication of the
                // login flow itself: this endpoint reserves 401 for a rejected flow
                // cookie, and a mistyped code must not read as "your flow died"
                // (see `a_failed_step_does_not_burn_the_token` in
                // api/tests/mfa_bypass_test.rs). Generic message — never echo the
                // internal error string back to the client.
                return Err(ApiError::BadRequest("invalid or expired code".into()));
            }
            // Everything else maps via From<CoreError> so it is not a blanket 500.
            return Err(e.into());
        }
    };

    let response = ChallengeOtpResponse {
        url: result.login_url,
        required_actions: result.required_actions,
    };

    Ok((
        sso_cookie::headers(result.sso_session, base_url.starts_with("https"))?,
        Response::OK(response),
    ))
}
