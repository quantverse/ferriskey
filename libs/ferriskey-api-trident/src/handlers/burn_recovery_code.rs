use axum::{
    Extension,
    extract::{Path, State},
    response::IntoResponse,
};
use axum_cookie::CookieManager;
use ferriskey_core::domain::{
    authentication::value_objects::Identity,
    trident::ports::{BurnRecoveryCodeInput, TridentService},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

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

#[derive(Debug, Serialize, Deserialize, ToSchema, Validate)]
pub struct BurnRecoveryCodeRequest {
    recovery_code: String,
    recovery_code_format: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct BurnRecoveryCodeResponse {
    login_url: String,
}

#[utoipa::path(
    post,
    path = "/login-actions/burn-recovery-code",
    tag = "auth",
    summary = "Burn a recovery code to authenticate",
    description = "Using a recovery code allows a user to bypass a MFA challenge",
    request_body = BurnRecoveryCodeRequest,
    params(
        ("realm_name" = String, Path, description = "Name of the realm"),
    ),
    responses(
        (status = 200, description = "Successfully burned recovery code", body = BurnRecoveryCodeResponse),
        (status = 400, description = "Invalid request payload", body = ApiErrorResponse),
        (status = 400, description = "Invalid recovery code", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid session cookie", body = ApiErrorResponse),
        (status = 401, description = "TOTP verification failed", body = ApiErrorResponse),
        (status = 403, description = "Identity not authorized", body = ApiErrorResponse),
        (status = 404, description = "Session not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    )
)]
pub async fn burn_recovery_code(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    FullUrl(_, base_url): FullUrl,
    cookie: CookieManager,
    ValidateJson(payload): ValidateJson<BurnRecoveryCodeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let session_code = cookie
        .get("FERRISKEY_SESSION")
        .ok_or_else(|| ApiError::Unauthorized("Missing session cookie".into()))? // Ou un type d'erreur 401/403
        .value()
        .to_string();

    let bf_realm = Uuid::from(identity.realm_id()).to_string();
    let bf_key = format!("recovery:{}", identity.id());

    if state.brute_force.check(&bf_realm, &bf_key) {
        return Err(ApiError::TooManyRequests {
            message: "too many incorrect codes, try again later".into(),
            retry_after_secs: state.args.security.login_throttle_secs,
        });
    }

    let result = match state
        .service
        .burn_recovery_code(
            identity,
            BurnRecoveryCodeInput {
                realm_name,
                session_code,
                format: payload.recovery_code_format,
                code: payload.recovery_code,
            },
        )
        .await
    {
        Ok(result) => {
            state.brute_force.record_success(&bf_realm, &bf_key);
            result
        }
        Err(e) => {
            // Only an actual wrong recovery code counts toward the per-account
            // throttle; infrastructure/session errors must not lock the account out.
            if is_credential_rejection(&e) {
                state.brute_force.record_failure(&bf_realm, &bf_key);
                // Same status contract as challenge_otp: 401 is reserved for a
                // rejected flow cookie, so a wrong code is a 400 with a generic
                // message rather than a 401 that reads as a dead login flow.
                return Err(ApiError::BadRequest("invalid or expired code".into()));
            }
            return Err(ApiError::from(e));
        }
    };

    Ok((
        sso_cookie::headers(Some(result.sso_session), base_url.starts_with("https"))?,
        Response::OK(BurnRecoveryCodeResponse {
            login_url: result.login_url,
        }),
    ))
}
