/// Integration tests for portal auth abuse controls (rate limiting, captcha,
/// brute-force throttle).
///
/// Run with:
///   cargo test -p ferriskey-api --test portal_security_test -- --ignored
///
/// Each test builds a minimal Axum router from the authentication sub-router
/// directly (bypassing `router()`) so the `axum-prometheus` process-global
/// metrics recorder is never installed. This is the same pattern used whenever
/// more than one server needs to be built in a single test binary.
#[cfg(test)]
mod tests {
    use std::{env, sync::Arc};

    use axum::Router;
    use axum_test::TestServer;
    use ferriskey_api::{
        application::http::{authentication::router::authentication_routes, server::app_state::AppState},
        args::Args,
    };
    use ferriskey_core::{
        application::create_service,
        domain::common::{
            DatabaseConfig, FerriskeyConfig, entities::StartupConfig, ports::CoreService,
        },
    };
    use sqlx::Executor;
    use uuid::Uuid;

    fn env_or(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }
    fn env_u16_or(key: &str, default: u16) -> u16 {
        env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    async fn make_server(mutate: impl FnOnce(&mut Args)) -> (TestServer, String) {
        let db_host = env_or("DATABASE_HOST", "localhost");
        let db_port = env_u16_or("DATABASE_PORT", 5432);
        let db_name = env_or("DATABASE_NAME", "ferriskey");
        let db_user = env_or("DATABASE_USER", "ferriskey");
        let db_password = env_or("DATABASE_PASSWORD", "ferriskey");

        let schema = format!("portal_sec_{}", Uuid::new_v4().simple());
        let admin_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_password, db_host, db_port, db_name
        );
        let admin_pool = sqlx::PgPool::connect(&admin_url).await.expect("admin pool");
        admin_pool
            .execute(sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{}\"", schema)))
            .await
            .expect("create schema");

        let schema_url = format!(
            "postgres://{}:{}@{}:{}/{}?options=-c search_path={}",
            db_user, db_password, db_host, db_port, db_name,
            urlencoding::encode(&schema)
        );
        let pool = sqlx::PgPool::connect(&schema_url).await.expect("schema pool");
        sqlx::migrate!("../core/migrations").run(&pool).await.expect("migrate");

        let service = create_service(FerriskeyConfig {
            database: DatabaseConfig {
                host: db_host, port: db_port,
                username: db_user, password: db_password,
                name: db_name, schema: schema.clone(),
            },
        })
        .await
        .expect("create service");

        let realm_name = format!("realm-{}", Uuid::new_v4().simple());
        service
            .initialize_application(StartupConfig {
                master_realm_name: realm_name.clone(),
                admin_username: "admin".to_string(),
                admin_password: "admin".to_string(),
                admin_email: "admin@test.local".to_string(),
                default_client_id: "admin-cli".to_string(),
            })
            .await
            .expect("init app");

        let mut args = Args::default();
        mutate(&mut args);
        let state = AppState::new(Arc::new(args), service);
        // Build a minimal router (authentication sub-router only) without the
        // Prometheus middleware. This avoids the process-global recorder panic
        // when more than one test in this binary calls `router()`.
        let app = Router::new()
            .merge(authentication_routes(state.clone(), ""))
            .layer(axum_cookie::prelude::CookieLayer::default())
            .with_state(state);
        let server = TestServer::new(app).expect("server");
        (server, realm_name)
    }

    #[tokio::test]
    #[ignore]
    async fn token_endpoint_rate_limited_after_burst() {
        let (server, realm_name) = make_server(|args| {
            args.security.rate_limit_enabled = true;
            args.security.auth_rate_limit_per_min = 1;
            args.security.auth_rate_limit_burst = 3;
            args.security.cap_enabled = false;
        })
        .await;

        let path = format!("/realms/{}/protocol/openid-connect/token", realm_name);
        let mut saw_429 = false;
        for _ in 0..10 {
            let resp = server
                .post(&path)
                .form(&[
                    ("grant_type", "password"),
                    ("client_id", "admin-cli"),
                    ("username", "admin"),
                    ("password", "wrong-on-purpose"),
                ])
                .await;
            if resp.status_code() == 429 {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "expected a 429 after exceeding the burst of 3");
    }

    #[tokio::test]
    #[ignore]
    async fn rate_limit_disabled_never_429() {
        let (server, realm_name) = make_server(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = false;
        })
        .await;

        let path = format!("/realms/{}/protocol/openid-connect/token", realm_name);
        for _ in 0..8 {
            let resp = server
                .post(&path)
                .form(&[
                    ("grant_type", "password"),
                    ("client_id", "admin-cli"),
                    ("username", "admin"),
                    ("password", "wrong-on-purpose"),
                ])
                .await;
            assert_ne!(resp.status_code(), 429, "rate limiting should be off");
        }
    }

    #[tokio::test]
    #[ignore]
    async fn authenticate_requires_captcha_when_enabled() {
        let (server, realm_name) = make_server(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = true;
            // Unreachable Cap + fail-closed: a *present* token yields 503, an
            // *absent* token yields 400 (Missing) before Cap is even contacted.
            args.security.cap_verify_url = "http://127.0.0.1:1".to_string();
            args.security.cap_site_key = "sk".to_string();
            args.security.cap_secret = "secret".to_string();
            args.security.cap_fail_open = false;
        })
        .await;

        // Send a random FERRISKEY_SESSION cookie so execution reaches the captcha
        // check (without a cookie the handler returns 401 before captcha runs).
        // The session UUID need not be valid because captcha is verified before
        // the session is used by the service.
        let session_cookie = format!("FERRISKEY_SESSION={}", Uuid::new_v4());
        let resp = server
            .post(&format!(
                "/realms/{}/login-actions/authenticate?client_id=admin-cli",
                realm_name
            ))
            .add_header("Cookie", session_cookie.as_str())
            .json(&serde_json::json!({ "username": "admin", "password": "admin" }))
            .await;

        assert_eq!(
            resp.status_code(),
            400,
            "missing captcha should be a 400, body: {}",
            resp.text()
        );
    }

    #[tokio::test]
    #[ignore]
    async fn brute_force_throttles_after_failures() {
        let (server, realm_name) = make_server(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = false;
            args.security.login_max_failures = 3;
            args.security.login_failure_window_secs = 300;
            args.security.login_throttle_secs = 300;
        })
        .await;

        let path = format!(
            "/realms/{}/login-actions/authenticate?client_id=admin-cli",
            realm_name
        );
        let session_cookie = format!("FERRISKEY_SESSION={}", Uuid::new_v4());
        let body = serde_json::json!({ "username": "admin", "password": "definitely-wrong" });

        let mut saw_429 = false;
        for _ in 0..6 {
            let resp = server
                .post(&path)
                .add_header("Cookie", session_cookie.as_str())
                .json(&body)
                .await;
            if resp.status_code() == 429 {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "expected 429 after repeated failed logins");
    }
}
