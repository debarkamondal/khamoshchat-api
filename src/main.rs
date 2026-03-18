mod handlers;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use state::AppState;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialise tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Build shared state
    let state = AppState::new().await;

    // Build router
    let app = Router::new()
        // PreKeyBundle
        .route("/bundle/{phone}", post(handlers::bundle::get_bundle))
        .route("/register/phone", post(handlers::register::register_phone))
        .route("/register/phone/otp", post(handlers::register::verify_otp))
        .route("/register/google_oauth/init", post(handlers::google_oauth::google_oauth_init))
        .route(
            "/register/google_oauth/callback",
            get(handlers::google_oauth::google_oauth_callback),
        )
        .route(
            "/register/google_oauth/id_token",
            post(handlers::google_oauth::google_oauth_id_token),
        )
        .with_state(state);

    // Start server
    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to port 3000");

    tracing::info!("Starting KhamoshChat Auth API on {}", addr);

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("Server error: {}", e);
    }

    tracing::info!("KhamoshChat Auth API has stopped.");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        },
    }
}
