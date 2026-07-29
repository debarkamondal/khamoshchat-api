mod auth;
mod crypto;
mod db;
mod error;
mod handlers;
mod models;
mod push;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use state::AppState;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialise tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info")),
        )
        .init();

    // Build shared state
    let state = AppState::new().await;

    // Build public router
    let public_router = Router::new()
        .route(
            "/bundle/{identifier}",
            post(handlers::public::bundle::get_bundle),
        )
        .route(
            "/bundle/sync/{userId}",
            get(handlers::public::bundle::get_sync_bundle),
        )
        .route(
            "/register/device",
            post(handlers::public::device::register_device),
        )
        .route(
            "/register/google/id_token",
            post(handlers::public::google_oauth::verify_id_token),
        )
        .route(
            "/register/device/fcm",
            post(handlers::public::device::update_fcm_token),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Build private router
    let private_router = Router::new()
        .route(
            "/offline_message",
            post(handlers::private::offline_message::handle_offline_message),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Ports
    let public_port = std::env::var("PUBLIC_API_PORT").unwrap_or_else(|_| "3000".to_string());
    let private_port = std::env::var("PRIVATE_API_PORT").unwrap_or_else(|_| "3001".to_string());

    let public_addr = format!("0.0.0.0:{}", public_port);
    let private_addr = format!("0.0.0.0:{}", private_port);

    // Listeners
    let public_listener = tokio::net::TcpListener::bind(&public_addr)
        .await
        .expect(&format!("Failed to bind to public port {}", public_port));

    let private_listener = tokio::net::TcpListener::bind(&private_addr)
        .await
        .expect(&format!("Failed to bind to private port {}", private_port));

    tracing::info!("Starting Nijhum public API on {}", public_addr);
    tracing::info!("Starting Nijhum private API on {}", private_addr);

    // Run both servers concurrently
    let public_server =
        axum::serve(public_listener, public_router).with_graceful_shutdown(shutdown_signal());
    let private_server =
        axum::serve(private_listener, private_router).with_graceful_shutdown(shutdown_signal());

    let _ = tokio::join!(public_server, private_server);

    tracing::info!("Nijhum API servers have stopped.");
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
