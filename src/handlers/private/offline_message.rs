use crate::state::AppState;
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SubscriptionOptions {
    pub qos: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WebhookPayload {
    SessionCreated {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        created_at: i64,
        time: String,
    },
    SessionTerminated {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        reason: String,
        time: String,
    },
    SessionSubscribed {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        topic: String,
        opts: SubscriptionOptions,
        time: String,
    },
    SessionUnsubscribed {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        topic: String,
        time: String,
    },
    ClientConnect {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        keepalive: i64,
        proto_ver: u8,
        clean_session: Option<bool>,
        clean_start: Option<bool>,
        time: String,
    },
    ClientConnack {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        keepalive: i64,
        proto_ver: u8,
        clean_session: Option<bool>,
        clean_start: Option<bool>,
        conn_ack: String,
        time: String,
    },
    ClientConnected {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        keepalive: i64,
        proto_ver: u8,
        clean_session: Option<bool>,
        clean_start: Option<bool>,
        connected_at: i64,
        session_present: bool,
        user_properties: Option<serde_json::Value>,
        time: String,
    },
    ClientDisconnected {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        disconnected_at: i64,
        reason: String,
        time: String,
    },
    ClientSubscribe {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        topic: String,
        opts: SubscriptionOptions,
        time: String,
    },
    ClientUnsubscribe {
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        topic: String,
        time: String,
    },
    MessagePublish {
        from_node: i64,
        from_ipaddress: String,
        from_clientid: String,
        from_username: String,
        dup: bool,
        retain: bool,
        qos: u8,
        topic: String,
        packet_id: Option<String>,
        payload: String,
        ts: i64,
        time: String,
    },
    MessageDelivered {
        from_node: i64,
        from_ipaddress: String,
        from_clientid: String,
        from_username: String,
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        dup: bool,
        retain: bool,
        qos: u8,
        topic: String,
        packet_id: Option<String>,
        payload: String,
        pts: i64,
        ts: i64,
        time: String,
    },
    MessageAcked {
        from_node: i64,
        from_ipaddress: String,
        from_clientid: String,
        from_username: String,
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        dup: bool,
        retain: bool,
        qos: u8,
        topic: String,
        packet_id: Option<String>,
        payload: String,
        pts: i64,
        ts: i64,
        time: String,
    },
    MessageDropped {
        from_node: i64,
        from_ipaddress: String,
        from_clientid: String,
        from_username: String,
        node: Option<i64>,
        ipaddress: Option<String>,
        clientid: Option<String>,
        username: Option<String>,
        dup: bool,
        retain: bool,
        qos: u8,
        topic: String,
        packet_id: Option<String>,
        payload: String,
        reason: String,
        pts: i64,
        ts: i64,
        time: String,
    },
    OfflineMessage {
        from_node: i64,
        from_ipaddress: String,
        from_clientid: String,
        from_username: String,
        node: i64,
        ipaddress: String,
        clientid: String,
        username: String,
        dup: bool,
        retain: bool,
        qos: u8,
        topic: String,
        packet_id: Option<String>,
        payload: String,
        pts: i64,
        ts: i64,
        time: String,
    },
    #[serde(other)]
    Unknown,
}

pub async fn handle_offline_message(
    State(_state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to deserialize webhook payload: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    match payload {
        WebhookPayload::OfflineMessage { .. } => {
            let json = serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| "Error serializing payload".to_string());
            tracing::warn!("OFFLINE MESSAGE RECEIVED:\n{}", json);
            // TODO: Store in DynamoDB
        }
        _ => {}
    }

    StatusCode::OK
}

fn decode_payload(payload: &str) -> String {
    match general_purpose::STANDARD.decode(payload) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => "Error: Invalid Base64".to_string(),
    }
}
