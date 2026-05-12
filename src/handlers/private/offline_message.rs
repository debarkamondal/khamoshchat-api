use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    db::{keys::device_sk, primary::get_item},
    push::fcm::send_push,
    state::AppState,
};

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
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to deserialize webhook payload: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    if let WebhookPayload::OfflineMessage { topic, payload: msg_payload, .. } = payload {
        tracing::info!("Received offline message for topic: {}", topic);

        // Extract user_id and device_id from topic (format: "[prefix/...]userId/deviceId")
        let parts: Vec<&str> = topic.split('/').collect();
        let len = parts.len();
        if len >= 2 {
            let user_id = parts[len - 2];
            let device_id = parts[len - 1];

            // 1. Fetch recipient's device to get FCM token
            let pk = format!("USER#{}", user_id);
            let sk = device_sk(device_id);
            
            match get_item(&state, &pk, &sk).await {
                Ok(Some(item)) => {
                    let device = crate::models::device::Device::from(item);
                    if let Some(fcm_token) = device.fcm_token {
                        // 2. Dispatch Push Notification
                        // Create a dummy payload for the push
                        let push_payload = serde_json::json!({
                            "type": "offline_message",
                            "topic": topic,
                            // don't send the full ciphertext in push, just a wake-up
                        });
                        
                        let _ = send_push(&fcm_token, &push_payload).await.map_err(|e| {
                            tracing::error!("Failed to send push notification: {:?}", e);
                        });
                    } else {
                        tracing::warn!("Device found but no FCM token present: {}/{}", user_id, device_id);
                    }
                }
                Ok(None) => tracing::warn!("Device not found for offline message: {}/{}", user_id, device_id),
                Err(e) => tracing::error!("Failed to fetch device: {:?}", e),
            }

            // 3. Store offline message in DynamoDB (Stubbed)
            store_offline_message_stub(&topic, &msg_payload);
        } else {
            tracing::warn!("Invalid topic format for offline message: {}", topic);
        }
    }

    // Always return OK to acknowledge webhook
    StatusCode::OK
}

fn store_offline_message_stub(topic: &str, _payload: &str) {
    tracing::info!("STUB: Storing offline message for topic: {}", topic);
    // Real persistence logic goes here in a future milestone.
}
