use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    db::{
        keys::device_sk,
        primary::{clear_device_fcm_token, get_item, put_offline_message},
    },
    push::{provider::PushError, WakeUpPayload},
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

        // Topic format: /nijhum/{recipientId}/{recipientDeviceId}/{senderId}/{senderDeviceId}
        // Split yields: ["", "nijhum", recipientId, recipientDeviceId, senderId, senderDeviceId]
        let parts: Vec<&str> = topic.split('/').collect();
        if parts.len() == 6 && parts[1] == "nijhum" {
            let recipient_id = parts[2];
            let recipient_device_id = parts[3];
            let sender_id = parts[4];
            let sender_device_id = parts[5];

            tracing::info!(
                "Offline message: recipient={}/{} sender={}/{}",
                recipient_id, recipient_device_id, sender_id, sender_device_id
            );

            let pk = format!("USER#{}", recipient_id);
            let sk = device_sk(recipient_device_id);

            // 1. Fetch recipient's device record to resolve push token
            match get_item(&state, &pk, &sk).await {
                Ok(Some(item)) => {
                    let device = crate::models::device::Device::from(item);

                    // 2. Dispatch data-only wake-up push (no ciphertext forwarded)
                    if let Some(push_token) = device.push_token() {
                        let wake_payload = WakeUpPayload {
                            sender_id: sender_id.to_string(),
                            sender_device_id: sender_device_id.to_string(),
                            topic: topic.clone(),
                        };

                        match state.push_provider.send(&push_token, &wake_payload).await {
                            Ok(()) => {
                                tracing::info!(
                                    "Push notification sent to recipient={}/{}",
                                    recipient_id, recipient_device_id
                                );
                            }
                            Err(PushError::TokenInvalid) => {
                                // Token is stale (app uninstalled / token rotated) — clean up DB
                                tracing::warn!(
                                    "Push token invalid for recipient={}/{}, clearing from DB",
                                    recipient_id, recipient_device_id
                                );
                                let _ = clear_device_fcm_token(&state, &pk, &sk).await;
                            }
                            Err(e) => {
                                tracing::error!("Failed to send push notification: {}", e);
                            }
                        }
                    } else {
                        tracing::warn!(
                            "No push token registered for recipient={}/{}",
                            recipient_id, recipient_device_id
                        );
                    }
                }
                Ok(None) => tracing::warn!(
                    "Device not found for offline message: recipient={}/{}",
                    recipient_id, recipient_device_id
                ),
                Err(e) => tracing::error!("Failed to fetch device: {:?}", e),
            }

            // 3. Persist offline message in DynamoDB for reliable retrieval on reconnect
            if let Err(e) = put_offline_message(
                &state,
                recipient_id,
                sender_id,
                sender_device_id,
                &topic,
                &msg_payload,
            )
            .await
            {
                tracing::error!("Failed to persist offline message: {:?}", e);
            }
        } else {
            tracing::warn!("Invalid topic format for offline message: {}", topic);
        }
    }

    // Always return 200 OK to acknowledge the webhook to RMQTT broker
    StatusCode::OK
}
