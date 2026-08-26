use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static TOPIC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^/deezchatz/(?P<rec_id>[^/]+)/(?P<rec_dev>[^/]+)/(?P<sen_id>[^/]+)/(?P<sen_dev>[^/]+)$",
    )
    .expect("static topic regex is valid")
});

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
        from_node: Option<i64>,
        from_ipaddress: Option<String>,
        from_clientid: Option<String>,
        from_username: Option<String>,
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
        from_node: Option<i64>,
        from_ipaddress: Option<String>,
        from_clientid: Option<String>,
        from_username: Option<String>,
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
        from_node: Option<i64>,
        from_ipaddress: Option<String>,
        from_clientid: Option<String>,
        from_username: Option<String>,
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
        from_node: Option<i64>,
        from_ipaddress: Option<String>,
        from_clientid: Option<String>,
        from_username: Option<String>,
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
        from_node: Option<i64>,
        from_ipaddress: Option<String>,
        from_clientid: Option<String>,
        from_username: Option<String>,
        node: Option<i64>,
        ipaddress: Option<String>,
        clientid: Option<String>,
        username: Option<String>,
        dup: Option<bool>,
        retain: Option<bool>,
        qos: Option<u8>,
        topic: String,
        packet_id: Option<serde_json::Value>,
        payload: String,
        pts: Option<i64>,
        ts: Option<i64>,
        time: Option<String>,
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

    if let WebhookPayload::OfflineMessage {
        topic,
        payload: msg_payload,
        ..
    } = payload
    {
        tracing::info!(topic = %topic, "Received offline message");

        if let Some(captures) = TOPIC_REGEX.captures(&topic) {
            let recipient_id = match captures.name("rec_id") {
                Some(m) => m.as_str(),
                None => return StatusCode::BAD_REQUEST,
            };
            let recipient_device_id = match captures.name("rec_dev") {
                Some(m) => m.as_str(),
                None => return StatusCode::BAD_REQUEST,
            };
            let sender_id = match captures.name("sen_id") {
                Some(m) => m.as_str(),
                None => return StatusCode::BAD_REQUEST,
            };
            let sender_device_id = match captures.name("sen_dev") {
                Some(m) => m.as_str(),
                None => return StatusCode::BAD_REQUEST,
            };

            tracing::info!(
                recipient_id = %recipient_id,
                recipient_device_id = %recipient_device_id,
                sender_id = %sender_id,
                sender_device_id = %sender_device_id,
                "Processing offline message"
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
                                    recipient_id = %recipient_id,
                                    recipient_device_id = %recipient_device_id,
                                    "Push notification sent successfully"
                                );
                            }
                            Err(PushError::TokenInvalid) => {
                                // Token is stale (app uninstalled / token rotated) — clean up DB
                                tracing::warn!(
                                    recipient_id = %recipient_id,
                                    recipient_device_id = %recipient_device_id,
                                    "Push token invalid, clearing from DB"
                                );
                                let _ = clear_device_fcm_token(&state, &pk, &sk).await;
                            }
                            Err(PushError::RateLimit) => {
                                tracing::warn!(
                                    recipient_id = %recipient_id,
                                    recipient_device_id = %recipient_device_id,
                                    "Push notification rate limited by provider"
                                );
                            }
                            Err(PushError::Internal(ref e)) => {
                                tracing::error!(
                                    recipient_id = %recipient_id,
                                    recipient_device_id = %recipient_device_id,
                                    error = %e,
                                    "Failed to send push notification"
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            recipient_id = %recipient_id,
                            recipient_device_id = %recipient_device_id,
                            "No push token registered for recipient"
                        );
                    }
                }
                Ok(None) => tracing::warn!(
                    recipient_id = %recipient_id,
                    recipient_device_id = %recipient_device_id,
                    "Device not found for offline message"
                ),
                Err(e) => tracing::error!(
                    recipient_id = %recipient_id,
                    recipient_device_id = %recipient_device_id,
                    error = ?e,
                    "Failed to fetch device"
                ),
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
                tracing::error!(
                    recipient_id = %recipient_id,
                    recipient_device_id = %recipient_device_id,
                    error = ?e,
                    "Failed to persist offline message"
                );
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        } else {
            tracing::warn!(topic = %topic, "Invalid topic format for offline message");
        }
    }

    // Always return 200 OK to acknowledge the webhook to RMQTT broker
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_regex_valid() {
        let topic = "/deezchatz/rec-user-1/rec-dev-1/sen-user-2/sen-dev-2";
        let caps = TOPIC_REGEX.captures(topic).expect("should match topic");
        assert_eq!(caps.name("rec_id").unwrap().as_str(), "rec-user-1");
        assert_eq!(caps.name("rec_dev").unwrap().as_str(), "rec-dev-1");
        assert_eq!(caps.name("sen_id").unwrap().as_str(), "sen-user-2");
        assert_eq!(caps.name("sen_dev").unwrap().as_str(), "sen-dev-2");
    }

    #[test]
    fn test_topic_regex_invalid() {
        let invalid_topics = [
            "/other/rec/dev/sen/dev",
            "/deezchatz/rec/dev",
            "/deezchatz/rec/dev/sen/dev/extra",
            "deezchatz/rec/dev/sen/dev",
        ];
        for topic in invalid_topics {
            assert!(
                TOPIC_REGEX.captures(topic).is_none(),
                "should not match {}",
                topic
            );
        }
    }
}
