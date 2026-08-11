# API Reference

The DeezChatz API is split into two distinct logical services running on separate ports.

- **Public API (Port 3000)**: Client-facing — registration, key discovery, and authenticated device management.
- **Private API (Port 3001)**: Internal only — **not exposed to clients**. Receives backend webhooks (e.g., RMQTT offline message notifications). Must be firewalled from external traffic.

---

## Authentication

### Open Endpoints (Public API)
Endpoints for registration do not require signature authentication:
- `POST /register/google/id_token` — validated via Google's JWKS.
- `POST /register/device` — validated via VXEdDSA dual-key verification in the payload itself.

### Authenticated Endpoints (Public API)

Endpoints that operate on existing client data or perform key discovery require **Stateless Signature Authentication**. The middleware verifies the caller's identity before the request reaches the handler.

- **Required Headers**:
  - `X-User-Id`: The user's ID (UUID).
  - `X-Timestamp`: Current UTC timestamp in milliseconds.
  - `X-Signature`: A Base64 VXEdDSA signature of `userId + timestamp`.
  - `X-Vrf`: A Base64 VRF output corresponding to the signature.
- **Drift Tolerance**: The `X-Timestamp` must be within **±10 seconds** of the server's current UTC time.
- **Replay Protection**: Critical endpoints (like `POST /register/device/fcm`) are protected by a **10-second Redis-backed replay cache** that tracks signature uniqueness. Replayed requests are rejected with `401 Unauthorized`.

---

## 1. Registration Flow

### Verify Google ID Token
Verifies a Google OAuth token and creates a temporary registration session in Redis. If a user with the Google email already exists, their existing `userId` is returned.

- **Endpoint**: `POST /register/google/id_token`
- **Request Body**:
  ```json
  {
    "idToken": "string (JWT)"
  }
  ```
- **Example cURL**:
  ```bash
  curl -X POST http://localhost:3000/register/google/id_token \
       -H "Content-Type: application/json" \
       -d '{"idToken": "eyJhb..."}'
  ```
- **Responses**:
  - `200 OK`: 
    ```json
    {
      "status": "success",
      "userId": "uuid-string",
      "email": "user@gmail.com",
      "name": "User Name",
      "picture": "https://..."
    }
    ```
  - `400 Bad Request`: Missing token.
  - `401 Unauthorized`: Invalid or expired JWT, or wrong audience.
  - `500 Internal Server Error`: Could not fetch Google JWKS.

### Register Device & Keys
Finalizes registration (or re-registration) by uploading the device's cryptographic public keys.

- **Endpoint**: `POST /register/device`
- **Request Body**:
  ```json
  {
    "userId": "string",
    "phone": "string (optional)",
    "iKey": "string (Base64)",
    "signedPreKey": "string (Base64)",
    "preKeySign": "string (Base64 VXEdDSA Signature)",
    "preKeyVrf": "string (Base64 VRF output)",
    "opks": ["string (Base64)", "..."],
    "signedDeviceKey": "string (Base64)",
    "devKeySign": "string (Base64 VXEdDSA Signature)",
    "devKeyVrf": "string (Base64 VRF output)",
    "fcmToken": "string (optional)"
  }
  ```
- **Example cURL**:
  ```bash
  curl -X POST http://localhost:3000/register/device \
       -H "Content-Type: application/json" \
       -d '{"userId": "123", "iKey": "...", ...}'
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "status": "success",
      "userId": "uuid-string",
      "deviceId": "uuid-string"
    }
    ```
  - `401 Unauthorized`: VXEdDSA signature or VRF validation failed for either key.
  - `404 Not Found`: Pending registration expired or missing in Redis.
  - `500 Internal Server Error`: DynamoDB write failure.

---

## 2. Key Discovery

### Get Pre-Key Bundle
Retrieves the cryptographic material required to start an E2EE session with a user. This consumes one One-Time Pre-Key (OPK) from the recipient.

- **Endpoint**: `POST /bundle/{identifier}` (identifier can be `userId`, email, or phone)
- **Auth**: Requires Stateless Signature Authentication.
- **Example cURL**:
  ```bash
  curl -X POST http://localhost:3000/bundle/bob@example.com \
       -H "X-User-Id: alice-uuid" \
       -H "X-Timestamp: 1690000000000" \
       -H "X-Signature: base64-sig" \
       -H "X-Vrf: base64-vrf"
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "userId": "uuid-string",
      "deviceId": "uuid-string",
      "identityKey": "base64-string",
      "signedPreKey": "base64-string",
      "signature": "base64-string",
      "phone": "+1234567890",
      "picture": "https://...",
      "opk": {
        "id": 0,
        "key": "base64-string"
      }
    }
    ```
  - `401 Unauthorized`: Invalid caller signature.
  - `404 Not Found`: Target user not found, or they have no OPKs remaining.
  - `409 Conflict`: High concurrency prevented OPK extraction (client should retry).

### Get Sync Bundle
Retrieves read-only profile and identity key data for syncing a user, without consuming an OPK.

- **Endpoint**: `GET /bundle/sync/{userId}`
- **Auth**: Requires Stateless Signature Authentication.
- **Example cURL**:
  ```bash
  curl -X GET http://localhost:3000/bundle/sync/bob-uuid \
       -H "X-User-Id: alice-uuid" \
       -H "X-Timestamp: 1690000000000" \
       -H "X-Signature: base64-sig" \
       -H "X-Vrf: base64-vrf"
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "userId": "uuid-string",
      "identityKey": "base64-string",
      "picture": "https://...",
      "displayName": "John Doe"
    }
    ```
  - `401 Unauthorized`: Invalid caller signature.
  - `404 Not Found`: User not found.

---

## 3. Device Management (Authenticated)

### Update FCM Token
Updates the Firebase Cloud Messaging token for a specific device.

- **Endpoint**: `POST /register/device/fcm`
- **Auth**: Requires Stateless Signature Authentication.
- **Request Body**:
  ```json
  {
    "deviceId": "string",
    "fcmToken": "string"
  }
  ```
- **Example cURL**:
  ```bash
  curl -X POST http://localhost:3000/register/device/fcm \
       -H "X-User-Id: user-uuid" \
       -H "X-Timestamp: 1690000000000" \
       -H "X-Signature: base64-sig" \
       -H "X-Vrf: base64-vrf" \
       -H "Content-Type: application/json" \
       -d '{"deviceId": "dev-uuid", "fcmToken": "new-token-..."}'
  ```
- **Responses**:
  - `200 OK`: `{"status": "success", "message": "FCM token updated"}`
  - `401 Unauthorized`: Invalid signature, timestamp drift, or replay attack detected.
  - `404 Not Found`: Device not found in DynamoDB.

---

## 4. Internal API (Port 3001)

### MQTT Offline Message Webhook
Triggered by the RMQTT broker when a message arrives for an offline subscriber. Parses the topic to extract the recipient ID and sends a data-only FCM push notification to wake the device.

- **Endpoint**: `POST /offline_message`
- **Caller**: RMQTT broker (`rmqtt-web-hook` plugin)
- **Request Body** (truncated for clarity):
  ```json
  {
    "action": "offline_message",
    "topic": "/deezchatz/{recipient_id}/{recipient_device_id}/{sender_id}/{sender_device_id}",
    "payload": "base64-encrypted-ciphertext",
    ...
  }
  ```
- **Responses**:
  - `200 OK`: Push notification sent successfully, or no FCM token on file.
  - `400 Bad Request`: Malformed topic string.
  - `500 Internal Server Error`: FCM API failure or DynamoDB error.
