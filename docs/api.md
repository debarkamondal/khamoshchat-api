# API Reference

The KhamoshChat API is split into two distinct logical services running on separate ports.

- **Public API (Port 3000)**: Client-facing — registration, key discovery, and authenticated device management.
- **Private API (Port 3001)**: Internal only — **not exposed to clients**. Receives backend webhooks (e.g., RMQTT offline message notifications). Must be firewalled from external traffic.

---

## Authentication

### Open Endpoints (Public API)
Endpoints for registration do not require client authentication:
- `POST /register/google/id_token` — validated via Google's JWKS.
- `POST /register/device` — validated via VXEdDSA dual-key verification at the application level.

### Authenticated Endpoints (Public API)

Endpoints that operate on existing client data or perform key discovery require **Stateless Signature Authentication**. The middleware verifies the caller's identity before the request reaches the handler.
- Clients must include the following headers:
    - `X-User-Id`: The user's ID.
    - `X-Timestamp`: Current UTC timestamp in milliseconds.
    - `X-Signature`: A Base64 VXEdDSA signature of `userId + timestamp`.
    - `X-Vrf`: A Base64 VRF output corresponding to the signature.
- **Drift Tolerance**: The `X-Timestamp` must be within **±10 seconds** of the server's current UTC time.
- **Replay Protection**: Requests to `/register/device/fcm` are protected by a **10-second Redis-backed replay cache** that tracks signature uniqueness. Replayed requests are rejected with `401 Unauthorized`.
- **Applies to**:
    - `POST /bundle/{identifier}` — Key discovery (retrieves public key bundle).
    - `POST /register/device/fcm` — Updates the device FCM token.

### Internal Endpoints (Private API — Port 3001)
Private API endpoints have **no client-facing authentication**. They are intended to be called only by trusted backend services (e.g., RMQTT broker) and must be network-isolated from public traffic.

---

## 1. Registration Flow

### Verify Google ID Token
Verifies a Google OAuth token and creates a temporary registration session. If a user with the Google email already exists, their existing `userId` is returned so their pre-key bundle can be updated on re-registration.

- **Endpoint**: `POST /register/google/id_token`
- **Request Body**:
    ```json
    {
      "idToken": "string"
    }
    ```
- **Response**:
    ```json
    {
      "status": "success",
      "userId": "string (UUID)",
      "email": "string",
      "name": "string (optional)",
      "picture": "string (optional)"
    }
    ```

### Register Device & Keys
Finalizes registration (or re-registration) by uploading the device's cryptographic public keys. If `userId` belongs to an existing user profile, their identity keys and device records are updated in place in DynamoDB without creating duplicate user entries.

- **Endpoint**: `POST /register/device`
- **Request Body**:
    ```json
    {
      "userId": "string",
      "phone": "string",
      "iKey": "string (Base64 Identity Key)",
      "signedPreKey": "string (Base64 Signed Pre-Key)",
      "preKeySign": "string (VXEdDSA Signature of signedPreKey)",
      "preKeyVrf": "string (VRF output from signedPreKey signature)",
      "opks": ["string (One-Time Pre-Keys)"],
      "signedDeviceKey": "string (Base64 Signed Device Key)",
      "devKeySign": "string (VXEdDSA Signature of signedDeviceKey)",
      "devKeyVrf": "string (VRF output from signedDeviceKey signature)",
      "fcmToken": "string (Optional)"
    }
    ```
- **Response**:
    ```json
    {
      "status": "success",
      "userId": "string",
      "deviceId": "string"
    }
    ```
- **Verification**: The server performs VXEdDSA verification on **both** the signed pre-key and the signed device key. Each signature must produce a VRF output matching the provided `preKeyVrf` / `devKeyVrf`.

---

## 2. Key Discovery

### Get Pre-Key Bundle
Retrieves the cryptographic material required to start an E2EE session with a user.

- **Endpoint**: `POST /bundle/{identifier}`
- **Auth**: Requires Stateless Signature Authentication (`X-User-Id`, `X-Timestamp`, `X-Signature`, `X-Vrf` headers).
- **Description**: Fetches the profile and a single One-Time Pre-Key for the given user identifier (`user_id`, email, or phone).
- **Response**:
    ```json
    {
      "userId": "string",
      "deviceId": "string",
      "identityKey": "string (Base64 Identity Key)",
      "signedPreKey": "string (Base64 Signed Pre-Key)",
      "signature": "string (VXEdDSA Signature of signedPreKey)",
      "phone": "string (Phone number, optional)",
      "picture": "string (Profile picture URL, optional)",
      "opk": {
        "id": 0,
        "key": "string (One-Time Pre-Key)"
      }
    }
    ```
    *(Note: `phone`, `picture`, and `opk` are optional/nullable and may be null or skipped under certain conditions).*

### Get Sync Bundle
Retrieves read-only profile and identity key data for syncing a user.

- **Endpoint**: `GET /bundle/sync/{userId}`
- **Auth**: Requires Stateless Signature Authentication (`X-User-Id`, `X-Timestamp`, `X-Signature`, `X-Vrf` headers).
- **Description**: Fetches the user's public identity key and profile metadata without consuming a One-Time Pre-Key.
- **Response**:
    ```json
    {
      "userId": "uuid-string",
      "identityKey": "base64-encoded-public-identity-key",
      "picture": "https://...",
      "displayName": "John Doe"
    }
    ```
    *(Note: `picture` and `displayName` are nullable and may be returned as `null`.)*

---

## 3. Messaging

### MQTT Topic Schema

Messages are published directly to the MQTT broker by clients. The broker delivers them in real-time when the recipient is online, or stores them for offline delivery.

**Topic format:**
```
/nijhum/{recipient_id}/{recipient_device_id}/{sender_id}/{sender_device_id}
```

**Subscriber patterns (used by clients):**

| Pattern | Receives |
| :--- | :--- |
| `/nijhum/{recipient_id}/#` | All messages for that user across all devices |
| `/nijhum/{recipient_id}/{recipient_device_id}/#` | Messages targeting a specific device only |

**Message payload**: Opaque encrypted ciphertext. The server never inspects or decrypts it.

---

### MQTT Offline Message Webhook (Internal)
When a subscriber is offline, the MQTT broker fires a webhook to the private API to trigger a push notification.

- **Endpoint**: `POST /offline_message`
- **Port**: 3001 (Private — broker-to-server only, not client-facing)
- **Caller**: RMQTT broker (`rmqtt-web-hook` plugin)
- **Request Body** (broker-generated):
    ```json
    {
      "action": "offline_message",
      "from_node": 1001,
      "from_ipaddress": "127.0.0.1",
      "from_clientid": "string",
      "from_username": "string",
      "node": 1001,
      "ipaddress": "127.0.0.1",
      "clientid": "string",
      "username": "string",
      "dup": false,
      "retain": false,
      "qos": 1,
      "topic": "/nijhum/{recipient_id}/{recipient_device_id}/{sender_id}/{sender_device_id}",
      "packet_id": "string (optional)",
      "payload": "string (Encrypted ciphertext, base64)",
      "pts": 1234567890,
      "ts": 1234567890,
      "time": "string (ISO timestamp)"
    }
    ```
- **Behaviour**: Extracts `recipient_id` and `recipient_device_id` from the topic, looks up the device's `fcm_token`, and sends a data-only push notification. The ciphertext is **not** forwarded in the push.

---

## 4. Device Management (Authenticated)

### Update FCM Token
Updates the Firebase Cloud Messaging token for a specific device.

- **Endpoint**: `POST /register/device/fcm`
- **Port**: 3000 (Public API — client-facing)
- **Auth**: Requires Stateless Signature Authentication (`X-User-Id`, `X-Timestamp`, `X-Signature`, `X-Vrf` headers).
- **Request Body**:
    ```json
    {
      "deviceId": "string",
      "fcmToken": "string"
    }
    ```
- **Responses**:
    - `200 OK`: `{"status": "success", "message": "FCM token updated"}`
    - `401 Unauthorized`: If the signature is invalid, timestamp drift is >10 seconds, or a signature replay is detected.
    - `404 Not Found`: If the device is not registered (guarantees no ghost devices are created in DynamoDB).
