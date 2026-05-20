# API Reference

The KhamoshChat API is split into two distinct logical services, often running on different ports for security and routing purposes.

- **Public API (Port 3000)**: Registration, discovery, and public key retrieval.
- **Private API (Port 3001)**: Message routing and authenticated state updates.

---

## Authentication

### Public Endpoints
Endpoints under `/register` and `/bundle` are generally public, though some may require internal validation (like Google ID tokens).

### Private Endpoints
Private endpoints require **Stateless Signature Authentication**.
- Clients must include the following headers:
    - `X-User-Id`: The user's ID.
    - `X-Timestamp`: Current UTC timestamp in milliseconds.
    - `X-Signature`: A Base64 VXEdDSA signature of `userId + timestamp`.
    - `X-Vrf`: A Base64 VRF output corresponding to the signature.

---

## 1. Registration Flow

### Verify Google ID Token
Verifies a Google OAuth token and creates a temporary registration session.

- **Endpoint**: `POST /register/google/id_token`
- **Request Body**:
    ```json
    {
      "id_token": "string"
    }
    ```
- **Response**: Returns `user_id` and user profile info extracted from the token.

### Register Device & Keys
Finalizes registration by uploading the device's cryptographic public keys.

- **Endpoint**: `POST /register/device`
- **Request Body**:
    ```json
    {
      "user_id": "string",
      "phone": "string",
      "iKey": "string (Base64 Identity Key)",
      "signedPreKey": "string (Base64 Signed Pre-Key)",
      "preKeySign": "string (VXEdDSA Signature of signedPreKey)",
      "preKeyVrf": "string (VRF output from signedPreKey signature)",
      "opks": ["string (One-Time Pre-Keys)"],
      "device_id": "string",
      "signDevKey": "string (Base64 Signed Device Key)",
      "devKeySign": "string (VXEdDSA Signature of signDevKey)",
      "devKeyVrf": "string (VRF output from signDevKey signature)",
      "fcmToken": "string (Optional)"
    }
    ```
- **Verification**: The server performs VXEdDSA verification on **both** the signed pre-key and the signed device key. Each signature must produce a VRF output matching the provided `preKeyVrf` / `devKeyVrf`.

---

## 2. Key Discovery

### Get Pre-Key Bundle
Retrieves the cryptographic material required to start an E2EE session with a user.

- **Endpoint**: `POST /bundle/{identifier}`
- **Description**: Fetches the profile and a single One-Time Pre-Key for the given user identifier (`user_id` or phone).

---

## 3. Messaging

### MQTT Topic Schema

Messages are published directly to the MQTT broker by clients. The broker delivers them in real-time when the recipient is online, or stores them for offline delivery.

**Topic format:**
```
/khamoshchat/{recipient_id}/{recipient_device_id}/{sender_id}/{sender_device_id}
```

**Subscriber patterns (used by clients):**

| Pattern | Receives |
| :--- | :--- |
| `/khamoshchat/{recipient_id}/#` | All messages for that user across all devices |
| `/khamoshchat/{recipient_id}/{recipient_device_id}/#` | Messages targeting a specific device only |

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
      "topic": "/khamoshchat/{recipient_id}/{recipient_device_id}/{sender_id}/{sender_device_id}",
      "payload": "string (Encrypted ciphertext, base64)",
      "from_clientid": "string",
      "from_username": "string",
      "ts": 1234567890
    }
    ```
- **Behaviour**: Extracts `recipient_id` and `recipient_device_id` from the topic, looks up the device's `fcm_token`, and sends a data-only push notification. The ciphertext is **not** forwarded in the push.

---

## 4. Device Management

### Update FCM Token
Updates the Firebase Cloud Messaging token for a specific device.

- **Endpoint**: `POST /register/device/fcm`
- **Request Body**:
    ```json
    {
      "device_id": "string",
      "fcmToken": "string"
    }
    ```
