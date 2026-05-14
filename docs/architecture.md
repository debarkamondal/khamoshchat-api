# Architecture & Design Guide

KhamoshChat is built on the principle of **Zero-Trust**. This document outlines how the system achieves security, scalability, and flexibility.

## 1. Security Model (Zero-Trust & E2EE)

The backend is strictly a **message router** and **identity registry**. It does not generate, store, or have access to:
- User private keys.
- Plaintext message content.
- Cryptographic session secrets.

### X3DH (Extended Triple Diffie-Hellman)
The system facilitates the X3DH protocol by acting as a repository for Pre-Key Bundles. 
1. Clients upload their **Identity Key (iKey)**, **Signed Pre-Key**, and **One-Time Pre-Keys (OPKs)**.
2. When Alice wants to message Bob, she fetches Bob's bundle from the server and initiates a session locally.
3. The server merely delivers the initial handshake and subsequent encrypted messages.

### Stateless Signature Authentication
Post-registration, clients authenticate using cryptographic signatures. 
- **Mechanism**: Every request to a private endpoint must include a signature of the payload (or a timestamped challenge) signed by the device's `signedPreKey`.
- **Benefit**: No sessions, no JWTs, and the server verifies identity using the same keys used for encryption.

## 2. Identity & Entity Model

The system has moved from a phone-number-centric model to a generic identity model.

1.  **Individuals (OAuth)**: Human users registered via OAuth providers (currently Google). This is the primary identity.
2.  **Devices**: Physical or virtual clients owned by Individuals. A single Individual can have multiple Devices (e.g., Phone, Desktop) that sync state.
3.  **Agents (Future)**: AI bots or programmatic scripts that operate with their own cryptographic identities but are owned by an Individual.

## 3. Data Modeling (DynamoDB Single-Table Design)

We use a single DynamoDB table to store all entities, utilizing the Partition Key (`pk`) and Sort Key (`sk`) to model relationships.

### Primary Table Patterns (`khamoshchat-identity`)

| Entity | Partition Key (`pk`) | Sort Key (`sk`) | Description |
| :--- | :--- | :--- | :--- |
| **Profile** | `USER#<userId>` | `PROFILE` | Basic info (name, email, iKey, signedPreKey). |
| **Device** | `USER#<userId>` | `DEVICE#<deviceId>` | Device-specific keys and FCM tokens. |
| **Lookup** | `LOOKUP#<phone>` | `PROFILE` | (GSI) Allows finding `userId` via phone number. |

### Temporary Storage (Redis)
Redis is used for short-lived state, primarily during the registration handoff:
- **Pending Registration**: Stores Google OAuth claims (`email`, `name`, `picture`) for 10 minutes while waiting for the client to complete Phase 2 (uploading crypto keys).

## 4. Registration Flow

The registration is a two-phase handshake to ensure identity verification precedes cryptographic setup.

### Phase 1: OAuth Verification
1. Client sends a Google `id_token` to `/register/google/id_token`.
2. Server verifies the token with Google's JWKS.
3. Server generates a `userId`, stores claims in Redis, and returns the `userId` to the client.

### Phase 2: Device & Key Setup
1. Client generates cryptographic keys locally.
2. Client sends `userId`, `iKey`, `signedPreKey`, and `signedDeviceKey` to `/register/device`.
3. Server validates the signature, retrieves claims from Redis, and commits the Profile and Device items to DynamoDB in a single transaction.

## 5. Messaging Layer (MQTT)

All messages are routed through the MQTT broker. The API server **never sees plaintext**; it only handles delivery bookkeeping.

### Topic Schema

```
/khamoshchat/{recipient_id}/{recipient_device_id}/{sender_id}/{sender_device_id}
```

All four IDs are embedded in the topic, making the routing information self-describing and avoiding any server-side lookup to determine delivery intent.

### Subscription Patterns

| Client subscribes to | Effect |
| :--- | :--- |
| `/khamoshchat/{recipient_id}/#` | Receives messages across all of the user's devices (multi-device sync) |
| `/khamoshchat/{recipient_id}/{recipient_device_id}/#` | Receives messages targeting only this specific device |

### Offline Delivery

When the recipient is offline, RMQTT stores the message (Redis-backed) and fires the `offline_message` webhook to the private API (port 3001). The handler:
1. Parses `recipient_id` and `recipient_device_id` from the topic.
2. Looks up the device's `fcm_token` in DynamoDB.
3. Sends a **data-only** push notification (no ciphertext) to wake the client.
4. The client reconnects via MQTT and retrieves the stored message from the broker.
