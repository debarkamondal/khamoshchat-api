# Cryptographic Flows

This document details the cryptographic operations and verification flows used by KhamoshChat. All signatures use the **VXEdDSA** scheme, which produces both a cryptographic signature and a Verifiable Random Function (VRF) output.

---

## 1. Key Hierarchy

Each user's cryptographic identity consists of:

| Key | Type | Purpose |
| :--- | :--- | :--- |
| **Identity Key (`iKey`)** | Curve25519 (33 bytes) | Long-term identity; signs all other keys |
| **Signed Pre-Key (`signedPreKey`)** | Curve25519 (33 bytes) | Medium-term key for X3DH; also used for API authentication |
| **Signed Device Key (`signDevKey`)** | Curve25519 (33 bytes) | Per-device key signed by the Identity Key |
| **One-Time Pre-Keys (`opks`)** | Curve25519 (33 bytes each) | Ephemeral keys consumed during X3DH handshake |

```mermaid
graph TD
    IK["🔑 Identity Key (iKey)
    Long-term · 33 bytes"]

    SPK["🔐 Signed Pre-Key
    Medium-term · 33 bytes"]

    SDK["📱 Signed Device Key
    Per-device · 33 bytes"]

    OPK1["🔓 OPK #1"]
    OPK2["🔓 OPK #2"]
    OPKN["🔓 OPK #N"]

    IK -- "VXEdDSA sign → preKeySign + preKeyVrf" --> SPK
    IK -- "VXEdDSA sign → devKeySign + devKeyVrf" --> SDK
    SPK -.- OPK1
    SPK -.- OPK2
    SPK -.- OPKN

    style IK fill:#4a90d9,color:#fff,stroke:#2a5f9e
    style SPK fill:#7b68ee,color:#fff,stroke:#5a4fcf
    style SDK fill:#e67e22,color:#fff,stroke:#c0601a
    style OPK1 fill:#2ecc71,color:#fff,stroke:#1fa855
    style OPK2 fill:#2ecc71,color:#fff,stroke:#1fa855
    style OPKN fill:#2ecc71,color:#fff,stroke:#1fa855
```

### Signature Outputs (VXEdDSA)

Every VXEdDSA signature operation over a message `m` with Identity Key `iKey` produces:

- **Signature** (96 bytes): The cryptographic proof.
- **VRF output** (32 bytes): A deterministic, verifiable random value unique to `(iKey, m)`.

---

## 2. Registration: Dual-Key Verification

During device registration (`POST /register/device`), the server verifies **two** VXEdDSA signatures to ensure the client provably holds the Identity Key.

### Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant R as Redis
    participant D as DynamoDB

    Note over C: Generate keys locally:<br/>iKey, signedPreKey,<br/>signDevKey, OPKs

    Note over C: VXEdDSA sign signedPreKey with iKey<br/>→ preKeySign (96 B) + preKeyVrf (32 B)
    Note over C: VXEdDSA sign signDevKey with iKey<br/>→ devKeySign (96 B) + devKeyVrf (32 B)

    C->>+S: POST /register/device<br/>{iKey, signedPreKey, preKeySign, preKeyVrf,<br/>signDevKey, devKeySign, devKeyVrf,<br/>device_id, phone, opks, fcmToken}

    S->>R: Fetch pending registration (userId)
    R-->>S: {name, email, picture}

    Note over S: Verify #1: preKeySign
    Note over S: Verify #2: devKeySign
    Note over S: (see flowchart below)

    S->>D: TransactWriteItems<br/>[Profile item, Device item]
    D-->>S: Success

    S->>R: Delete pending registration key

    S-->>-C: {status: "success", userId, deviceId}
```

### Verification Flowchart

```mermaid
flowchart TD
    A["Receive registration request"] --> B["Decode iKey, signedPreKey,<br/>preKeySign, preKeyVrf"]
    B --> C{"vxeddsa_verify(<br/>iKey, signedPreKey,<br/>preKeySign)"}
    C -- "None (invalid)" --> ERR1["❌ 401: Invalid signature<br/>for signedPreKey"]
    C -- "Some(vrf₁)" --> D{"vrf₁ == preKeyVrf?"}
    D -- No --> ERR2["❌ 401: VRF mismatch<br/>for signedPreKey"]
    D -- Yes --> E["Decode signDevKey,<br/>devKeySign, devKeyVrf"]
    E --> F{"vxeddsa_verify(<br/>iKey, signDevKey,<br/>devKeySign)"}
    F -- "None (invalid)" --> ERR3["❌ 401: Invalid signature<br/>for signedDeviceKey"]
    F -- "Some(vrf₂)" --> G{"vrf₂ == devKeyVrf?"}
    G -- No --> ERR4["❌ 401: VRF mismatch<br/>for signedDeviceKey"]
    G -- Yes --> H["✅ Both keys verified<br/>Proceed to DynamoDB write"]

    style A fill:#3498db,color:#fff
    style H fill:#2ecc71,color:#fff
    style ERR1 fill:#e74c3c,color:#fff
    style ERR2 fill:#e74c3c,color:#fff
    style ERR3 fill:#e74c3c,color:#fff
    style ERR4 fill:#e74c3c,color:#fff
```

### What Gets Stored

| Table Item | Fields Stored | Fields **NOT** Stored |
| :--- | :--- | :--- |
| **Profile** | `iKey`, `signedPreKey`, `signature` (preKeySign), `opks` | `preKeyVrf`, `devKeySign`, `devKeyVrf` |
| **Device** | `signedDeviceKey`, `fcmToken` | VRF outputs |

> VRF outputs are verified at registration time and discarded. They serve as proof-of-possession but are not needed post-verification.

---

## 3. Stateless Signature Authentication

Every request to a private endpoint (`port 3001`) is authenticated using VXEdDSA without sessions or tokens.

### Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant D as DynamoDB

    Note over C: Construct payload:<br/>message = userId + timestamp

    Note over C: VXEdDSA sign message<br/>with signedPreKey<br/>→ signature (96 B) + vrf (32 B)

    C->>+S: Request with headers:<br/>X-User-Id · X-Timestamp<br/>X-Signature · X-Vrf

    Note over S: 1. Validate timestamp<br/>(±5 min drift allowed)

    S->>D: Fetch Profile (signedPreKey)
    D-->>S: Profile item

    Note over S: 2. Reconstruct message:<br/>userId + timestamp

    Note over S: 3. vxeddsa_verify(<br/>signedPreKey, message,<br/>signature) → output_vrf

    Note over S: 4. Assert output_vrf<br/>== X-Vrf header

    S-->>-C: ✅ Authenticated / ❌ 401
```

### Verification Flowchart

```mermaid
flowchart TD
    A["Incoming request with<br/>X-User-Id, X-Timestamp,<br/>X-Signature, X-Vrf"] --> B{"Timestamp within<br/>±5 min of server time?"}
    B -- No --> ERR1["❌ 401: Timestamp expired<br/>or too far in the future"]
    B -- Yes --> C["Fetch Profile from DynamoDB<br/>using X-User-Id"]
    C --> D{"Profile found?"}
    D -- No --> ERR2["❌ 401: User not found"]
    D -- Yes --> E["Extract signedPreKey<br/>from Profile"]
    E --> F["Reconstruct message:<br/>userId + timestamp"]
    F --> G{"vxeddsa_verify(<br/>signedPreKey,<br/>message, signature)"}
    G -- "None (invalid)" --> ERR3["❌ 401: Invalid signature"]
    G -- "Some(output_vrf)" --> H{"output_vrf == X-Vrf?"}
    H -- No --> ERR4["❌ 401: VRF mismatch"]
    H -- Yes --> I["✅ Authenticated<br/>Proceed to handler"]

    style A fill:#3498db,color:#fff
    style I fill:#2ecc71,color:#fff
    style ERR1 fill:#e74c3c,color:#fff
    style ERR2 fill:#e74c3c,color:#fff
    style ERR3 fill:#e74c3c,color:#fff
    style ERR4 fill:#e74c3c,color:#fff
```

### Security Properties

| Property | Mechanism |
| :--- | :--- |
| **Replay protection** | Timestamp must be within ±5 minutes of server time |
| **Identity binding** | Signature is over `userId + timestamp`, tying the request to a specific user |
| **Key binding** | Verified against the user's `signedPreKey` stored at registration |
| **VRF integrity** | VRF output must match, proving the signer holds the private key corresponding to `signedPreKey` |
| **Stateless** | No sessions, cookies, or JWTs; every request is independently verifiable |

---

## 4. X3DH Session Establishment

The X3DH handshake is performed entirely client-side. The server's role is limited to storing and serving Pre-Key Bundles.

### Sequence

```mermaid
sequenceDiagram
    participant A as Alice (Initiator)
    participant S as Server
    participant D as DynamoDB
    participant B as Bob (Recipient)

    Note over B: Previously registered:<br/>iKey, signedPreKey,<br/>OPKs uploaded

    A->>+S: POST /bundle/{bob_id}

    S->>D: Fetch Bob's Profile<br/>(iKey, signedPreKey, signature)
    D-->>S: Profile item

    S->>D: Consume one OPK<br/>(remove from opks list)
    D-->>S: opk

    S-->>-A: Pre-Key Bundle:<br/>{iKey, signedPreKey,<br/>signature, opk}

    Note over A: Verify signature of<br/>signedPreKey using iKey

    Note over A: Perform X3DH locally:<br/>DH1 = DH(Alice_iKey, Bob_signedPreKey)<br/>DH2 = DH(Alice_ephemeral, Bob_iKey)<br/>DH3 = DH(Alice_ephemeral, Bob_signedPreKey)<br/>DH4 = DH(Alice_ephemeral, Bob_opk)

    Note over A: Derive shared secret<br/>SK = KDF(DH1 || DH2 || DH3 || DH4)

    A->>B: Send initial message<br/>(encrypted with SK)<br/>via MQTT topic

    Note over B: Perform matching X3DH<br/>Derive same SK locally
```

### Pre-Key Bundle Contents

| Field | Source |
| :--- | :--- |
| `iKey` | Profile item |
| `signedPreKey` | Profile item |
| `signature` | Profile item (VXEdDSA signature of `signedPreKey`) |
| `opk` | One OPK consumed from the `opks` list (removed after retrieval) |

The initiating client uses these to perform the X3DH key agreement locally. The server never participates in the key exchange computation.

---

## 5. VXEdDSA Verification Functions

The server exposes two internal verification functions in `src/crypto.rs`:

### `verify_signed_signature(iKey, target_key, signature, vrf, field_name)`

**Used during**: Registration (called twice — once for pre-key, once for device key)

1. Decodes all Base64 inputs and validates lengths.
2. Calls `vxeddsa_verify(iKey, target_key, signature)`.
3. If verification succeeds, asserts the returned VRF matches the expected `vrf`.
4. Returns `Err(Unauthorized)` on signature failure or VRF mismatch.

### `verify_signature(public_key, message, signature)`

**Used during**: Stateless authentication (per-request)

1. Calls `vxeddsa_verify(public_key, message, signature)`.
2. Returns the VRF output on success (caller checks the match against `X-Vrf`).
3. Returns `Err(Unauthorized)` on signature failure.

---

## 6. Message Encryption & Delivery

Messages exchanged over MQTT are **opaque ciphertext**. The server never inspects, decrypts, or validates message payloads.

### Delivery Flow

```mermaid
sequenceDiagram
    participant A as Sender
    participant M as RMQTT Broker
    participant S as Server (port 3001)
    participant F as Firebase (FCM)
    participant B as Recipient

    A->>M: Publish encrypted message to<br/>/khamoshchat/{recipient_id}/<br/>{recipient_device_id}/{sender_id}/{sender_device_id}

    alt Recipient is online
        M-->>B: Deliver message in real-time
    else Recipient is offline
        M->>M: Store message (Redis-backed)
        M->>S: POST /offline_message webhook<br/>{topic, from_clientid, ts}
        S->>S: Parse recipient_id and<br/>device_id from topic
        S->>S: Lookup fcm_token in DynamoDB
        S->>F: Send data-only push<br/>(no ciphertext included)
        F-->>B: Wake notification
        B->>M: Reconnect via MQTT
        M-->>B: Deliver stored message
    end
```
