# Cryptographic Operations & Flows

This document details the exact cryptographic operations and verification flows used by the DeezChatz API. It serves as a technical reference for how the server handles keys, verifies signatures, and facilitates key exchange.

For a narrative explanation of these concepts (including *why* we use signature-based auth instead of JWTs), see the [Concepts Guide](concepts.md). For how these flows interact with the database and infrastructure, see the [Architecture Guide](architecture.md).

All signatures in DeezChatz use the **VXEdDSA** scheme, which produces both a cryptographic signature and a Verifiable Random Function (VRF) output.

---

## 1. Key Hierarchy

Before understanding the flows, it's important to know the keys involved. Each user's cryptographic identity consists of a chain of keys, rooted in a long-term Identity Key.

| Key | Type | Purpose |
| :--- | :--- | :--- |
| **Identity Key (`iKey`)** | Curve25519 (33 bytes) | Long-term identity; signs all other keys and state tokens |
| **Signed Pre-Key (`signedPreKey`)** | Curve25519 (33 bytes) | Medium-term key for X3DH; also used for API authentication |
| **Signed Device Key (`signedDeviceKey`)** | Curve25519 (33 bytes) | Per-device key signed by the Identity Key |
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

## 2. Registration: Triple-Key Verification

During device registration (`POST /register/device`), the client uploads its newly generated keys along with cryptographic proofs of possession. The server verifies **three** VXEdDSA signatures to ensure the client provably holds the private Identity Key:
1. `stateSignature` + `stateVrf` over the random `state` session token.
2. `preKeySign` + `preKeyVrf` over the `signedPreKey`.
3. `devKeySign` + `devKeyVrf` over the `signedDeviceKey`.

This happens after Phase 1 (OAuth), which is described in the [Concepts Guide](concepts.md#registration-flow).

### Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant R as Redis
    participant D as DynamoDB

    Note over C: 1. Generate keys locally:<br/>iKey, signedPreKey,<br/>signedDeviceKey, OPKs

    Note over C: 2. VXEdDSA sign state with iKey<br/>→ stateSignature (96 B) + stateVrf (32 B)
    Note over C: 3. VXEdDSA sign signedPreKey with iKey<br/>→ preKeySign (96 B) + preKeyVrf (32 B)
    Note over C: 4. VXEdDSA sign signedDeviceKey with iKey<br/>→ devKeySign (96 B) + devKeyVrf (32 B)

    C->>+S: POST /register/device<br/>{state, stateSignature, stateVrf, phone, signedPreKey,<br/>preKeySign, preKeyVrf, signedDeviceKey, devKeySign,<br/>devKeyVrf, opks, fcmToken}

    S->>R: Fetch pending registration (reg:pending:state)
    R-->>S: {userId, iKey, name, email, picture, createdAt}

    Note over S: Verify #1: stateSignature over state using iKey
    Note over S: Verify #2: preKeySign over signedPreKey using iKey
    Note over S: Verify #3: devKeySign over signedDeviceKey using iKey
    Note over S: (see flowchart below)

    S->>D: TransactWriteItems<br/>[Profile, Device, Email Pointer, Phone Pointer]
    D-->>S: Success

    S->>R: Delete pending registration key
    S-->>-C: {status: "success", userId, deviceId}
```

### Verification Flowchart

If any signature or VRF verification fails, the entire registration request is rejected.

```mermaid
flowchart TD
    A["Receive registration request with state token"] --> B["Fetch TempRegistration from Redis via state token"]
    B --> B1{"State token found?"}
    B1 -- No --> ERR0["❌ 404: Pending registration not found or expired"]
    B1 -- Yes --> C["Decode iKey, state, stateSignature, stateVrf"]
    C --> D{"vxeddsa_verify(<br/>iKey, state,<br/>stateSignature)"}
    D -- "None (invalid)" --> ERR1["❌ 401: Invalid signature for state"]
    D -- "Some(vrf₁)" --> E{"vrf₁ == stateVrf?"}
    E -- No --> ERR2["❌ 401: VRF mismatch for state"]
    E -- Yes --> F{"verify_signed_signature(<br/>iKey, signedPreKey,<br/>preKeySign, preKeyVrf)"}
    F -- Failed --> ERR3["❌ 401: Invalid signature/VRF for signedPreKey"]
    F -- OK --> G{"verify_signed_signature(<br/>iKey, signedDeviceKey,<br/>devKeySign, devKeyVrf)"}
    G -- Failed --> ERR4["❌ 401: Invalid signature/VRF for signedDeviceKey"]
    G -- OK --> H["✅ All proofs verified<br/>Proceed to DynamoDB TransactWriteItems"]

    style A fill:#3498db,color:#fff
    style H fill:#2ecc71,color:#fff
    style ERR0 fill:#e74c3c,color:#fff
    style ERR1 fill:#e74c3c,color:#fff
    style ERR2 fill:#e74c3c,color:#fff
    style ERR3 fill:#e74c3c,color:#fff
    style ERR4 fill:#e74c3c,color:#fff
```

### What Gets Stored

| Table Item | Fields Stored | Fields **NOT** Stored |
| :--- | :--- | :--- |
| **Profile** | `iKey`, `signedPreKey`, `signature` (preKeySign), `opks`, `deviceId`, `signedDeviceKey`, `fcmToken`, `phone`, `email`, `name`, `picture` | `stateVrf`, `preKeyVrf`, `devKeySign`, `devKeyVrf` |
| **Device** | `signedDeviceKey`, `fcmToken`, `createdAt`, `updatedAt` | VRF outputs |
| **Email Pointer** | `pk: EMAIL#{email}`, `sk: PTR`, `userId` | None |
| **Phone Pointer** | `pk: PHONE#{phone}`, `sk: PTR`, `userId` | None |

> VRF outputs are verified at registration time and discarded. They serve as cryptographic proofs-of-possession but are not stored post-verification.

---

## 3. Stateless Signature Authentication

Authenticated endpoints on the **Public API** (e.g., retrieving a pre-key bundle, syncing contact bundles, or updating an FCM token) use VXEdDSA signature authentication via Axum's `AuthenticatedUser` middleware extractor.

### Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server (Middleware)
    participant R as Redis
    participant D as DynamoDB
    participant H as Route Handler

    Note over C: Construct message payload:<br/>message = userId + timestamp

    Note over C: VXEdDSA sign message<br/>with signedPreKey<br/>→ signature (96 B) + vrf (32 B)

    C->>+S: Request with headers:<br/>X-User-Id · X-Timestamp<br/>X-Signature · X-Vrf

    Note over S: 1. Validate X-User-Id is UUID v4
    Note over S: 2. Validate timestamp drift<br/>(|now - ts| <= 10 sec)

    S->>D: Fetch Profile (pk: USER#userId, sk: PROFILE)
    D-->>S: Profile item (contains signedPreKey)

    Note over S: 3. Reconstruct payload: userId + timestamp
    Note over S: 4. vxeddsa_verify(signedPreKey, message, signature) → output_vrf
    Note over S: 5. Assert output_vrf == X-Vrf

    S->>R: SET replay:sig:<X-Signature> "1" NX EX 20
    alt Signature already exists in Redis
        R-->>S: false (Key exists)
        S-->>C: ❌ 401 Replay attack detected
    else Signature unique
        R-->>S: true (Key stored)
        S->>+H: Pass AuthenticatedUser to handler
        H-->>-C: ✅ 200 OK Response
    end
```

### Verification Flowchart

```mermaid
flowchart TD
    A["Incoming request with<br/>X-User-Id, X-Timestamp,<br/>X-Signature, X-Vrf"] --> B1{"X-User-Id is valid<br/>UUID v4?"}
    B1 -- No --> ERR0["❌ 401: Invalid user ID format"]
    B1 -- Yes --> B2{"Timestamp within<br/>±10 sec of server time?"}
    B2 -- No --> ERR1["❌ 401: Timestamp expired<br/>or too far in the future"]
    B2 -- Yes --> C["Fetch Profile from DynamoDB<br/>using USER#userId"]
    C --> D{"Profile found & has<br/>signedPreKey?"}
    D -- No --> ERR2["❌ 401: User not found"]
    D -- Yes --> E["Reconstruct message:<br/>userId + timestamp"]
    E --> F{"vxeddsa_verify(<br/>signedPreKey,<br/>message, signature)"}
    F -- "None (invalid)" --> ERR3["❌ 401: Invalid signature"]
    F -- "Some(output_vrf)" --> G{"output_vrf == X-Vrf?"}
    G -- No --> ERR4["❌ 401: VRF mismatch"]
    G -- Yes --> H{"Redis SET NX EX 20<br/>replay:sig:X-Signature"}
    H -- "Already Exists" --> ERR5["❌ 401: Replay attack detected"]
    H -- "Saved (New)" --> I["✅ Authenticated<br/>Proceed to handler"]

    style A fill:#3498db,color:#fff
    style I fill:#2ecc71,color:#fff
    style ERR0 fill:#e74c3c,color:#fff
    style ERR1 fill:#e74c3c,color:#fff
    style ERR2 fill:#e74c3c,color:#fff
    style ERR3 fill:#e74c3c,color:#fff
    style ERR4 fill:#e74c3c,color:#fff
    style ERR5 fill:#e74c3c,color:#fff
```

### Security Properties

| Property | Mechanism |
| :--- | :--- |
| **Strict Format Enforcement** | `X-User-Id` must parse as a valid UUID v4. |
| **Drift Window** | `X-Timestamp` must be within ±10 seconds of current server UTC time. |
| **Replay Protection** | Valid signatures are cached in Redis (`replay:sig:<sig>`) with a 20-second TTL (`SET NX EX 20`), which completely outlasts the ±10s drift window. Replays of identical signatures fail immediately. |
| **Identity Binding** | Signature is over `userId + timestamp`, cryptographically tying the request to the specified user identity. |
| **Key Binding** | Verified against the user's `signedPreKey` stored at registration. |
| **VRF Integrity** | VRF output must match, proving the signer possesses the private key corresponding to `signedPreKey`. |
| **Stateless** | No server sessions, cookies, or JWTs; every request is independently verifiable. |

---

## 4. X3DH Session Establishment

When one user wants to message another for the first time, they must perform an X3DH handshake. The server serves the recipient's pre-key bundle; the actual key exchange happens entirely client-side.

### Sequence

```mermaid
sequenceDiagram
    participant A as Alice (Initiator)
    participant S as Server
    participant D as DynamoDB
    participant B as Bob (Recipient)

    Note over B: Previously registered:<br/>iKey, signedPreKey,<br/>OPKs uploaded

    A->>+S: POST /bundle/{bob_id}<br/>with signature headers

    loop Retry up to 5 times on Conflict
        S->>D: Fetch Bob's Profile<br/>(iKey, signedPreKey, signature)
        D-->>S: Profile item

        Note over S: Select last OPK & its index

        S->>D: pop_opk(opks[last_index] == expected)<br/>(atomic conditional pop)
        
        alt Success
            Note over S: OPK popped successfully
        else Conflict (Concurrent pop)
            Note over S: Retry loop with exponential back-off (50ms, 100ms, 200ms, 400ms)
        end
    end

    S-->>-A: Pre-Key Bundle:<br/>{userId, deviceId, identityKey,<br/>signedPreKey, signature, phone, picture, opk}

    Note over A: Verify signature of<br/>signedPreKey using iKey

    Note over A: Perform X3DH locally:<br/>DH1 = DH(Alice_iKey, Bob_signedPreKey)<br/>DH2 = DH(Alice_ephemeral, Bob_iKey)<br/>DH3 = DH(Alice_ephemeral, Bob_signedPreKey)<br/>DH4 = DH(Alice_ephemeral, Bob_opk)

    Note over A: Derive shared secret<br/>SK = KDF(DH1 || DH2 || DH3 || DH4)

    A->>B: Send initial message<br/>(encrypted with SK)<br/>via MQTT topic

    Note over B: Perform matching X3DH<br/>Derive same SK locally
```

| Field | Source |
| :--- | :--- |
| `userId` | Profile item (`pk` stripped of `USER#` prefix) |
| `deviceId` | Profile item (`deviceId`) |
| `identityKey` | Profile item (`iKey`) |
| `signedPreKey` | Profile item (`signedPreKey`) |
| `signature` | Profile item (`signature` / VXEdDSA signature of `signedPreKey`) |
| `phone` | Profile item (`phone`, optional) |
| `picture` | Profile item (`picture`, optional) |
| `opk` | One OPK atomically popped from the `opks` array (omitted if exhausted) |

---

## 5. VXEdDSA Verification Functions

The server exposes internal verification helpers in `src/crypto.rs` to support these flows:

### `verify_signed_signature(iKey, target_key, signature, vrf, field_name)`

**Used during**: Registration (called for `signedPreKey` and `signedDeviceKey`)

1. Decodes all Base64 inputs and validates byte lengths (33-byte keys, 96-byte signatures, 32-byte VRF outputs).
2. Calls `vxeddsa_verify(iKey, target_key, signature)` from `libsignal-dezire`.
3. If verification succeeds, asserts the returned VRF matches the expected `vrf`.
4. Returns `Err(AppError::Unauthorized)` on signature failure or VRF mismatch.

### `verify_signature(public_key, message, signature)`

**Used during**: Stateless per-request authentication and `state` token verification in registration

1. Calls `vxeddsa_verify(public_key, message, signature)` from `libsignal-dezire`.
2. Returns the computed 32-byte VRF output on success.
3. The caller asserts that the returned VRF equals the expected VRF.
4. Returns `Err(AppError::Unauthorized)` on signature failure.
