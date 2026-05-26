# KhamoshChat Architecture & Design

## System Entities
The system is built around four primary entities, transitioning away from a phone-number-first approach to a generic identity model.

1. **Individuals (OAuth):** Human users registered via OAuth providers (starting with Google).
2. **Individuals (Phone):** Human users registered via standard SMS verification (Future).
3. **Agents:** AI bots or programmatic scripts owned by Individuals, operating with their own cryptographic identities and restricted ACLs (Future).
4. **Devices:** Physical or virtual clients that hold cryptographic keys. Users and Agents can have multiple devices that sync state.

## Authentication & Security
* **Zero-Trust & E2EE:** The system is designed to facilitate end-to-end encryption. The backend stores public keys and routes messages, but does not generate client cryptographic keys.
* **Stateless Signature Auth:** Post-registration authentication does not rely on traditional sessions or JWTs. Instead, clients sign a payload (e.g., `userId + timestamp`) using their `signedPreKey`. The backend verifies this signature and the timestamp to authenticate the request and prevent replay attacks.

## Database Design (DynamoDB)
We utilize a Single-Table Design pattern to efficiently store and query the diverse entities.

* **Partition Key (`pk`):** Represents the core identity.
  * `USER#<userId>`
* **Sort Key (`sk`):** Represents the specific entity or sub-entity.
  * **Profile:** `sk: PROFILE` (Contains name, email, picture URL, `iKey`, `signedPreKey`, signature, and vrf).
  * **Device Data:** `sk: DEVICE#<deviceId>` (Contains `signedDeviceKey` and device notification keys).
  * **Agent Data:** `sk: AGENT#<agentId>` (Future).

### Temporary Storage
* A temporary DynamoDB table with TTL is used during the OAuth handoff phase. It temporarily holds the Google verification data before the client finalizes registration by providing their device cryptographic keys.

## Messaging & Cryptography
* **Protocol:** Utilizes the Signal Protocol (X3DH) for establishing secure sessions.
* **Pre-Key Bundles:** Clients upload their Identity Key, Signed Pre-Key, and a batch of One-Time Pre-Keys (OPKs).
* **Routing:** Messages are routed via offline queues (and MQTT for real-time delivery) using the destination `userId` and `deviceId`.
