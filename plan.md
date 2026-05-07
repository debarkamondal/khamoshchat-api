# KhamoshChat Revamp Plan

## Objective
Revamp the KhamoshChat architecture to support a robust, multi-entity system centered around UUIDs rather than phone numbers.

## Phase 1: Immediate Action Items (Individuals via OAuth on Mobile)

1. **OAuth Verification & Identity Generation**
   - Update Google OAuth callback to explicitly capture `name`, `email`, and `picture`.
   - On successful Google token verification, generate a unique `userId` (UUID).
   - Store this initial verification state in a **Temporary DynamoDB Table** with a strict TTL.
   - Send the generated `userId` and profile info back to the mobile client for confirmation.

2. **Device Registration Finalization**
   - Implement the `/register/device` endpoint.
   - Accept the user's confirmation along with their `signedDeviceKey` (signed with the user's identity key) and device notification key.
   - Move the user's Profile (containing `iKey`, `signedPreKey`, signature, vrf) and initial Device data (containing `signedDeviceKey` and notification keys) from the Temporary Table to the **Primary DynamoDB Table**.

3. **Stateless Signature Authentication**
   - Implement a post-OAuth authentication middleware/check.
   - Require clients to sign a payload of `userId + timestamp` using their `signedPreKey`.
   - Backend validates the signature against the public key stored in DB and ensures the timestamp is recent to prevent replay attacks.

4. **Database & Index Migration**
   - Refactor DynamoDB queries to use `userId` instead of `phone` numbers.
   - Migrate offline messaging queues, MQTT routing, and all related systems to key off `userId` and `deviceId`.
   - Update `/bundle/<userId>` endpoint to fetch pre-keys using the new identifiers.

## Phase 2: Future Milestones

1. **Agents (Bots/Programs)**
   - Build a CLI tool for Agents to generate their own cryptographic identities.
   - Implement Agent registration and ACL (Access Control List) management by their owning Individual.
2. **Multi-Device Support**
   - Enable registering multiple `DEVICE#<deviceId>` records under a single `USER#<userId>`.
   - Implement device synchronization for messages and state.
3. **Phone Registration**
   - Implement standard SMS/Phone-based authentication flows.
4. **Perfect Forward Secrecy**
   - Implement an endpoint for clients to upload new OPKs (One-Time Pre-Keys) when depleted.
   - Update the bundle fetching logic to delete OPKs after a single use.
