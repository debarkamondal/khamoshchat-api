# Nijhum API

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Arch-amd64%20%7C%20arm64-lightgrey)]()

The backend server for the [Nijhum](https://github.com/nijhum-in) encrypted messaging ecosystem. Built with Rust and Axum, it operates as a **Zero-Trust** infrastructure — the server routes messages, manages identities, and serves key bundles, but **never sees plaintext messages or private keys**.

## Where This Fits

```mermaid
graph TD
    subgraph "Client"
        MOBILE["Nijhum Mobile"]
    end

    subgraph "Native Modules"
        OAUTH["expo-google-native-oauth"]
        CRYPTO["expo-libsignal-dezire"]
    end

    subgraph "Backend"
        API["⭐ Nijhum API (this server)"]
        REDIS["Redis"]
        RMQTT["RMQTT Broker"]
        DYNAMO["DynamoDB"]
    end

    subgraph "Core Crypto"
        LIB["libsignal-dezire"]
    end

    MOBILE -->|"idToken"| OAUTH
    OAUTH -.->|"POST /register/google/id_token"| API
    MOBILE -->|"crypto keys"| CRYPTO
    CRYPTO --> LIB
    MOBILE -->|"REST + MQTT"| API
    API --> REDIS
    API --> DYNAMO
    API -->|"cargo dep"| LIB
    RMQTT -->|"webhook"| API
    MOBILE <-->|"encrypted messages"| RMQTT
```

## What This Server Does

The Nijhum API has **three roles**:

1. **Identity Registry** — Verifies Google OAuth tokens, creates user profiles, and stores cryptographic public keys in DynamoDB. It never generates keys — clients do that locally.

2. **Pre-Key Bundle Server** — When Alice wants to message Bob, she asks the server for Bob's public key bundle. The server hands it over. Alice then performs the X3DH key exchange locally — the server is not involved in the computation.

3. **Offline Push Gateway** — When a message arrives via MQTT but the recipient is offline, the RMQTT broker fires a webhook to the API. The API looks up the recipient's FCM token and sends a data-only push notification to wake the device (no message content is included in the push).

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Language** | [Rust](https://www.rust-lang.org/) (Axum framework) |
| **Database** | [Amazon DynamoDB](https://aws.amazon.com/dynamodb/) (Single-Table Design) |
| **Cache** | [Redis](https://redis.io/) (pending registrations, replay protection) |
| **Message Broker** | [RMQTT](https://rmqtt.io/) (MQTT broker for real-time delivery) |
| **Crypto** | [libsignal-dezire](https://github.com/nijhum-in/libsignal-dezire) (VXEdDSA verification) |
| **Push** | Firebase Cloud Messaging (FCM) |
| **Container** | OCI-compliant image via GitHub Container Registry |

---

## Quick Start

### Prerequisites

- **Rust** 1.75+ (`rustup update`)
- **Docker & Docker Compose** (for Redis and RMQTT)
- **AWS credentials** (for DynamoDB — or use DynamoDB Local)

### Local Development

```bash
# 1. Clone
git clone https://github.com/nijhum-in/nijhum-api.git
cd nijhum-api

# 2. Configure environment
cp .env.example .env
# Edit .env with your AWS, Google OAuth, and Redis credentials

# 3. Start supporting services
docker-compose up -d   # Starts Redis + RMQTT

# 4. Run the API
cargo run
# Public API starts on port 3000
# Private API starts on port 3001
```

### Running with Docker

```bash
docker pull ghcr.io/nijhum-in/nijhum-api:latest
docker run -p 3000:3000 -p 3001:3001 --env-file .env ghcr.io/nijhum-in/nijhum-api:latest
```

Images are available for both `linux/amd64` and `linux/arm64`.

---

## Documentation

Start with the concepts guide, then explore the detailed docs:

| Document | What it covers |
|----------|---------------|
| [**Concepts Guide**](docs/concepts.md) | Start here — Zero-Trust philosophy, identity model, registration and messaging flows explained narratively |
| [**Architecture Guide**](docs/architecture.md) | System architecture — DynamoDB schema, MQTT topic design, infrastructure, environment variables |
| [**Cryptographic Flows**](docs/cryptographic_flows.md) | Detailed Mermaid diagrams of VXEdDSA verification, registration, auth, and X3DH flows |
| [**API Reference**](docs/api.md) | Complete endpoint documentation with request/response schemas and cURL examples |
| [**Development Guide**](docs/development.md) | Local setup, project structure, testing, and deployment |

---

## Security

Nijhum is designed with a security-first mindset. The server operates on a Zero-Trust model:

- **No plaintext access** — Messages are opaque ciphertext; the server never decrypts them.
- **No private keys** — All key generation happens on the client. The server only stores public keys.
- **Signature-based auth** — No JWTs or sessions. Every authenticated request is verified with VXEdDSA signatures.
- **VRF integrity** — Registration and auth both verify VRF outputs, proving the signer holds the private key.

If you discover security vulnerabilities, please refer to our [Security Policy](SECURITY.md) (coming soon).

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
