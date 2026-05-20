# KhamoshChat API

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

KhamoshChat API is a high-performance, **Zero-Trust, End-to-End Encrypted (E2EE)** messaging backend built with Rust and Axum. It serves as the backbone for the KhamoshChat ecosystem, facilitating secure message routing and identity management without ever having access to users' private cryptographic keys.

## 🚀 Key Features

*   **Zero-Trust Architecture**: The server never sees plaintext messages or private keys.
*   **E2EE Messaging**: Full support for the Signal Protocol (X3DH) for establishing secure sessions.
*   **Identity Management**: Transitioned to a generic identity model supporting Individuals (OAuth/Google) and multiple Devices.
*   **Signature-Based Auth**: Stateless authentication using cryptographic signatures instead of traditional sessions or JWTs.
*   **Single-Table Design**: Optimized DynamoDB schema for high scalability and low latency.
*   **Push Notifications**: Integrated FCM support for reliable message delivery alerts.

## 🛠 Tech Stack

*   **Language**: [Rust](https://www.rust-lang.org/) (Axum framework)
*   **Database**: [Amazon DynamoDB](https://aws.amazon.com/dynamodb/) (Single-Table Design)
*   **Cache/Temp State**: [Redis](https://redis.io/)
*   **Messaging**: [RMQTT](https://rmqtt.io/) (MQTT Broker for real-time delivery)
*   **Infrastructure**: Docker, AWS SDK for Rust

## 🚦 Quick Start

### Prerequisites
*   Docker & Docker Compose
*   Rust (latest stable)
*   `devenv` (optional, for local development environment)

### Local Development Setup
1.  Clone the repository.
2.  Copy `.env.example` to `.env` and fill in your AWS and Google OAuth credentials.
3.  Start the supporting services:
    ```bash
    docker-compose up -d
    ```
4.  Run the API:
    ```bash
    cargo run
    ```

## 🐳 Deployment

The KhamoshChat API is distributed as a container image via the GitHub Container Registry (GHCR).

### Running with Docker
You can pull and run the latest production image:

```bash
docker pull ghcr.io/debarkamondal/khamoshchat-api:latest
docker run -p 3000:3000 -p 3001:3001 --env-file .env ghcr.io/debarkamondal/khamoshchat-api:latest
```

### Supported Architectures
Images are available for both `linux/amd64` and `linux/arm64`.

## 📖 Documentation

Detailed documentation is available in the `docs/` directory:

*   [**Architecture Guide**](docs/architecture.md): Deep dive into the security model, identity system, and database patterns.
*   [**Cryptographic Flows**](docs/cryptographic_flows.md): Detailed VXEdDSA verification, registration signatures, and stateless auth flows.
*   [**API Reference**](docs/api.md): Complete list of endpoints, request/response schemas, and authentication methods.
*   [**Development Guide**](docs/development.md): How to contribute, run tests, and deploy the application.

## 🔒 Security

KhamoshChat is designed with a security-first mindset. If you discover any security vulnerabilities, please refer to our [Security Policy](SECURITY.md) (coming soon).

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
