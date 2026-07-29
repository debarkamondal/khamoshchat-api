# Development & Deployment Guide

This guide provides instructions for setting up the Nijhum API development environment and deploying it to production.

---

## 🛠 Local Development Setup

### Prerequisites
*   **Rust**: Version 1.75 or higher (`rustup update`)
*   **Docker & Docker Compose**: For local Redis and RMQTT services
*   **AWS Account** (optional): Access to Amazon DynamoDB (or use DynamoDB Local)

### 1. Clone & Configure
```bash
git clone https://github.com/nijhum-in/nijhum-api.git
cd nijhum-api
cp .env.example .env
```

Edit `.env` to configure your local settings.

---

## 🐳 Docker / OCI Deployment

The Nijhum API is packaged as an OCI-compliant container image, distributed via the GitHub Container Registry.

### Running with Docker Compose
To spin up all supporting services (Redis, RMQTT):
```bash
docker-compose up -d
```

## 2. Running the Application

### Development Mode
```bash
# Public API and Private API start concurrently
cargo run
```

### Environment Variables
Ensure your `.env` file contains:
- `REDIS_URL`: URL for the Redis instance.
- `PRIMARY_TABLE`: Name of the DynamoDB table.
- `AWS_REGION`: e.g., `ap-south-1`.
- `GOOGLE_CLIENT_ID`: For OAuth token verification.
- `PUBLIC_API_PORT`: Default `3000`.
- `PRIVATE_API_PORT`: Default `3001`.

## 3. Testing

### Unit & Integration Tests
Run the test suite with:
```bash
cargo test
```
*Note: Some tests may require a local Redis instance or specific AWS credentials.*

### Validating Crypto Flows
The `src/crypto.rs` and `src/auth/` modules contain critical logic. Key functions to verify:
- `verify_signed_signature()`: Unified VXEdDSA + VRF verification used during registration (dual key verification for both pre-key and device key).
- `verify_signature()`: Raw VXEdDSA verification used in stateless auth (signature + VRF match against `userId + timestamp`).
Ensure any changes to these modules are accompanied by unit tests.

## 4. Deployment

The Nijhum API is packaged as an OCI-compliant container image, distributed via the GitHub Container Registry.

### Using the Container Image

#### Pulling the Image
```bash
docker pull ghcr.io/nijhum-in/nijhum-api:latest
```

#### Running the Container
Ensure your `.env` file is configured with the necessary AWS and Redis credentials before execution:

```bash
docker run -d \
  --name nijhum-api \
  -p 3000:3000 \
  -p 3001:3001 \
  --env-file .env \
  ghcr.io/nijhum-in/nijhum-api:latest
```

### Production Considerations
- **Network Isolation**: Port 3001 (Private API) must **not** be exposed to the internet. It is for internal backend services only (e.g., RMQTT webhooks). Use firewall rules or network policies to restrict access.
- **AWS Permissions**: Ensure the production environment has an IAM role with `dynamodb:PutItem`, `dynamodb:GetItem`, `dynamodb:UpdateItem`, `dynamodb:Query`, and `dynamodb:TransactWriteItems` permissions on the primary table.
- **Secrets**: Use a secret manager for Google Client secrets and AWS credentials.
- **RMQTT Hooks**: The API relies on RMQTT webhooks for handling message delivery states. Ensure the RMQTT configuration in `devenv/rmqtt/` is correctly mirrored in production.
