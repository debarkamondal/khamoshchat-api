# Development & Deployment Guide

This guide provides instructions for setting up the KhamoshChat API development environment and deploying it to production.

## 1. Local Development Setup

### Using `devenv`
The project includes a `devenv` configuration for a reproducible development environment.
1. Install [devenv](https://devenv.sh/).
2. Run `devenv shell` to enter the environment with all dependencies pre-installed.

### Manual Setup
If not using `devenv`, ensure you have:
- **Rust**: `1.75+`
- **Redis**: For temporary session storage.
- **RMQTT**: For real-time MQTT message routing.
- **DynamoDB**: The API currently connects to the AWS region specified in `.env`. To use a local DynamoDB, you must update the AWS SDK initialization in `src/db/mod.rs`.

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

The KhamoshChat API is packaged as an OCI-compliant container image, distributed via the GitHub Container Registry.

### Using the Container Image

#### Pulling the Image
```bash
docker pull ghcr.io/debarkamondal/khamoshchat-api:latest
```

#### Running the Container
Ensure your `.env` file is configured with the necessary AWS and Redis credentials before execution:

```bash
docker run -d \
  --name khamoshchat-api \
  -p 3000:3000 \
  -p 3001:3001 \
  --env-file .env \
  ghcr.io/debarkamondal/khamoshchat-api:latest
```

### Production Considerations
- **AWS Permissions**: Ensure the production environment has an IAM role with `dynamodb:PutItem`, `dynamodb:GetItem`, and `dynamodb:UpdateItem` permissions on the primary table.
- **Secrets**: Use a secret manager for Google Client secrets and AWS credentials.
- **RMQTT Hooks**: The API relies on RMQTT webhooks for handling message delivery states. Ensure the RMQTT configuration in `devenv/rmqtt/` is correctly mirrored in production.
