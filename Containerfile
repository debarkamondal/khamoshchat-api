# Build Stage
FROM rust:1-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    pkg-config \
    git \
    cmake \
    make \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies - copy manifests first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release && rm -rf src

# Copy the real source and rebuild
COPY . .
RUN touch src/main.rs && cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

# OCI metadata
LABEL org.opencontainers.image.source="https://github.com/debarkamondal/khamoshchat-api"
LABEL org.opencontainers.image.description="KhamoshChat API server"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (UID/GID 1000 to match host rocky user for keep-id)
RUN groupadd --gid 1000 rocky && useradd --uid 1000 --gid 1000 --create-home rocky

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/khamoshchat-api /app/khamoshchat-api

RUN chown -R rocky:rocky /app
USER rocky

# Expose the API port
EXPOSE 3000

# Run the application
CMD ["/app/khamoshchat-api"]
