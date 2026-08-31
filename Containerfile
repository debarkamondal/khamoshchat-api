# syntax=docker/dockerfile:1
# Build Stage
FROM rust:1.98.0-alpine3.24 AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git \
    cmake \
    make \
    perl

WORKDIR /app

# Copy dependency manifests and source files
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build with BuildKit cache mounts for cargo registry, git, and target artifacts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/deezchatz-api /app/deezchatz-api

# Runtime Stage
FROM alpine:3.24.1

# OCI metadata
LABEL org.opencontainers.image.source="https://github.com/deez-in/deezchatz-api"
LABEL org.opencontainers.image.description="DeezChatz API server"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    gcompat \
    libssl3

# Non-root user (UID/GID 1000 to match host rocky user for keep-id)
RUN addgroup -g 1000 rocky && adduser -u 1000 -G rocky -D rocky

WORKDIR /app

# Copy the binary from the builder stage with proper ownership
COPY --from=builder --chown=rocky:rocky /app/deezchatz-api /app/deezchatz-api

USER rocky

# Expose the API ports
EXPOSE 3000
EXPOSE 3001

# Run the application
CMD ["/app/deezchatz-api"]
