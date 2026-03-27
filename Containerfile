# Build Stage
FROM rust:1-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git \
    cmake \
    make \
    perl

WORKDIR /app

# Cache dependencies - copy manifests first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release && rm -rf src

# Copy the real source and rebuild
COPY . .
RUN touch src/main.rs && cargo build --release

# Runtime Stage
FROM alpine:3

# OCI metadata
LABEL org.opencontainers.image.source="https://github.com/debarkamondal/khamoshchat-api"
LABEL org.opencontainers.image.description="KhamoshChat API server"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libssl3

# Non-root user
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/khamoshchat-api /app/khamoshchat-api

RUN chown -R app:app /app
USER app

# Expose the API port
EXPOSE 3000

# Run the application
CMD ["/app/khamoshchat-api"]
