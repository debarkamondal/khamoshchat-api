# Build Stage
FROM rust:1-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the project files
COPY . .

# Build the application
# We use --release to optimize the binary
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies (like libssl)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/khamoshchat-api /app/khamoshchat-api

# Expose the API port
EXPOSE 3000

# Run the application
CMD ["/app/khamoshchat-api"]
