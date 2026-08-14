# ==============================================================================
# WIDPS Backend - Multi-stage Rust Build
# ==============================================================================
# Stage 1: Build the Rust binary
# Stage 2: Minimal runtime with Python for ML inference
# ==============================================================================

# --- Build Stage ---
FROM rust:1.79-bookworm AS builder

WORKDIR /build

# Cache dependencies
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build actual source
COPY src/ src/
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iw \
    wireless-tools \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/widps /app/widps

# Setup Python ML environment
COPY ../ml/requirements.txt /app/ml/requirements.txt
RUN python3 -m venv /app/ml/.venv && \
    /app/ml/.venv/bin/pip install --no-cache-dir -r /app/ml/requirements.txt

# Copy ML scripts and model
COPY ../ml/ /app/ml/

# Create data directories
RUN mkdir -p /app/data/logs /app/data/honeypot_forensics /app/config

EXPOSE 8787

ENTRYPOINT ["/app/widps"]
