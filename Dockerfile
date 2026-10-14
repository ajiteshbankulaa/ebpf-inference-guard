
# syntax=docker/dockerfile:1

# Stage 1: Compile the Go application and eBPF program.
FROM golang:1.27.2-bookworm AS builder
# Packages needed by bpf2go and Clang.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        llvm \
        gcc \
        libbpf-dev \
        libelf-dev \
        linux-libc-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Download module dependencies before copying the
# entire project, allowing Docker build caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the application, ML-generated Go model,
# BPF source, and generator.
COPY . .

# Regenerate the eBPF object and Go bindings.
RUN go generate ./cmd/shield

# Build the actual cmd/shield package.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags="-s -w" \
    -o /out/shield ./cmd/shield

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags="-s -w" \
    -o /out/gateway ./cmd/gateway

# Stage 2: Small runtime environment.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder \
    /out/shield /usr/local/bin/shield
COPY --from=builder \
    /out/gateway /usr/local/bin/gateway

USER 0

ENTRYPOINT ["/usr/local/bin/shield"]
