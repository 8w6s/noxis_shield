# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install dependencies needed for CGO if we were to compile eBPF on Alpine, 
# but for now we rely on pre-compiled or userspace fallback.
RUN apk add --no-cache clang llvm make gcc musl-dev libbpf-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build Noxis Engine
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /noxis ./cmd/noxis

# Build NoxCtl
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /noxctl ./cmd/noxctl

# Final stage
FROM alpine:3.19

WORKDIR /app

# Copy binaries
COPY --from=builder /noxis /usr/local/bin/noxis
COPY --from=builder /noxctl /usr/local/bin/noxctl

# Copy configuration (Ensure this is mounted/overridden in prod)
COPY config/noxis.yaml /app/config/noxis.yaml

# Expose Proxy Port, Metrics, Dashboard, and Admin API
EXPOSE 8080 2112 9090 9091

ENTRYPOINT ["noxis"]
