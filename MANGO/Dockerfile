# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mango-shield .

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata iptables

WORKDIR /app

COPY --from=builder /app/mango-shield .
COPY --from=builder /app/config/default.yaml ./config/default.yaml

# Create directories
RUN mkdir -p /app/logs /app/certs /app/data

EXPOSE 443 80 9090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:9090/api/health || exit 1

ENTRYPOINT ["./mango-shield"]
CMD ["-config", "config/default.yaml"]
