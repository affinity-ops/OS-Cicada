FROM golang:1.25-alpine AS builder

# CGO is required for go-sqlite3
RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /sandbox ./cmd/server

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM alpine:3.19

# Create a non-root user — the sandbox runs with minimal privileges
RUN addgroup -S sandbox && adduser -S sandbox -G sandbox

# Persistent volume for the SQLite database
RUN mkdir -p /data && chown sandbox:sandbox /data
VOLUME ["/data"]

COPY --from=builder /sandbox /usr/local/bin/sandbox

USER sandbox
EXPOSE 9090

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:9090/health || exit 1

ENTRYPOINT ["/usr/local/bin/sandbox"]
