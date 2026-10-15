# © 2026 Affinity Ops Ltd. All rights reserved.
# Proprietary and confidential. Unauthorized copying or distribution prohibited.

# ─── Cicada Mesh Directory — Multi-stage Build ───────────────────
# Produces a ~15MB Alpine image with just the Go binary.
# This service runs on Affinity Ops infrastructure, NOT on customer servers.

FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mesh-directory .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /build/mesh-directory /usr/local/bin/mesh-directory
EXPOSE 9090
ENTRYPOINT ["mesh-directory"]
