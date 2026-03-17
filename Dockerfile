# ── Stage 1: Build ─────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /bin/gateway ./cmd/gateway

# ── Stage 2: Runtime (distroless, non-root) ────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/gateway /gateway
COPY --from=builder /src/policies /policies

USER nonroot:nonroot

EXPOSE 8080 9090

ENTRYPOINT ["/gateway"]
