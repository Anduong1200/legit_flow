FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/llm-mock ./demo/llm-mock

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bin/llm-mock /llm-mock
USER nonroot:nonroot
EXPOSE 11434
ENTRYPOINT ["/llm-mock"]
