FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/demo-app ./demo/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bin/demo-app /demo-app
USER nonroot:nonroot
EXPOSE 3000
ENTRYPOINT ["/demo-app"]
