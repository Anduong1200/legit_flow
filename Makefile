.PHONY: all build test lint helm-lint docker run clean

APP_NAME    := legit-flow
VERSION     := 0.1.0-demo
GOFLAGS     := -trimpath -ldflags="-s -w -X main.version=$(VERSION)"
IMAGE       := legitflow/gateway:$(VERSION)
HELM_CHART  := deploy/helm/legit-flow

all: lint test build

# ── Build ──────────────────────────────────────────────
build:
	go build $(GOFLAGS) -o bin/gateway ./cmd/gateway

build-demo-app:
	go build $(GOFLAGS) -o bin/demo-app ./demo/app

build-llm-mock:
	go build $(GOFLAGS) -o bin/llm-mock ./demo/llm-mock

# ── Test ───────────────────────────────────────────────
test:
	go test ./internal/... -v -race -cover -coverprofile=coverage.out

test-e2e:
	go test ./test/e2e/... -v -tags=e2e

coverage: test
	go tool cover -html=coverage.out -o coverage.html

# ── Lint ───────────────────────────────────────────────
lint:
	golangci-lint run ./...

# ── Helm ───────────────────────────────────────────────
helm-lint:
	helm lint $(HELM_CHART)

helm-install:
	helm upgrade --install $(APP_NAME) $(HELM_CHART) -f $(HELM_CHART)/values-dev.yaml

helm-uninstall:
	helm uninstall $(APP_NAME)

# ── Docker ─────────────────────────────────────────────
docker:
	docker build -t $(IMAGE) .

docker-demo:
	docker build -t legitflow/demo-app:$(VERSION) -f demo/app/Dockerfile .
	docker build -t legitflow/llm-mock:$(VERSION) -f demo/llm-mock/Dockerfile .

# ── Run local ──────────────────────────────────────────
run:
	go run ./cmd/gateway

# ── Clean ──────────────────────────────────────────────
clean:
	rm -rf bin/ coverage.out coverage.html
