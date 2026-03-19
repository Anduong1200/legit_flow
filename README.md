# 🛡️ Legit Flow

**AI Security Data Plane for On-Premises Kubernetes**

Legit Flow intercepts, inspects, and sanitizes all traffic between enterprise applications and LLM/SLM endpoints — ensuring zero data exfiltration while preserving AI utility.

## ✨ Key Features

| Feature | Status | Description |
|---------|--------|-------------|
| **L1 PII/Secret Detection** | ✅ MVP | Regex-based: VN CCCD, SĐT, email, bank accounts, JWT, API keys |
| **L2 Contextual Classifier** | ✅ MVP | Pluggable API: OpenAI, Anthropic, or local ML endpoint |
| **Streaming Output Guard** | ✅ MVP | Holdback window + per-chunk scan + truncate on violation |
| **Policy-as-Code** | ✅ MVP | YAML rules, hot reload, versioned, tiered (restricted→public) |
| **2-Tier Audit** | ✅ MVP | Tier 1 metadata (always-on) + Tier 2 redacted content |
| **Break-Glass** | ✅ MVP | 2-person rule, ticket link, time-bound access |
| **Tool/Action Guard** | ✅ MVP | Allowlist, RBAC, approval workflow, default deny |
	| **Hardened K8s** | ✅ MVP | Non-root, read-only FS, NetworkPolicy, seccomp |

## 🏰 Technical Architecture

Legit Flow operates as a standard reverse proxy (API Gateway) intercepting HTTP requests between internal enterprise applications and external/internal LLM APIs (OpenAI, Anthropic, local vLLM). It is designed with modularity and low latency in mind.

### Core Components:
1. **Request Interceptor & Metrics Middleware:** Terminates the HTTP connection, extracts the prompt, and logs initial metrics.
2. **Detector Registry:**
   - **L1 Fast-path (Regex):** Deterministic scanning for clear formats (CCCD, Emails, Phone numbers, JWTs, API Keys). Runs in < 2ms.
   - **L2 Contextual (LLM-based):** Semantic scanning for complex requests using a fast classifier model (e.g., `gpt-4o-mini` or local tiny LLM).
3. **Policy-as-Code Engine:** Evaluates the detections against a YAML-defined policy array to determine the risk tier and the corresponding action (`allow`, `mask`, `block`).
4. **Output Stream Guard:** For streaming responses (`stream: true`), this component acts as a sliding window buffer holding back tokens temporarily to perform real-time scanning. If a violation is found mid-stream, it truncates the stream and shuts the connection.
5. **2-Tier Audit Logger:** Logs the metadata (Tier 1) for every request for observability and SIEM integration. Only authorized personnel can access the encrypted, pseudonymized payloads (Tier 2).

## 🚀 Quick Start

```bash
# 1. Start mock LLM
go run ./demo/llm-mock

# 2. Start gateway (new terminal)
go run ./cmd/gateway

# 3. Start demo app (new terminal)
go run ./demo/app

# 4. Open http://localhost:3000
```

### With External API Classifier (Optional)

```bash
export LEGIT_CLASSIFIER_PROVIDER=openai
export LEGIT_CLASSIFIER_API_KEY=sk-your-key-here
export LEGIT_CLASSIFIER_MODEL=gpt-4o-mini
go run ./cmd/gateway
```

Swap to local model later:
```bash
export LEGIT_CLASSIFIER_PROVIDER=local
export LEGIT_CLASSIFIER_API_URL=http://localhost:8000/v1/chat/completions
export LEGIT_CLASSIFIER_API_KEY=local-key
export LEGIT_CLASSIFIER_MODEL=my-classifier-v1
```

## 📁 Project Structure

```
cmd/gateway/          → Gateway entry point
internal/
├── gateway/          → HTTP proxy + streaming
├── detector/         → L1 regex + L2 API classifier
├── transformer/      → mask, pseudonymize, tokenize, block
├── outputguard/      → Streaming holdback + truncate
├── audit/            → 2-tier audit + break-glass
├── policy/           → Policy-as-code engine
├── toolguard/        → Tool/Action access control
└── common/           → Config, logger, metrics
deploy/helm/          → Helm chart (hardened K8s)
demo/                 → Demo app + mock LLM
policies/             → Policy YAML files
test/                 → E2E, perf (k6), security tests
```

## 🧪 Testing

```bash
# Unit tests
make test

# Lint
make lint

# Helm lint
make helm-lint

# Load test (requires k6)
k6 run test/perf/k6/load_test.js
```

## 📊 Metrics

Prometheus metrics at `:9090/metrics`:
- `legitflow_requests_total` — request count by method/path/status
- `legitflow_detections_total` — PII/secret detections by type/action
- `legitflow_output_guard_truncations_total` — stream truncations
- `legitflow_audit_events_total` — audit events by tier
- `legitflow_request_duration_seconds` — request latency histogram

## 📖 Documentation

- [Architecture](docs/architecture.md) — System flow chart + component details
- [Demo Runbook](docs/demo-runbook.md) — Step-by-step demo with pass/fail criteria
- [Roadmap](docs/roadmap.md) — 4-month Gantt chart (24/02 → 30/06/2026)

## 📜 License

Confidential — For evaluation purposes only.
