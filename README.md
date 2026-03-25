# 🛡️ Legit Flow — Secure LLM Gateway Lab

**Runtime Security Demo for LLM Traffic — Structured Data Minimization, Streaming Leak Interception, and Policy-Driven Enforcement**

Legit Flow is a reverse-proxy gateway that intercepts, inspects, and sanitizes traffic between enterprise applications and LLM endpoints. It demonstrates three core capabilities:

1. **Structured PII/secret minimization** before requests reach the LLM provider
2. **Streaming leak interception** for real-time output scanning with holdback window
3. **Auditable request/response decision trace** with 2-tier logging

> [!WARNING]
> **Trust Boundary:** When using an external L2 classifier (OpenAI, Anthropic, Gemini), the full prompt text is sent to the external API for classification. "Zero exfiltration" is only valid in regex-only mode or with a local/on-prem classifier. See [Trust Boundary Analysis](docs/trust-boundary.md).

## ✨ Feature Status

| Feature | Status | Notes |
|---------|--------|-------|
| **L1 PII/Secret Detection** | ✅ Working | Regex-based: VN CCCD, SĐT, email, bank accounts, JWT, API keys |
| **L2 Contextual Classifier** | ✅ Working | Pluggable API (OpenAI/Anthropic/Gemini/local) — ⚠️ external API breaks trust boundary |
| **Streaming Output Guard** | ✅ Working | Holdback window + per-chunk scan + truncate on restricted tier violation |
| **Policy Engine** | ✅ Working | YAML rules with detection-type matching, tier fallback, hot reload |
| **2-Tier Audit** | ✅ Working | Tier 1 metadata (always-on) + Tier 2 redacted content |
| **Tool/Action Guard** | 🔧 Integrated | RBAC + allowlist + approval workflow — wired into gateway with demo tools |
| **Break-Glass** | 🔧 Validation only | Struct + validation logic present; no runtime workflow yet |
| **Hardened K8s** | 🔧 Skeleton | Non-root, read-only FS, NetworkPolicy, seccomp — PVC template included, no mTLS |

### What This Is NOT (Yet)

- ❌ Not a production-grade security product
- ❌ No prompt injection detection (direct or indirect)
- ❌ No agent/tool chain abuse detection
- ❌ No semantic leakage analysis beyond regex patterns
- ❌ No benchmark for false positive/negative rates

## 🏰 Architecture

```
Enterprise App → [Gateway] → LLM Provider
                    │
           ┌────────┼────────┐
           │        │        │
        L1 Regex  Policy   Output
        L2 LLM   Engine   Guard
           │        │        │
         Detect  Evaluate  Scan
           │        │      Stream
           └────────┼────────┘
                    │
              Audit Logger
              (Tier1 + Tier2)
```

### Core Components

1. **Request Interceptor:** Terminates HTTP, extracts prompt, starts trace
2. **Detector Registry:**
   - **L1 (Regex):** Deterministic scanning for structured formats. Runs in < 2ms
   - **L2 (LLM-based):** Optional semantic scanning via external/local classifier
3. **Policy Engine:** Evaluates detections against YAML rules (detection_type match → tier fallback)
4. **Transformer:** Applies actions (tokenize/mask/block/redact/pseudonymize)
5. **Output Stream Guard:** Sliding window buffer for live output scanning
6. **Tool Guard:** RBAC allowlist for tool/action invocations (default deny)
7. **2-Tier Audit:** Always-on metadata (Tier 1) + redacted payloads (Tier 2)

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

### L2 External Classifier (Optional — breaks trust boundary)

```bash
# ⚠️ Prompt text will be sent to external API
export LEGIT_CLASSIFIER_PROVIDER=openai
export LEGIT_CLASSIFIER_API_KEY=sk-your-key-here
export LEGIT_CLASSIFIER_MODEL=gpt-4o-mini
go run ./cmd/gateway
```

### L2 Local Classifier (Preserves trust boundary)

```bash
export LEGIT_CLASSIFIER_PROVIDER=local
export LEGIT_CLASSIFIER_API_URL=http://localhost:8000/v1/chat/completions
export LEGIT_CLASSIFIER_MODEL=my-classifier-v1
go run ./cmd/gateway
```

## 📁 Project Structure

```
cmd/gateway/          → Gateway entry point
internal/
├── gateway/          → HTTP proxy + streaming + tool guard endpoint
├── detector/         → L1 regex + L2 API classifier
├── transformer/      → mask, pseudonymize, tokenize, block
├── outputguard/      → Streaming holdback + truncate
├── audit/            → 2-tier audit + break-glass validation
├── policy/           → Rule-level policy engine with hot reload
├── toolguard/        → Tool/Action RBAC access control
└── common/           → Config, logger, metrics
deploy/helm/          → Helm chart (security-aware K8s skeleton)
demo/                 → Enterprise chat UI + mock LLM
policies/             → Policy YAML files
docs/                 → Architecture, trust boundary, runbook
```

## 🧪 Testing

```bash
go test ./internal/... -v -race -cover     # Unit tests
go vet ./...                                # Static analysis
go build ./...                              # Build verification
helm lint deploy/helm/legit-flow            # Helm validation
```

## 📊 Metrics

Prometheus metrics at `:9090/metrics`:
- `legitflow_requests_total` — request count by method/path/status
- `legitflow_detections_total` — PII/secret detections by type/action
- `legitflow_output_guard_truncations_total` — stream truncations
- `legitflow_audit_events_total` — audit events by tier
- `legitflow_request_duration_seconds` — request latency histogram

## 📖 Documentation

- [Architecture](docs/architecture.md) — System flow + component details
- [Trust Boundary](docs/trust-boundary.md) — When data leaves the boundary
- [Demo Runbook](docs/demo-runbook.md) — Step-by-step demo guide

## 📜 License

Educational / Portfolio use — For evaluation purposes only.
