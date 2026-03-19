# Legit Flow — Demo Runbook

## Prerequisites

- Go 1.22+
- Docker (for container builds)
- kind or k3s (for Kubernetes demo)
- Helm 3.14+ (optional, for K8s deployment)

## Quick Start (Local, No K8s)

### 1. Start Mock LLM
```bash
go run ./demo/llm-mock
# → 🤖 Mock LLM running at http://localhost:11434
```

### 2. Start Gateway
```bash
# Terminal 2
go run ./cmd/gateway
# → 🛡️ Legit Flow Gateway
#   ├── Proxy:   :8080 → http://localhost:11434
#   ├── Metrics: :9090/metrics
#   └── Policy:  default-hardened (1.0.0)
```

### 3. Start Demo App
```bash
# Terminal 3
go run ./demo/app
# → 🖥️ Demo app running at http://localhost:3000
```

### 4. Open Demo UI
Navigate to **http://localhost:3000** and use the scenario buttons.

---

## Demo Scenarios & Pass/Fail Criteria

### Scenario 1: VN PII Detection (CCCD + SĐT)
**Input:** `Khách hàng CCCD 001234567890, SĐT 0912345678`
- ✅ **Pass:** CCCD is blocked (Restricted tier); SĐT is masked (Confidential)
- ❌ **Fail:** Raw CCCD appears in response or UI

### Scenario 2: Secret Detection (API Key)
**Input:** `API key: sk-abc123def456ghi789jkl012mno345pqr678`
- ✅ **Pass:** API key is blocked; response shows `[BLOCKED]`
- ❌ **Fail:** Raw `sk-*` key appears in output

### Scenario 3: JWT Token
**Input:** `Token: eyJhbGci...`
- ✅ **Pass:** JWT blocked by policy
- ❌ **Fail:** JWT token visible in response

### Scenario 4: Clean Text (No Detection)
**Input:** `Hôm nay thời tiết đẹp.`
- ✅ **Pass:** Request passes through unchanged; low latency
- ❌ **Fail:** False positive detection or gateway error

### Scenario 5: Streaming Output Guard
**Test:** Mock LLM injects PII in streaming response
- ✅ **Pass:** Stream truncated with safe message; no raw PII leaked
- ❌ **Fail:** PII appears in streamed output

---

## Verify Audit Logs

```bash
# Tier 1 (metadata)
cat audit-logs/tier1_$(date +%Y-%m-%d).jsonl | jq .

# Tier 2 (redacted content)
cat audit-logs/tier2_$(date +%Y-%m-%d).jsonl | jq .
```

**Check:** Tier 1 has `event_id`, `user_id`, `action`, `outcome` but NO raw PII values.
**Check:** Tier 2 has redacted/pseudonymized values only.

## Policy Hot Reload

```bash
# Edit policy
vim policies/default-policy.yaml

# Trigger reload
curl -X POST http://localhost:8080/api/v1/policy/reload
# → {"status":"reloaded"}
```

## Metrics

```bash
curl http://localhost:9090/metrics | grep legitflow
# → legitflow_requests_total
# → legitflow_detections_total
# → legitflow_output_guard_truncations_total
# → legitflow_audit_events_total
```
