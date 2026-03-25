# Trust Boundary Analysis

## Data Flow Modes

Legit Flow operates in three distinct trust boundary configurations:

### Mode 1: Regex-Only (Full Trust Boundary)

```
┌─────────────── Trust Boundary ───────────────┐
│                                               │
│  App  →  Gateway  →  L1 Regex  →  LLM API    │
│                    (no data leaves boundary)  │
│                                               │
└───────────────────────────────────────────────┘
```

- **L2 classifier**: disabled (`LEGIT_CLASSIFIER_PROVIDER=disabled`)
- **Data stays within**: gateway process
- **"Zero exfiltration" claim**: ✅ valid
- **Trade-off**: no semantic/contextual detection

### Mode 2: External API Classifier (Broken Trust Boundary)

```
┌─────────── Trust Boundary ──────────┐
│                                      │
│  App  →  Gateway  →  L1 Regex       │
│                    ↓                 │
│              ┌─────────────────┐    │
│              │ L2 Classifier   │────┼──→  OpenAI / Anthropic / Gemini
│              │ (sends full     │    │      (raw text leaves boundary)
│              │  prompt text)   │    │
│              └─────────────────┘    │
│                    ↓                 │
│              Transform → LLM API    │
└──────────────────────────────────────┘
```

- **L2 classifier**: enabled with external provider
- **Data that leaves boundary**: full prompt text sent to classifier API
- **"Zero exfiltration" claim**: ❌ **NOT valid**
- **Risk**: the very data you're trying to protect (PII/secrets) is sent to an external LLM for classification

### Mode 3: Local/On-Prem Classifier (Full Trust Boundary)

```
┌─────────── Trust Boundary ──────────┐
│                                      │
│  App  →  Gateway  →  L1 Regex       │
│                    ↓                 │
│              L2 Classifier           │
│              (local model,           │
│               on-prem vLLM)          │
│                    ↓                 │
│              Transform → LLM API    │
│                                      │
└──────────────────────────────────────┘
```

- **L2 classifier**: enabled with local endpoint
- **Data stays within**: on-prem infrastructure
- **"Zero exfiltration" claim**: ✅ valid (if LLM API is also on-prem)

## Provider Visibility Matrix

| Component | Provider Sees | Gateway Sees | Audit Stores |
|-----------|:-------------|:-------------|:-------------|
| L1 Regex | nothing | raw text | Tier1: metadata only |
| L2 External | **full prompt** | raw text + L2 result | Tier1: metadata |
| L2 Local | nothing (same infra) | raw text + L2 result | Tier1: metadata |
| LLM Backend | **sanitized text** | raw + sanitized | Tier2: sanitized |
| Output Guard | nothing | response text | truncation events |

## Recommendations

1. **Default to regex-only** unless semantic detection is required
2. **Document clearly** when L2 external is enabled — inform data owners
3. **Prefer local classifiers** for sensitive environments
4. **Never claim "zero exfiltration"** when using external L2 classifier
