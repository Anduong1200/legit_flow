# Legit Flow — Architecture

## System Flow (Data Plane Pipeline)

```mermaid
flowchart LR
    A[App / User] -->|Request| B[Gateway Proxy]
    B -->|1. Intercept| C[L1 Regex Detector]
    C -->|structured PII/secrets| D{Policy Engine}
    B -.->|optional| E[L2 API Classifier]
    E -.->|contextual flags| D
    D -->|block| F[❌ Block Response]
    D -->|mask/pseudonymize| G[Transformer]
    D -->|allow| H[Router]
    G -->|sanitized| H
    H -->|forward| I[On-Prem LLM/SLM]
    I -->|response stream| J[Output Guard]
    J -->|holdback scan| K{Violation?}
    K -->|no| L[✅ Safe Response]
    K -->|yes| M[⚠️ Truncate + Safe Message]
    
    B -->|always| N[Audit Tier 1 - Metadata]
    G -->|if transformed| O[Audit Tier 2 - Redacted]
```

## Component Descriptions

| Component | Package | Purpose |
|-----------|---------|---------|
| **Gateway Proxy** | `internal/gateway` | HTTP reverse proxy with streaming (SSE/chunked) support |
| **L1 Regex Detector** | `internal/detector` | Fast-path regex for VN PII (CCCD, SĐT, email, STK) + secrets (JWT, API keys) |
| **L2 API Classifier** | `internal/detector` | Pluggable LLM API (OpenAI/Anthropic/local) for contextual classification |
| **Policy Engine** | `internal/policy` | YAML-based policy-as-code with hot reload and versioning |
| **Transformer** | `internal/transformer` | Mask, pseudonymize, tokenize, block, or redact detected entities |
| **Output Guard** | `internal/outputguard` | Streaming holdback window — buffers N tokens, scans, truncates on violation |
| **Audit Logger** | `internal/audit` | 2-tier: Tier 1 metadata (always-on) + Tier 2 redacted content. Break-glass workflow. |
| **Tool Guard** | `internal/toolguard` | Allowlist + RBAC + approval for AI agent tool/action calls |

## Security Posture (Hardened-by-Default)

- **Non-root** container (UID 65534)
- **Read-only** root filesystem
- **Drop ALL** capabilities
- **Seccomp** RuntimeDefault profile
- **NetworkPolicy** deny-by-default
- **mTLS** ready (cert-manager hook)
- **No secrets in code** — all from K8s Secrets / env
