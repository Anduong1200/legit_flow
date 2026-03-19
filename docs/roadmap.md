# Legit Flow — 4-Month Roadmap (24/02 → 30/06/2026)

```mermaid
gantt
    title Legit Flow MVP Roadmap
    dateFormat  YYYY-MM-DD
    axisFormat  %d/%m

    section WS1 Platform
    Helm/GitOps skeleton          :done,   ws1a, 2026-02-24, 3d
    Hardened profiles + mTLS      :        ws1b, 2026-03-03, 14d
    Observability (Prom/Grafana)  :        ws1c, 2026-03-17, 14d
    CI pipeline + container scan  :        ws1d, 2026-03-03, 7d
    Offline updates + signed rel  :        ws1e, 2026-05-01, 14d

    section WS2 Data Plane
    Intercept + route (REST)      :done,   ws2a, 2026-02-24, 3d
    Streaming SSE support         :        ws2b, 2026-03-03, 7d
    Auth JWT/SSO stub             :        ws2c, 2026-03-10, 7d
    Rate limit + backpressure     :        ws2d, 2026-03-17, 7d
    Circuit breaker + retry       :        ws2e, 2026-04-01, 7d

    section WS3 Detection
    L1 regex VN PII + secrets     :done,   ws3a, 2026-02-24, 3d
    L2 API classifier (pluggable) :done,   ws3b, 2026-02-24, 3d
    Utility transforms (MVP)      :        ws3c, 2026-03-03, 14d
    Synthetic replacement gen     :        ws3d, 2026-04-01, 21d
    L2 local SLM on-prem          :        ws3e, 2026-05-01, 30d

    section WS4 Output Guard
    Holdback window prototype     :done,   ws4a, 2026-02-24, 3d
    Chunk boundary handling       :        ws4b, 2026-03-03, 7d
    Regen under stricter policy   :        ws4c, 2026-04-01, 14d

    section WS5 Governance
    Policy-as-code + hot reload   :done,   ws5a, 2026-02-24, 3d
    Versioning + staged rollout   :        ws5b, 2026-03-10, 14d
    Audit 2-tier + break-glass    :        ws5c, 2026-03-10, 14d
    RBAC/ABAC + SoD               :        ws5d, 2026-04-01, 14d
    Approval UI (MVP)             :        ws5e, 2026-05-01, 21d

    section WS6 Tool Guard
    Allowlist + RBAC              :done,   ws6a, 2026-02-24, 3d
    Approval workflow             :        ws6b, 2026-04-01, 14d
    Injection negative tests      :        ws6c, 2026-04-15, 7d

    section WS7 QA/Testing
    Unit tests (core)             :done,   ws7a, 2026-02-24, 3d
    Integration tests             :        ws7b, 2026-03-17, 14d
    Performance (k6/locust)       :        ws7c, 2026-04-01, 14d
    Security scan pipeline        :        ws7d, 2026-04-15, 14d
    Dataset + eval reports        :        ws7e, 2026-05-01, 30d

    section Milestones
    Demo 3-day                    :milestone, m1, 2026-02-26, 0d
    Sprint review cadence starts  :milestone, m2, 2026-02-27, 0d
    MVP usable                    :milestone, m3, 2026-06-30, 0d
    Hardening + demo prep         :        h1, 2026-07-01, 45d
    Enterprise demo               :milestone, m4, 2026-08-15, 0d
```

## Workstream Owners (To Assign)

| WS | Focus | Suggested Owner |
|----|-------|-----------------|
| WS1 | Platform/DevOps | DevOps Lead |
| WS2 | Data Plane Core | Backend Lead |
| WS3 | Detection/Transform | Backend + ML |
| WS4 | Output Guard | Backend |
| WS5 | Governance/Audit | Backend + PM |
| WS6 | Tool Guard | Backend |
| WS7 | QA/Testing | QA + All |
