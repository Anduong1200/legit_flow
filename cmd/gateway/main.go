// Legit Flow — Secure LLM Gateway Lab
// Entry point for the gateway service.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/legitflow/legitflow/internal/audit"
	"github.com/legitflow/legitflow/internal/common"
	"github.com/legitflow/legitflow/internal/detector"
	"github.com/legitflow/legitflow/internal/gateway"
	"github.com/legitflow/legitflow/internal/policy"
	"github.com/legitflow/legitflow/internal/toolguard"
)

var version = "dev"

func main() {
	// ── Config ──────────────────────────────────────────────
	cfg := common.DefaultConfig()
	logger := common.NewLogger("info")

	logger.Info("starting legit-flow gateway",
		"version", version,
		"listen", cfg.ListenAddr,
		"backend", cfg.LLMBackendURL,
		"classifier", cfg.ClassifierProvider,
	)

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}

	// ── Detector Registry ───────────────────────────────────
	reg := detector.NewRegistry()

	// L1: always-on regex detectors (fast path, no data leaves trust boundary)
	reg.Register(detector.NewL1RegexDetector())

	// L2: contextual classifier (API-based, pluggable)
	// ⚠️ TRUST BOUNDARY WARNING: When using external API providers (openai, anthropic, gemini),
	// the full prompt text is sent to the external API for classification.
	// This means data leaves the trust boundary. For true zero-exfiltration,
	// use regex-only mode (LEGIT_CLASSIFIER_PROVIDER=disabled) or a local classifier.
	if apiKey := os.Getenv("GEMINI_API_KEY"); apiKey != "" {
		if l2 := detector.NewL2LLMDetector(apiKey); l2 != nil {
			reg.Register(l2)
			logger.Info("L2 Contextual LLM Detector enabled (gemini-1.5-flash via genai-go)")
			logger.Warn("⚠️  L2 detector sends text to external API — data leaves trust boundary")
		}
	} else if cfg.ClassifierProvider != "disabled" {
		l2 := detector.NewL2ContextualDetector(detector.L2Config{
			Provider: cfg.ClassifierProvider,
			APIURL:   cfg.ClassifierAPIURL,
			APIKey:   cfg.ClassifierAPIKey,
			Model:    cfg.ClassifierModel,
		})
		reg.Register(l2)
		logger.Info("L2 contextual detector enabled",
			"provider", cfg.ClassifierProvider,
			"model", cfg.ClassifierModel,
		)
		logger.Warn("⚠️  L2 detector sends text to external API — data leaves trust boundary")
	} else {
		logger.Info("L2 contextual detector disabled (regex-only mode — full trust boundary)")
	}

	// ── Policy Engine ───────────────────────────────────────
	eng, err := policy.NewEngine(cfg.PolicyDir, logger)
	if err != nil {
		logger.Error("policy engine init failed", "error", err)
		os.Exit(1)
	}
	p := eng.GetPolicy()
	logger.Info("policy engine ready",
		"policy", p.Name,
		"version", p.Version,
		"rules", len(p.Rules),
	)

	// ── Tool Guard ──────────────────────────────────────────
	// Default deny: no tools allowed unless explicitly configured.
	// In production, load from policy YAML or dedicated tool config.
	defaultTools := []toolguard.ToolEndpoint{
		{
			Name:          "customer_lookup",
			Endpoint:      "/api/tools/customer_lookup",
			AllowedRoles:  []string{"admin", "support"},
			Permission:    toolguard.PermRead,
			NeedsApproval: false,
			Description:   "Look up customer by ID",
		},
		{
			Name:          "send_email",
			Endpoint:      "/api/tools/send_email",
			AllowedRoles:  []string{"admin"},
			Permission:    toolguard.PermExecute,
			NeedsApproval: true,
			Description:   "Send email on behalf of user",
		},
		{
			Name:          "export_csv",
			Endpoint:      "/api/tools/export_csv",
			AllowedRoles:  []string{"admin"},
			Permission:    toolguard.PermWrite,
			NeedsApproval: true,
			Description:   "Export data as CSV file",
		},
	}
	tg := toolguard.NewGuard(defaultTools)
	logger.Info("tool guard ready", "tools", len(defaultTools))

	// ── Audit Logger ────────────────────────────────────────
	auditor, err := audit.NewLogger(cfg, logger)
	if err != nil {
		logger.Error("audit logger init failed", "error", err)
		os.Exit(1)
	}

	// ── Gateway Server ──────────────────────────────────────
	srv, err := gateway.NewServer(cfg, logger, reg, eng, auditor, tg)
	if err != nil {
		logger.Error("server init failed", "error", err)
		os.Exit(1)
	}

	handler := gateway.RequestMetricsMiddleware(srv, logger)

	// ── Metrics Server ──────────────────────────────────────
	metrics := gateway.NewMetricsServer(cfg.MetricsAddr)
	go func() {
		logger.Info("metrics server starting", "addr", cfg.MetricsAddr)
		if err := metrics.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// ── HTTP Server ─────────────────────────────────────────
	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("shutdown signal received", "signal", sig)
		httpServer.Close()
	}()

	fmt.Printf("\n  🛡️  Legit Flow Gateway v%s\n", version)
	fmt.Printf("  ├── Proxy:   %s → %s\n", cfg.ListenAddr, cfg.LLMBackendURL)
	fmt.Printf("  ├── Metrics: %s/metrics\n", cfg.MetricsAddr)
	fmt.Printf("  ├── Policy:  %s (%s) — %d rules\n", p.Name, p.Version, len(p.Rules))
	fmt.Printf("  ├── Tools:   %d endpoints guarded\n", len(defaultTools))
	if cfg.ClassifierProvider != "disabled" {
		fmt.Printf("  ├── L2 API:  %s (%s) ⚠️ external\n", cfg.ClassifierProvider, cfg.ClassifierModel)
	} else {
		fmt.Printf("  ├── L2:      disabled (regex-only, full trust boundary)\n")
	}
	fmt.Printf("  └── Health:  %s/healthz\n\n", cfg.ListenAddr)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}
