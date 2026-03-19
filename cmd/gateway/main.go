// Legit Flow — AI Security Data Plane
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

	// L1: always-on regex detectors (fast path)
	reg.Register(detector.NewL1RegexDetector())

	// L2: contextual classifier (API-based, pluggable)
	if cfg.ClassifierProvider != "disabled" {
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
	} else {
		logger.Info("L2 contextual detector disabled (regex-only mode)")
	}

	// ── Policy Engine ───────────────────────────────────────
	eng, err := policy.NewEngine(cfg.PolicyDir, logger)
	if err != nil {
		logger.Error("policy engine init failed", "error", err)
		os.Exit(1)
	}
	logger.Info("policy engine ready",
		"policy", eng.GetPolicy().Name,
		"version", eng.GetPolicy().Version,
	)

	// ── Audit Logger ────────────────────────────────────────
	auditor, err := audit.NewLogger(cfg, logger)
	if err != nil {
		logger.Error("audit logger init failed", "error", err)
		os.Exit(1)
	}

	// ── Gateway Server ──────────────────────────────────────
	srv, err := gateway.NewServer(cfg, logger, reg, eng, auditor)
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
	fmt.Printf("  ├── Policy:  %s (%s)\n", eng.GetPolicy().Name, eng.GetPolicy().Version)
	if cfg.ClassifierProvider != "disabled" {
		fmt.Printf("  ├── L2 API:  %s (%s)\n", cfg.ClassifierProvider, cfg.ClassifierModel)
	}
	fmt.Printf("  └── Health:  %s/healthz\n\n", cfg.ListenAddr)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}
