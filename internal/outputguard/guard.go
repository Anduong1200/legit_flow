// Package outputguard implements streaming-safe output scanning.
// It buffers a sliding window of tokens, scans each chunk with L1 detectors,
// and truncates + substitutes when violations are found.
package outputguard

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/legitflow/legitflow/internal/common"
	"github.com/legitflow/legitflow/internal/detector"
)

// StreamGuard holds the state for streaming output inspection.
type StreamGuard struct {
	detector   *detector.Registry
	windowSize int
	buffer     []string // sliding window of chunks
	mu         sync.Mutex
	flushed    int // number of chunks safely flushed
	violated   bool
}

// NewStreamGuard creates a new streaming output guard.
func NewStreamGuard(reg *detector.Registry, windowSize int) *StreamGuard {
	if windowSize < 1 {
		windowSize = 3
	}
	return &StreamGuard{
		detector:   reg,
		windowSize: windowSize,
	}
}

// ChunkResult describes the outcome of processing a chunk.
type ChunkResult struct {
	SafeText  string // text safe to send to client
	Truncated bool   // whether the stream was truncated
	Violation bool   // whether a violation was detected
	Message   string // safe message to send if truncated
}

// ProcessChunk adds a new chunk to the sliding window, scans the window,
// and returns any safe text that can be flushed to the client.
func (g *StreamGuard) ProcessChunk(ctx context.Context, chunk string) (*ChunkResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.violated {
		// Stream already terminated
		return &ChunkResult{
			Truncated: true,
			Violation: true,
			Message:   "[Response truncated: policy violation detected]",
		}, nil
	}

	g.buffer = append(g.buffer, chunk)

	// Build the full window text for scanning
	windowText := strings.Join(g.buffer, "")

	// Scan with all detectors
	detections, err := g.detector.DetectAll(ctx, windowText)
	if err != nil {
		return nil, fmt.Errorf("output guard scan: %w", err)
	}

	// Check for restricted-tier detections
	for _, det := range detections {
		if det.Tier == detector.TierRestricted {
			g.violated = true
			common.OutputGuardTruncations.Inc()
			return &ChunkResult{
				Truncated: true,
				Violation: true,
				Message:   "[Response truncated: sensitive content detected. Request policy review.]",
			}, nil
		}
	}

	// If we have enough chunks in the buffer, flush the oldest ones
	var safeText string
	if len(g.buffer) > g.windowSize {
		flushCount := len(g.buffer) - g.windowSize
		safeChunks := g.buffer[:flushCount]
		safeText = strings.Join(safeChunks, "")
		g.buffer = g.buffer[flushCount:]
		g.flushed += flushCount
	}

	return &ChunkResult{
		SafeText: safeText,
	}, nil
}

// Flush returns any remaining buffered text. Call this when the stream ends.
func (g *StreamGuard) Flush(ctx context.Context) (*ChunkResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.violated {
		return &ChunkResult{
			Truncated: true,
			Violation: true,
			Message:   "[Response truncated: policy violation detected]",
		}, nil
	}

	if len(g.buffer) == 0 {
		return &ChunkResult{}, nil
	}

	// Final scan of remaining buffer
	windowText := strings.Join(g.buffer, "")
	detections, err := g.detector.DetectAll(ctx, windowText)
	if err != nil {
		return nil, fmt.Errorf("output guard final scan: %w", err)
	}

	for _, det := range detections {
		if det.Tier == detector.TierRestricted {
			g.violated = true
			common.OutputGuardTruncations.Inc()
			return &ChunkResult{
				Truncated: true,
				Violation: true,
				Message:   "[Final content redacted: sensitive content detected]",
			}, nil
		}
	}

	safeText := windowText
	g.buffer = nil
	return &ChunkResult{SafeText: safeText}, nil
}

// Reset clears the guard state for a new stream.
func (g *StreamGuard) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.buffer = nil
	g.flushed = 0
	g.violated = false
}
