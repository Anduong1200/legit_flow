package outputguard

import (
	"context"
	"testing"

	"github.com/legitflow/legitflow/internal/detector"
)

func newTestRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	reg.Register(detector.NewL1RegexDetector())
	return reg
}

func TestStreamGuard_SafeChunks(t *testing.T) {
	guard := NewStreamGuard(newTestRegistry(), 2)
	ctx := context.Background()

	chunks := []string{"Hello ", "world! ", "How are ", "you today?"}
	var allSafe string

	for _, chunk := range chunks {
		result, err := guard.ProcessChunk(ctx, chunk)
		if err != nil {
			t.Fatalf("ProcessChunk error: %v", err)
		}
		if result.Violation {
			t.Fatal("Unexpected violation on safe text")
		}
		allSafe += result.SafeText
	}

	// Flush remaining
	result, err := guard.Flush(ctx)
	if err != nil {
		t.Fatalf("Flush error: %v", err)
	}
	allSafe += result.SafeText

	expected := "Hello world! How are you today?"
	if allSafe != expected {
		t.Errorf("Got %q, want %q", allSafe, expected)
	}
}

func TestStreamGuard_TruncateOnSecret(t *testing.T) {
	guard := NewStreamGuard(newTestRegistry(), 2)
	ctx := context.Background()

	// First chunk is safe
	result, err := guard.ProcessChunk(ctx, "Here is some info: ")
	if err != nil {
		t.Fatalf("ProcessChunk error: %v", err)
	}
	if result.Violation {
		t.Fatal("Unexpected violation on safe chunk")
	}

	// Second chunk contains a JWT
	result, err = guard.ProcessChunk(ctx, "token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c please use it")
	if err != nil {
		t.Fatalf("ProcessChunk error: %v", err)
	}
	if !result.Violation {
		t.Error("Expected violation on JWT chunk")
	}
	if !result.Truncated {
		t.Error("Expected truncation")
	}
	if result.Message == "" {
		t.Error("Expected safe message on truncation")
	}

	// Subsequent chunks should also be blocked
	result, err = guard.ProcessChunk(ctx, "more text after violation")
	if err != nil {
		t.Fatalf("ProcessChunk error: %v", err)
	}
	if !result.Violation {
		t.Error("Expected continued violation after truncation")
	}
}

func TestStreamGuard_Reset(t *testing.T) {
	guard := NewStreamGuard(newTestRegistry(), 2)
	ctx := context.Background()

	// Trigger violation
	guard.ProcessChunk(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

	// Reset
	guard.Reset()

	// Should accept safe chunks again
	result, err := guard.ProcessChunk(ctx, "Clean text")
	if err != nil {
		t.Fatalf("ProcessChunk error: %v", err)
	}
	if result.Violation {
		t.Error("Expected no violation after reset")
	}
}
