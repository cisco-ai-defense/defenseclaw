//go:build !cgo || !grpo_engine

// internal/training/grpo_stub.go
package training

import (
	"context"
	"fmt"
)

// GrpoEngineAvailable returns false when the C engine is not compiled in.
func GrpoEngineAvailable() bool { return false }

// RunGrpoLocal is a stub that returns an error when the C engine is unavailable.
func RunGrpoLocal(ctx context.Context, cfg GrpoLocalConfig) (*RunResult, error) {
	return nil, fmt.Errorf("grpo-local backend not available: rebuild with CGO_ENABLED=1 -tags grpo_engine")
}
