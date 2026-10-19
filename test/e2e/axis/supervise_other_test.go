//go:build !linux && axis_integration

// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import (
	"context"
	"errors"
	"testing"
)

// Unsupported platforms never spawn the supplied executable, including when
// the explicitly opted-in integration tests were compiled there.
func (s *probeSession) run(_ context.Context, pin runtimePin, _ ...string) (executionResult, error) {
	return executionResult{}, s.preflight(pin)
}

func (s *probeSession) version(_ context.Context, pin runtimePin) (executionResult, error) {
	return executionResult{}, s.preflight(pin)
}

func TestUnsupportedRunNeverExecutes(t *testing.T) {
	s := &probeSession{}
	if _, err := s.run(context.Background(), runtimePin{path: "must-not-execute"}, "ignored"); !errors.Is(err, errUnsupportedPlatform) {
		t.Fatalf("wanted platform refusal before examining or executing runtime: %v", err)
	}
}
