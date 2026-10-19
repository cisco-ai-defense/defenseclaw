//go:build linux && axis_integration

// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import "context"

func (s *probeSession) run(ctx context.Context, pin runtimePin, command ...string) (executionResult, error) {
	if err := s.preflight(pin); err != nil {
		return executionResult{}, err
	}
	args, err := s.arguments(command...)
	if err != nil {
		return executionResult{}, err
	}
	return supervise(ctx, pin.path, args, s.workspace, s.environment())
}

func (s *probeSession) version(ctx context.Context, pin runtimePin) (executionResult, error) {
	if err := s.preflight(pin); err != nil {
		return executionResult{}, err
	}
	return supervise(ctx, pin.path, []string{"--version"}, s.workspace, s.environment())
}
