// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

import (
	"context"
	"os"
)

// watchGuarded checks only that the folders exist: actors are Linux.
func watchGuardedAs(ctx context.Context, dirs []string, broken func(string), _ agentCred) error {
	return watchGuarded(ctx, dirs, broken)
}

func watchGuarded(_ context.Context, dirs []string, _ func(string)) error {
	if len(dirs) == 0 {
		return nil
	}
	for _, d := range dirs {
		if _, err := os.Lstat(d); err != nil {
			return err
		}
	}
	return nil
}
