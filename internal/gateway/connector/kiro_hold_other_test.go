// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"testing"
)

// holdKiroWorkspaceCopyAgainstRemoval makes the earlier per-user hooks folder
// read-only, so the managed Setup's reclaim cannot remove the workspace copy.
func holdKiroWorkspaceCopyAgainstRemoval(t *testing.T, hooks string) {
	t.Helper()
	if err := os.Chmod(hooks, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hooks, 0o700) })
}
