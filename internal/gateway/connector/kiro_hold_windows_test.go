// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// holdKiroWorkspaceCopyAgainstRemoval is the Windows form of the read-only
// folder: a read-only mode bit on a folder stops nothing there, but a file
// held open without delete sharing cannot be removed (sharing violation), so
// the managed Setup's reclaim of the earlier workspace copy fails the same way.
func holdKiroWorkspaceCopyAgainstRemoval(t *testing.T, hooks string) {
	t.Helper()
	held, err := os.Open(filepath.Join(hooks, kiroManagedHooksName))
	if err != nil {
		t.Fatalf("hold the earlier workspace copy: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
}
