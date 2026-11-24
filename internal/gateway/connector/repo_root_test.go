// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// connectorTestDir is this package's source folder, read once when the test
// binary starts: go test starts it there, and the native Windows harness
// starts a cross-built binary in the same folder of its copy of the tree.
// runtime.Caller names the folder the binary was compiled in, which does not
// exist on the host a cross-built binary runs on (rel-1-0-10:GAP-1598).
var connectorTestDir, connectorTestDirErr = os.Getwd()

// connectorRepoRoot is the repository root, three folders above
// connectorTestDir.
func connectorRepoRoot(t testing.TB) string {
	t.Helper()
	if connectorTestDirErr != nil {
		t.Fatalf("read the test working folder: %v", connectorTestDirErr)
	}
	return filepath.Clean(filepath.Join(connectorTestDir, "..", "..", ".."))
}
