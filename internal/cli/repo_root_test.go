// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"
)

// cliTestRepoRoot is the repository root, two folders above the package
// folder go test runs in. runtime.Caller named the build machine's source
// path, which a test binary built on one computer and run on another lacks.
func cliTestRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
