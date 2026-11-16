// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// recordGatewayHelperForTest writes the helper record setup leaves beside a
// rendered per-user hook (.gateway-helper). Per-user shell hooks and plugins
// post only through the helper that record names, never one an inherited
// HOME selects.
func recordGatewayHelperForTest(t *testing.T, hookDir, binary string) {
	t.Helper()
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(binary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
