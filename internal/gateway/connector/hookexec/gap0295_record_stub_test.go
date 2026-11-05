// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFreshGatewayRecordStub writes a just-modified gateway.pid in home, so
// the cheap recent-start look (perUserGatewayRecentlyStarted) passes on Linux.
func writeFreshGatewayRecordStub(t *testing.T, home string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, "gateway.pid"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}
