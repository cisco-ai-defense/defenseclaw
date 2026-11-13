// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0185: a configured mcp-scanner path that does not exist is "not
// installed", as a bare name not on PATH is, so the runtime's config rules
// decide instead of a failed scan refusing every server.
func TestGAP0185MissingMCPScannerPathIsUnavailable(t *testing.T) {
	for _, bin := range []string{"dc-gap0185-no-mcp-scanner", filepath.Join(t.TempDir(), "mcp-scanner")} {
		_, err := (&MCPStaticScanner{Binary: bin}).Scan(context.Background(), filepath.Join(t.TempDir(), "tools.json"))
		if !scanner.Unavailable(err) {
			t.Errorf("%s: %v is not unavailable", bin, err)
		}
	}
}
