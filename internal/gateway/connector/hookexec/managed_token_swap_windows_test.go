// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity/pinnedtest"
)

// rel-1-0-6:GAP-0300: the managed hook token is read only from the file the
// hook checked. One renamed over the path at the check/use instant (the
// pinned stat is the seam, no timing) is refused, not sent as the token.
func TestReadManagedTokenFileRefusesATokenSwappedAfterTheCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "managed-hook-token")
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(path, []byte("checked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("swapped-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readManagedTokenFile(path, 4096); err != nil || string(data) != "checked-token" {
		t.Fatalf("unswapped read = %q, %v", data, err)
	}
	swaps := pinnedtest.SwapAfterCheck(t, path, replacement)
	data, err := readManagedTokenFile(path, 4096)
	if swaps.Load() != 1 {
		t.Fatalf("swaps = %d, want 1", swaps.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "changed identity before open") {
		t.Fatalf("swapped token = %q, %v; want refused as changed identity before open", data, err)
	}
}
