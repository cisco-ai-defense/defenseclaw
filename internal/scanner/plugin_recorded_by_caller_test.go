// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2482: every Go caller records the plugin scan it runs, so the CLI child
// is told not to record the same scan a second time.
func TestPluginScannerTellsChildTheCallerRecords(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "env")
	bin := filepath.Join(dir, "defenseclaw")
	script := "#!/bin/sh\nprintf '%s' \"$" + ScanRecordedByCallerEnv + "\" > '" + marker + "'\n" +
		"echo '{\"scanner\":\"plugin-scanner\",\"findings\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (&PluginScanner{BinaryPath: bin}).Scan(context.Background(), dir); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "1" {
		t.Fatalf("%s = %q in the child, want 1", ScanRecordedByCallerEnv, got)
	}
}
