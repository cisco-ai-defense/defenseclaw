//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadHookSidecarRetriesFirstWindowsNameLookup(t *testing.T) {
	body := []byte(`{"version":2,"gateway_addr":"127.0.0.1:18970"}`)
	for _, delayed := range []bool{false, true} {
		name := "present"
		if delayed {
			name = "appears during read"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".hookcfg")
			var created bool
			var writeErr error
			if delayed {
				t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
					if !created {
						created = true
						writeErr = os.WriteFile(path, body, 0o600)
					}
				}))
			} else if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			addr := readHookSidecar(path)["DEFENSECLAW_GATEWAY_ADDR"]
			if delayed && (!created || writeErr != nil) {
				t.Fatalf("retry did not publish the fixture: created = %v, err = %v", created, writeErr)
			}
			if addr != "127.0.0.1:18970" {
				t.Fatalf("gateway address = %q", addr)
			}
		})
	}
}
