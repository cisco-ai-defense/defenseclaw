//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestOpenNoFollowRetriesFirstWindowsNameLookup(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "present"
		if delayed {
			name = "appears during read"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			var created bool
			var writeErr error
			if delayed {
				t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
					if !created {
						created = true
						writeErr = os.WriteFile(path, []byte("policy"), 0o600)
					}
				}))
			} else if err := os.WriteFile(path, []byte("policy"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := openNoFollow(path)
			if delayed && (!created || writeErr != nil) {
				t.Fatalf("retry did not publish the fixture: created = %v, err = %v", created, writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			data, err := io.ReadAll(file)
			if err != nil || string(data) != "policy" {
				t.Fatalf("body = %q, err = %v", data, err)
			}
		})
	}
}
