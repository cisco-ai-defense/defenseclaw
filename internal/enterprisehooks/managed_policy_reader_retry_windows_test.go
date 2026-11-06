//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadTrustedWindowsManagedPolicyRetriesFirstNameLookup(t *testing.T) {
	originalTrust := windowsManagedPolicyFileTrustCheck
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() { windowsManagedPolicyFileTrustCheck = originalTrust })
	for _, delayed := range []bool{false, true} {
		name := "present"
		if delayed {
			name = "appears during read"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "90-defenseclaw.json")
			body := []byte(`{"managed":true}`)
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
			data, present, err := readTrustedWindowsManagedPolicyFile(path)
			if delayed && (!created || writeErr != nil) {
				t.Fatalf("retry did not publish the fixture: created = %v, err = %v", created, writeErr)
			}
			if err != nil || !present || string(data) != string(body) {
				t.Fatalf("body = %q, present = %v, err = %v", data, present, err)
			}
		})
	}
}

func TestWindowsManagedPolicyWriterKeepsMatchingFileAfterFirstMiss(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	path := paths.Adapter
	body := []byte("same body\r\n")
	if err := writeWindowsManagedFile(path, body, true); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	parked := path + ".parked"
	if err := os.Rename(path, parked); err != nil {
		t.Fatal(err)
	}
	var restored bool
	var restoreErr error
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
		if !restored {
			restored = true
			restoreErr = os.Rename(parked, path)
		}
	}))
	if err := writeWindowsManagedFile(path, body, true); err != nil {
		t.Fatal(err)
	}
	if !restored || restoreErr != nil {
		t.Fatalf("retry did not restore the fixture: restored = %v, err = %v", restored, restoreErr)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("matching managed content was replaced after a first lookup miss")
	}
}
