// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"path/filepath"
	"testing"
)

// countMountedVolumeQueries counts the DOS device queries
// ValidateFixedNTFSMountedPath makes, one per full machine-root validation.
func countMountedVolumeQueries(t *testing.T) *int {
	t.Helper()
	saved := queryDOSDeviceTarget
	t.Cleanup(func() { queryDOSDeviceTarget = saved })
	count := 0
	queryDOSDeviceTarget = func(device string) (string, error) {
		count++
		return saved(device)
	}
	return &count
}

func freshMachineRoot(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "Root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	clean := filepath.Clean(resolved)
	// The root leaves the cache when the test ends: its change notifications
	// close before t.TempDir removes the folders, and the roots of earlier
	// tests (-count=N) never fill the cache (trustedMachineRootCacheMaxEntries)
	// so that a later root is not kept.
	t.Cleanup(func() { forgetTrustedMachineRoot(clean) })
	return clean
}

// GAP-0011 (red at the base): one root validated 200 times in a burst ran
// the whole mounted-volume and reparse-chain check 200 times.
func TestGAP0011ARepeatedMachineRootValidationRunsTheCheckOnce(t *testing.T) {
	root := freshMachineRoot(t)
	queries := countMountedVolumeQueries(t)
	if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
		t.Fatalf("precondition: %s is a trusted root: %v", root, err)
	}
	first := *queries
	if first == 0 {
		t.Fatal("precondition: a full validation queries the mounted volume")
	}
	for i := 0; i < 199; i++ {
		got, err := ValidateTrustedMachineRoot(root, "test")
		if err != nil || got != root {
			t.Fatalf("call %d: %q, %v", i, got, err)
		}
	}
	if *queries != first {
		t.Fatalf("200 validations of an unchanged root ran %d mounted-volume queries, want %d (one full check)", *queries, first)
	}
}

func BenchmarkGAP0011ValidateProgramFiles(b *testing.B) {
	programFiles, err := TrustedProgramFiles()
	if err != nil {
		b.Skip(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ValidateTrustedMachineRoot(programFiles, "Program Files"); err != nil {
			b.Fatal(err)
		}
	}
}
