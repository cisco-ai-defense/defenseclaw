//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// turev #8: retire rewrites the marker to record a skipped profile. A
// rewrite whose protection fails must keep the marker it had (and its
// earlier skips); it removed it, which un-retired the install.
func TestRetiredMarkerRewriteKeepsTheOldMarkerWhenProtectionFails(t *testing.T) {
	marker := filepath.Join(t.TempDir(), ".retired")
	ok := func(string, string) error { return nil }
	if err := writeWindowsHookImageRetiredMarker(marker, []byte("first\n"), ok); err != nil {
		t.Fatal(err)
	}
	if err := writeWindowsHookImageRetiredMarker(marker, []byte("second\n"), ok); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "second\n" {
		t.Fatalf("rewritten marker = %q, %v", body, err)
	}
	failed := func(string, string) error { return errors.New("The parameter is incorrect.") }
	if err := writeWindowsHookImageRetiredMarker(marker, []byte("third\n"), failed); err == nil {
		t.Fatal("a rewrite whose protection failed reported success")
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "second\n" {
		t.Fatalf("after a failed rewrite the marker = %q, %v; want the earlier marker kept", body, err)
	}
	if _, err := os.Lstat(marker + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed rewrite left %s.new: %v", marker, err)
	}
}
