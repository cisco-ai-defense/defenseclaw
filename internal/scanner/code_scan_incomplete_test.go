// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// unreadableTarget is one way a scan target can hide content from the
// scanners while the target itself can still be statted.
type unreadableTarget struct {
	name string
	// build returns the scan target and the path the scan cannot read.
	build func(t *testing.T) (target, unread string)
}

func unreadableTargets() []unreadableTarget {
	clean := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("print('hello')\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lock := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
	}
	return []unreadableTarget{
		{"root directory that cannot be listed", func(t *testing.T) (string, string) {
			dir := t.TempDir()
			skill := filepath.Join(dir, "skill")
			if err := os.Mkdir(skill, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(skill, "run.py"), []byte("os.system(cmd)\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			lock(t, skill)
			return skill, skill
		}},
		{"subdirectory that cannot be listed", func(t *testing.T) (string, string) {
			dir := t.TempDir()
			clean(t, dir)
			sub := filepath.Join(dir, "scripts")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sub, "run.py"), []byte("os.system(cmd)\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			lock(t, sub)
			return dir, sub
		}},
		{"code file that cannot be read", func(t *testing.T) (string, string) {
			dir := t.TempDir()
			clean(t, dir)
			file := filepath.Join(dir, "run.py")
			if err := os.WriteFile(file, []byte("os.system(cmd)\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			lock(t, file)
			return dir, file
		}},
		{"non-code file that cannot be read", func(t *testing.T) (string, string) {
			dir := t.TempDir()
			clean(t, dir)
			file := filepath.Join(dir, "payload.bin")
			if err := os.WriteFile(file, []byte("exec 3<>/dev/"+"tcp/127.0.0.1/4444\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			lock(t, file)
			return dir, file
		}},
		{"single-file target that cannot be read", func(t *testing.T) (string, string) {
			file := filepath.Join(t.TempDir(), "run.py")
			if err := os.WriteFile(file, []byte("os.system(cmd)\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			lock(t, file)
			return file, file
		}},
	}
}

func skipWhenPermissionsDoNotApply(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 paths; the restriction cannot be built here")
	}
}

// A `scan code` that cannot read part of its target must not report clean.
func TestScanCodeReportsAnUnreadableTargetAsIncomplete(t *testing.T) {
	skipWhenPermissionsDoNotApply(t)
	for _, tc := range unreadableTargets() {
		t.Run(tc.name, func(t *testing.T) {
			target, unread := tc.build(t)
			result, err := ScanCode(t.Context(), target, "")
			if !errors.Is(err, ErrIncompleteScan) {
				t.Fatalf("ScanCode(%s) = %+v, %v; want ErrIncompleteScan naming %s", target, result, err, unread)
			}
			if result != nil {
				t.Fatalf("an incomplete scan returned a result: %+v", result)
			}
		})
	}
}

// Every code scanner of the suite reports what it could not read once a
// complete scan is required, and keeps its best-effort skip otherwise (the
// gateway's hook-time scans rely on that).
func TestEveryCodeScannerReportsUnreadContentOnlyWhenACompleteScanIsRequired(t *testing.T) {
	skipWhenPermissionsDoNotApply(t)
	for _, tc := range unreadableTargets() {
		t.Run(tc.name, func(t *testing.T) {
			target, _ := tc.build(t)
			for _, sc := range NewCodeScanners("") {
				_, err := sc.Scan(requireCompleteScan(context.Background()), target)
				// The malware scanner reads every file; the others read only
				// their extensions, so a .bin file is outside their scope.
				inScope := tc.name != "non-code file that cannot be read" || sc.Name() == "clawshield-malware"
				if inScope && !errors.Is(err, ErrIncompleteScan) {
					t.Errorf("%s with a complete scan required: err = %v, want ErrIncompleteScan", sc.Name(), err)
				}
				if !inScope && err != nil {
					t.Errorf("%s failed on a file outside its scope: %v", sc.Name(), err)
				}
				if _, err := sc.Scan(context.Background(), target); err != nil && errors.Is(err, ErrIncompleteScan) {
					t.Errorf("%s best-effort scan: err = %v, want the unread content skipped", sc.Name(), err)
				}
			}
		})
	}
}

// Unreadable content outside the scanned set (symlinks, skipped vendor
// directories) is not part of the scan and never makes it incomplete.
func TestScanCodeIgnoresUnreadablePathsItNeverScans(t *testing.T) {
	skipWhenPermissionsDoNotApply(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("print('hello')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vendor := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(vendor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vendor, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vendor, 0o700) })
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.py"), filepath.Join(dir, "dangling.py")); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanCode(t.Context(), dir, ""); err != nil {
		t.Fatalf("ScanCode = %v, want a complete scan of the readable files", err)
	}
}
