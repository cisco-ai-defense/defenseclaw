// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// writeExecutable is a small helper that drops a shell-executable
// stub at path. We don't need a real binary — resolveDefenseclawBin
// only checks filesystem metadata (IsDir, +x bit), not whether the
// file is a valid ELF/mach-o.
func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestResolveDefenseclawBin_FallsBackToLiteral covers the very last
// branch: no $PATH hit and no sibling. The behaviour must still be a
// strict superset of the old hardcoded-string path (so os/exec can
// produce its usual "not found" error).
func TestResolveDefenseclawBin_FallsBackToLiteral(t *testing.T) {
	// Rule out PATH: point it at an empty directory so LookPath
	// cannot succeed. We do NOT try to override os.Executable —
	// that's unsafe in a test process.
	empty := t.TempDir()
	t.Setenv("PATH", empty)

	// Also rule out the sibling branch by checking directly: if
	// os.Executable's directory happens to contain a real
	// `defenseclaw`, the sibling branch will (correctly) return
	// that path — treat it as a pass.
	got := resolveDefenseclawBin()
	if got == "defenseclaw" {
		return // literal fallback exercised
	}

	// Sibling or self-match — accept as long as it exists and is
	// executable, or if os.Executable failed (unlikely on Linux CI).
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("resolveDefenseclawBin() returned non-existent %q: %v", got, err)
	}
	if info.IsDir() {
		t.Errorf("resolveDefenseclawBin() returned a directory: %q", got)
	}
}

// TestResolveDefenseclawBin_HonoursPATH stages a fake defenseclaw on
// PATH and verifies it wins over the literal fallback when there is
// no sibling binary. Skipped on Windows: the .exe extension
// machinery makes this test non-portable and CI runs on Linux.
func TestResolveDefenseclawBin_HonoursPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping PATH test on Windows")
	}

	dir := t.TempDir()
	stub := filepath.Join(dir, "defenseclaw")
	writeExecutable(t, stub)

	t.Setenv("PATH", dir)

	got := resolveDefenseclawBin()

	// If os.Executable returned a path whose directory is *also*
	// the tempdir (vanishingly unlikely) or whose basename is
	// already "defenseclaw", accept that as well — both are
	// legitimate higher-priority branches.
	self, err := os.Executable()
	if err == nil {
		resolved, _ := filepath.EvalSymlinks(self)
		if resolved == "" {
			resolved = self
		}
		if filepath.Base(resolved) == "defenseclaw" {
			return
		}
		sibling := filepath.Join(filepath.Dir(resolved), "defenseclaw")
		if _, serr := os.Stat(sibling); serr == nil {
			if got == sibling {
				return // sibling branch fired first — legitimate
			}
		}
	}

	// Otherwise, PATH lookup must have found our stub.
	wantResolved, lerr := exec.LookPath("defenseclaw")
	if lerr != nil {
		t.Fatalf("exec.LookPath after staging PATH failed: %v", lerr)
	}
	if got != wantResolved {
		t.Errorf("resolveDefenseclawBin() = %q, want PATH match %q", got, wantResolved)
	}
}

// TestResolveDefenseclawBin_PrefersSibling verifies that when the
// test process has a legitimate sibling on disk (i.e. we drop a
// `defenseclaw` stub next to `os.Executable()`), the resolver uses
// the sibling instead of walking PATH.
//
// We can only assert this non-destructively, so the test runs inside
// an isolated temp dir only when the test binary lives in a writable
// location. On CI this is the go-test scratch dir, which is
// writable by the test user.
func TestResolveDefenseclawBin_PrefersSibling(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		t.Skipf("EvalSymlinks on self failed: %v", err)
	}
	dir := filepath.Dir(self)

	// Skip if the dir is not writable (e.g. /usr/local/bin on
	// non-root). We don't want to try chmod hacks in tests.
	probe := filepath.Join(dir, ".dc-resolver-probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Skipf("test-binary dir not writable (%v); skipping sibling-preference check", err)
	}
	_ = os.Remove(probe)

	// If the binary we're running is already named "defenseclaw",
	// the self-match branch wins — don't muddy the test.
	if filepath.Base(self) == "defenseclaw" {
		t.Skip("test binary basename is already defenseclaw; self-match branch active")
	}

	sibling := filepath.Join(dir, "defenseclaw")
	if _, err := os.Stat(sibling); err == nil {
		t.Skipf("%s already exists; refusing to overwrite real binary", sibling)
	}
	writeExecutable(t, sibling)
	t.Cleanup(func() { _ = os.Remove(sibling) })

	// Neutralize PATH so the only way to land on `sibling` is the
	// sibling branch (not the LookPath fallback).
	t.Setenv("PATH", t.TempDir())

	got := resolveDefenseclawBin()
	if got != sibling {
		t.Errorf("expected sibling %q, got %q", sibling, got)
	}
}
