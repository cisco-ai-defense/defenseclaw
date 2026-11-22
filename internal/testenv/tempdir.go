// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"runtime"
	"testing"
)

// TempRoot is the folder t.TempDir makes its directories in: GOTMPDIR when
// it is set (the testing package reads it), else os.TempDir.
func TempRoot() string {
	if dir := os.Getenv("GOTMPDIR"); dir != "" {
		return dir
	}
	return os.TempDir()
}

// SetTempRoot makes dir the folder of every temporary directory the test
// makes from now on: os.TempDir (TMPDIR) and t.TempDir, which honors GOTMPDIR
// when it is set. Moving TMPDIR alone left t.TempDir in GOTMPDIR, so a test
// that needs a deep or an off-device temporary folder got the box's own one
// on every box that sets GOTMPDIR (rel-1-0-10:GAP-0423, GAP-0577, GAP-0439).
// A directory t.TempDir already made for this test stays where it is.
func SetTempRoot(t testing.TB, dir string) {
	t.Helper()
	t.Setenv("TMPDIR", dir)
	if runtime.GOOS == "windows" {
		// os.TempDir reads TMP, then TEMP, there.
		t.Setenv("TMP", dir)
		t.Setenv("TEMP", dir)
	}
	if os.Getenv("GOTMPDIR") != "" {
		t.Setenv("GOTMPDIR", dir)
	}
}
