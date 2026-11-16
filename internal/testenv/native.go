// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

//go:embed native/sleep.c
var nativeSleepSource []byte

// NativeSleep returns the path of a native program that sleeps for its first
// argument (seconds). It works under any name it is copied or linked to, which
// a test needs when it must run a program at a given path: a system sleep(1)
// can be one entry of a multi-call binary that refuses to run under another
// name (Ubuntu 26.04). The program is built from native/sleep.c in the temporary
// directory of the test and removed with it. It builds on Unix hosts; tests that
// need it skip on Windows.
func NativeSleep(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "sleep.c")
	if err := os.WriteFile(source, nativeSleepSource, 0o600); err != nil {
		t.Fatal(err)
	}
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}
	program := filepath.Join(dir, "native-sleep")
	if output, err := exec.Command(compiler, "-o", program, source).CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in program needs a C compiler (%s): %v\n%s", compiler, err, output)
	}
	return program
}
