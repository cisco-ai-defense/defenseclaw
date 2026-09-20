// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func buildScannerFixture(t *testing.T, stdout string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	program := fmt.Sprintf("package main\nimport (\"fmt\"; \"os\")\nfunc main() { fmt.Print(%s); os.Exit(%d) }\n", strconv.Quote(stdout), exitCode)
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "scanner-fixture")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("build scanner fixture: %v\n%s", err, output)
	}
	return binary
}
