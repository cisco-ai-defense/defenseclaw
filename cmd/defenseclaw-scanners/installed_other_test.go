// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1527: on Linux and macOS defenseclaw-scanners runs the scanners from
// the runtime tree the managed package installed (it refused every tool with
// "runs only on Windows").
func TestGAP1527LauncherRunsTheInstalledRuntime(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "python", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "python3.13"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version": 1, "python": "python/bin/python3.13", "versions": {"python": "3.13.16", "skill-scanner": "2.2.1"}}`
	if err := os.WriteFile(filepath.Join(root, "runtime.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	old := installedRuntime
	t.Cleanup(func() { installedRuntime = old })
	installedRuntime = func() (string, error) { return root, nil }

	var stdout, stderr bytes.Buffer
	if code := run([]string{"skill-scanner", "scan", "/opt/defenseclaw-scan/s"}, &stdout, &stderr); code != 0 {
		t.Fatalf("skill-scanner exit %d: %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) < 6 || lines[0] != "-I" || lines[1] != "-B" || lines[2] != "-c" || lines[4] != "skill-scanner" || lines[len(lines)-1] != "/opt/defenseclaw-scan/s" {
		t.Fatalf("interpreter arguments = %q", lines)
	}
	stdout.Reset()
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "skill-scanner 2.2.1") {
		t.Fatalf("--version = %d %q", code, stdout.String())
	}

	installedRuntime = func() (string, error) { return "", managed.ErrNoScannerRuntime }
	stderr.Reset()
	if code := run([]string{"skill-scanner", "scan", "x"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "defenseclaw-enterprise package installs it") {
		t.Fatalf("no runtime: exit %d %q", code, stderr.String())
	}

	installedRuntime = func() (string, error) { return root, nil }
	if err := os.WriteFile(filepath.Join(root, "runtime.json"), []byte(`{"schema_version": 1, "python": "../../usr/bin/python3"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run([]string{"skill-scanner"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "inside the runtime") {
		t.Fatalf("interpreter outside the runtime: exit %d %q", code, stderr.String())
	}
}
