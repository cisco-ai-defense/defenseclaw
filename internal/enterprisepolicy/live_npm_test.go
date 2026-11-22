// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestVerifyLiveCodexNamesTheNativeBinaryOfAnNpmLauncher (rel-1-0-10:GAP-0124):
// the shared npm Codex install is a node launcher the probe's minimal PATH
// cannot run. The refusal names the exact native executable inside the same
// package to pass as --agent-binary, not a path template.
func TestVerifyLiveCodexNamesTheNativeBinaryOfAnNpmLauncher(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("POSIX launcher script on linux/amd64 or arm64")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(root, "lib", "node_modules", "@openai", "codex")
	launcher := filepath.Join(pkg, "bin", "codex.js")
	writeFile(t, launcher, "#!/usr/bin/env dc-missing-node-interpreter\n")
	if err := os.Chmod(launcher, 0o755); err != nil {
		t.Fatal(err)
	}
	triple, platform := "x86_64-unknown-linux-musl", "codex-linux-x64"
	if runtime.GOARCH == "arm64" {
		triple, platform = "aarch64-unknown-linux-musl", "codex-linux-arm64"
	}
	native := filepath.Join(pkg, "node_modules", "@openai", platform, "vendor", triple, "bin", "codex")
	writeFile(t, native, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(native, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "bin", "codex")
	if err := os.Symlink(launcher, link); err != nil {
		t.Fatal(err)
	}
	opts := testOptions(t)
	_, err = VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorCodex, AgentBinary: link, Home: t.TempDir(), Timeout: 30 * time.Second})
	if err == nil {
		t.Fatal("an app-server that cannot start must fail the check")
	}
	if want := "pass --agent-binary " + native; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
}
