// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagedRecoveryPreservesLiteralUnixDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX recovery command")
	}
	dataDir := filepath.Join(t.TempDir(), "person$group's `name`", "custom-acp")
	flags := managedSetupFlags("http://127.0.0.1:18970/api/v1/acp/evaluate", filepath.Join(dataDir, "acp", "zed-kiro.token"))
	cmd := exec.Command("sh", "-c", "set -- "+flags+`; printf '%s\n' "$@"`)
	cmd.Env = append(cmd.Environ(), "group=expanded")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "--api-port\n18970\n--data-dir\n" + dataDir + "\n"; string(out) != want {
		t.Fatalf("recovery arguments = %q, want %q (flags %s)", out, want, flags)
	}
	if strings.Contains(string(out), "expanded") {
		t.Fatal("recovery expanded the runtime path")
	}
}
