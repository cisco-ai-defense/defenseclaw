// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDarwinProcessInspectionUsesFixedBinaryAndMinimalEnvironment(t *testing.T) {
	t.Setenv("PATH", "/tmp/attacker-controlled")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "must-not-reach-ps")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "must-not-reach-ps")

	cmd := darwinProcessInspectionCommand(os.Getpid())
	if cmd.Path != "/bin/ps" {
		t.Fatalf("process-inspection helper path = %q, want /bin/ps", cmd.Path)
	}
	if cmd.Dir != "/" {
		t.Fatalf("process-inspection helper dir = %q, want /", cmd.Dir)
	}
	if !slices.Equal(cmd.Env, []string{"LANG=C", "LC_ALL=C"}) {
		t.Fatalf("process-inspection helper environment = %q, want locale-only environment", cmd.Env)
	}
	for _, forbidden := range []string{
		"PATH=/tmp/attacker-controlled",
		"DEFENSECLAW_GATEWAY_TOKEN=must-not-reach-ps",
		"OPENCLAW_GATEWAY_TOKEN=must-not-reach-ps",
	} {
		if slices.Contains(cmd.Env, forbidden) {
			t.Fatalf("process-inspection helper inherited %q", forbidden)
		}
	}
}

func TestDarwinExecutableIdentityRejectsDifferentPathWithSameBasename(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	spoofedPath := filepath.Join(t.TempDir(), filepath.Base(executable))
	info := pidInfo{
		PID:        os.Getpid(),
		Executable: spoofedPath,
	}
	if New(t.TempDir()).verifyExecutable(info) {
		t.Fatalf("different executable path with same basename was accepted: %q", spoofedPath)
	}
}
