// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestResolveManagedIPCSocketPathWindowsHonoursExplicitOverride
// asserts cfg.Managed.SocketPath wins verbatim — same escape-hatch
// shape as macOS. Useful for CI fixture rigs that need to move the
// socket to a scratch dir. See docs/specs/004-windows-ui-ipc/
// design.md § Open questions.
func TestResolveManagedIPCSocketPathWindowsHonoursExplicitOverride(t *testing.T) {
	// This test drives the TOP-LEVEL ResolveSocketPath (which
	// applies the override rule) rather than the Windows-specific
	// helper, so we exercise the whole resolution chain the sidecar
	// bootstrap actually calls.
	explicit := `C:\scratch\ci\defenseclaw_ipc.sock`
	cfg := &config.Config{
		DeploymentMode: string(config.DeploymentModeManagedEnterprise),
		Managed:        config.ManagedIPCConfig{SocketPath: explicit},
	}
	if got := ResolveSocketPath(cfg); got != explicit {
		t.Fatalf("explicit override lost: got %q want %q", got, explicit)
	}
}

// TestResolveManagedIPCSocketPathWindowsProducesProgramDataPath
// asserts the default resolver produces a path under
// TrustedProgramData. On CI (`CI=true`) a failed TrustedProgramData
// resolution is a hard failure — a regression in winpath would
// otherwise produce a green build while leaving the ProgramData
// path unverified. On a developer laptop the test skips
// gracefully because the registry key may legitimately be
// unreadable outside of a real Windows managed_enterprise
// install. See CR spec-004:PRRT_kwDORuAK-s6ankzr.
func TestResolveManagedIPCSocketPathWindowsProducesProgramDataPath(t *testing.T) {
	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	got := ResolveSocketPath(cfg)
	if got == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("TrustedProgramData resolution returned empty on a CI runner — winpath registry access must succeed for the managed IPC surface")
		}
		t.Skip("TrustedProgramData resolution failed on this host; running outside CI so skipping")
	}
	// Expected shape: <programData>\Cisco\Cisco Secure Client\DefenseClaw\ipc\defenseclaw_ipc.sock
	if !strings.HasSuffix(got, filepath.Join(windowsManagedIPCRelativeDir, SocketFileName)) {
		t.Fatalf("socket path missing expected suffix: got %q, want ending %q",
			got, filepath.Join(windowsManagedIPCRelativeDir, SocketFileName))
	}
	if !strings.Contains(got, `Cisco\Cisco Secure Client\DefenseClaw`) {
		t.Fatalf("socket path missing Cisco Secure Client segment: got %q", got)
	}
}
