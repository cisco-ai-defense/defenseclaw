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
	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

// TestResolveManagedIPCSocketPathWindowsProducesProgramFilesPath
// asserts the default resolver produces a path under
// TrustedProgramFiles. On CI (`CI=true`) a failed TrustedProgramFiles
// resolution is a hard failure — a regression in winpath would
// otherwise produce a green build while leaving the Program Files
// path unverified. On a developer laptop the test skips
// gracefully because the registry key may legitimately be
// unreadable outside of a real Windows managed_enterprise
// install. See CR spec-004:PRRT_kwDORuAK-s6ankzr.
func TestResolveManagedIPCSocketPathWindowsProducesProgramFilesPath(t *testing.T) {
	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	got := ResolveSocketPath(cfg)
	if got == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("TrustedProgramFiles resolution returned empty on a CI runner — winpath registry access must succeed for the managed IPC surface")
		}
		t.Skip("TrustedProgramFiles resolution failed on this host; running outside CI so skipping")
	}
	// Expected shape: <programFiles>\Cisco\Cisco Secure Client\DefenseClaw\ipc\defenseclaw_ipc.sock
	if !strings.HasSuffix(got, filepath.Join(windowsManagedIPCRelativeDir, SocketFileName)) {
		t.Fatalf("socket path missing expected suffix: got %q, want ending %q",
			got, filepath.Join(windowsManagedIPCRelativeDir, SocketFileName))
	}
	if !strings.Contains(got, `Cisco\Cisco Secure Client\DefenseClaw`) {
		t.Fatalf("socket path missing Cisco Secure Client segment: got %q", got)
	}
}

func TestValidateWindowsSocketPathFollowsTheEnterpriseProfilePin(t *testing.T) {
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil || programFiles == "" {
		t.Skipf("trusted Program Files unavailable: %v", err)
	}
	secureClient := filepath.Join(programFiles, winpath.ManagedIPCRelativeDir, "defenseclaw-sensor.sock")
	standalone := filepath.Join(programFiles, winpath.StandaloneManagedIPCRelativeDir, "defenseclaw-sensor.sock")

	t.Setenv(winpath.EnterpriseProfileEnv, "")
	if err := validateWindowsSocketPathFor(secureClient, "defenseclaw-sensor.sock"); err != nil {
		t.Fatalf("unpinned service refused the Secure Client directory: %v", err)
	}
	if err := validateWindowsSocketPathFor(standalone, "defenseclaw-sensor.sock"); err == nil {
		t.Fatal("unpinned service accepted the standalone directory")
	}

	t.Setenv(winpath.EnterpriseProfileEnv, winpath.EnterpriseProfileStandalone)
	if err := validateWindowsSocketPathFor(standalone, "defenseclaw-sensor.sock"); err != nil {
		t.Fatalf("standalone-pinned service refused its own directory: %v", err)
	}
	if err := validateWindowsSocketPathFor(secureClient, "defenseclaw-sensor.sock"); err == nil {
		t.Fatal("standalone-pinned service accepted the Secure Client directory")
	}
}
