// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
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
// TrustedProgramData. The test only runs on a Windows host where
// TrustedProgramData resolves successfully (every real Windows
// managed_enterprise install; CI runners qualify). On any host where
// the lookup fails, the resolver returns "" and the server's
// existing empty-check turns that into a distinguishable
// "ipc: resolve socket path: empty" error.
func TestResolveManagedIPCSocketPathWindowsProducesProgramDataPath(t *testing.T) {
	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	got := ResolveSocketPath(cfg)
	if got == "" {
		t.Skip("TrustedProgramData resolution failed on this host; nothing to assert")
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
