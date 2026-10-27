// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package scanner

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1527: the standalone managed Linux/macOS gateway runs its default
// scanners through the scanner runtime its package installed.
func TestGAP1527ManagedUnixGatewayResolvesTheInstalledScannerRuntime(t *testing.T) {
	const launcher = "/opt/defenseclaw/bin/defenseclaw-scanners"
	old := installedScannerRuntime
	t.Cleanup(func() { installedScannerRuntime = old })
	installedScannerRuntime = func() (string, error) { return launcher, nil }

	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if got := NewSkillScannerFromLLM(config.SkillScannerConfig{}, config.LLMConfig{}, config.CiscoAIDefenseConfig{}).Config.Binary; got != launcher {
		t.Fatalf("default skill scanner = %q, want the runtime launcher", got)
	}
	if got := resolveScannerRuntime("defenseclaw", "defenseclaw"); got != launcher {
		t.Fatalf("default plugin/MCP scanner = %q", got)
	}
	if got := resolveScannerRuntime("/usr/local/bin/skill-scanner", "skill-scanner"); got != "/usr/local/bin/skill-scanner" {
		t.Fatalf("an explicit scanner path was replaced: %q", got)
	}
	if err := scannerRuntimePreflight(launcher, "skill-scanner"); err != nil {
		t.Fatalf("trusted runtime refused: %v", err)
	}

	installedScannerRuntime = func() (string, error) { return "", managed.ErrNoScannerRuntime }
	if got := resolveScannerRuntime("skill-scanner", "skill-scanner"); got != "skill-scanner" {
		t.Fatalf("a payload install without the runtime resolved %q", got)
	}
	if err := scannerRuntimePreflight("skill-scanner", "skill-scanner"); err != nil {
		t.Fatalf("absent runtime refused the preflight: %v", err)
	}

	installedScannerRuntime = func() (string, error) { return "", errors.New("python: group/other writable") }
	err := scannerRuntimePreflight(launcher, "skill-scanner")
	if !errors.Is(err, ErrScannerRuntimeUnavailable) || !strings.Contains(err.Error(), "reinstall") {
		t.Fatalf("untrusted runtime preflight = %v", err)
	}

	t.Setenv(managed.EnterpriseProfileEnv, "")
	installedScannerRuntime = func() (string, error) { return launcher, nil }
	if got := resolveScannerRuntime("skill-scanner", "skill-scanner"); got != "skill-scanner" {
		t.Fatalf("a per-user gateway resolved the managed runtime: %q", got)
	}
}
