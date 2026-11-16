//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestWindowsWatchOwnedFilesIncludesCodexRuntimeAndLeavesAgentConfigAlone(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	fixture := newWindowsGenericCodexFixture(t)
	previous := windowsCodexRequirementsOptionsResolver
	machineDir := filepath.Join(t.TempDir(), "machine")
	windowsCodexRequirementsOptionsResolver = func(string, string) (connector.WindowsCodexMachineRequirementsOptions, error) {
		return connector.WindowsCodexMachineRequirementsOptions{
			RequirementsPath: filepath.Join(machineDir, "requirements.toml"),
			OwnershipPath:    filepath.Join(machineDir, "ownership.json"),
			ManagedStatePath: filepath.Join(machineDir, "state.json"),
		}, nil
	}
	t.Cleanup(func() { windowsCodexRequirementsOptionsResolver = previous })

	own, err := WatchOwnedFiles(fixture.opts)
	if err != nil {
		t.Fatalf("Codex watch files: %v", err)
	}
	for _, path := range []string{
		filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hook-codex.token"),
		filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hookcfg.codex"),
		filepath.Join(machineDir, "requirements.toml"),
		filepath.Join(machineDir, "ownership.json"),
		filepath.Join(machineDir, "state.json"),
	} {
		if !slices.Contains(own.ExclusiveWriter, path) {
			t.Errorf("exclusive watch files omit %s: %v", path, own.ExclusiveWriter)
		}
	}
	if slices.Contains(own.ExclusiveWriter, fixture.config) || slices.Contains(own.SharedWriter, fixture.config) {
		t.Fatalf("machine-managed Codex does not own the agent config %s: %+v", fixture.config, own)
	}
}

func TestWindowsWatchOwnedFilesIncludesClaudePolicyAndRuntime(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	fixture := newWindowsManagedInstallFixture(t, nil)
	own, err := WatchOwnedFiles(InstallOptions{
		ConnectorName: "claudecode",
		UserHome:      fixture.home,
		OwnerSID:      fixture.targetSID.String(),
	})
	if err != nil {
		t.Fatalf("Claude Code watch files: %v", err)
	}
	for _, path := range []string{
		fixture.policyPath,
		filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hook-claudecode.token"),
		filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hookcfg.claudecode"),
	} {
		if !slices.Contains(own.ExclusiveWriter, path) {
			t.Errorf("exclusive watch files omit %s: %v", path, own.ExclusiveWriter)
		}
	}
}

func TestWindowsWatchOwnedFilesClassifiesPerUserConnectorFiles(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	fixture := newWindowsGenericCodexFixture(t)
	fixture.opts.ConnectorName = "devin"
	fixture.opts.AgentVersion = "3000.4.25"
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{name: "devin", configPath: fixture.config})
	fixture.opts.Registry = registry

	own, err := WatchOwnedFiles(fixture.opts)
	if err != nil {
		t.Fatalf("per-user watch files: %v", err)
	}
	hook := filepath.Join(fixture.home, ".defenseclaw", "hooks", "codex-hook.sh")
	if !slices.Contains(own.ExclusiveWriter, hook) {
		t.Errorf("exclusive watch files omit %s: %v", hook, own.ExclusiveWriter)
	}
	if !slices.Contains(own.SharedWriter, fixture.config) || slices.Contains(own.ExclusiveWriter, fixture.config) {
		t.Errorf("agent config %s has the wrong writer class: %+v", fixture.config, own)
	}
}

func TestWindowsWatchOwnedFilesUsesMachinePolicyForCopilot(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	fixture := newWindowsGenericCodexFixture(t)
	fixture.opts.ConnectorName = "copilot"
	fixture.opts.AgentVersion = "1.0.76"
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{name: "copilot", configPath: fixture.config})
	fixture.opts.Registry = registry
	policyPath := filepath.Join(t.TempDir(), "policy.d", "90-defenseclaw.json")
	previous := windowsRuntimeOnlyPolicyPath
	windowsRuntimeOnlyPolicyPath = func(string) (string, error) { return policyPath, nil }
	t.Cleanup(func() { windowsRuntimeOnlyPolicyPath = previous })

	own, err := WatchOwnedFiles(fixture.opts)
	if err != nil {
		t.Fatalf("Copilot watch files: %v", err)
	}
	if !slices.Contains(own.ExclusiveWriter, policyPath) ||
		!slices.Contains(own.ExclusiveWriter, filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hook-copilot.token")) {
		t.Fatalf("machine policy or per-user runtime is missing: %+v", own)
	}
	if slices.Contains(own.ExclusiveWriter, fixture.config) || slices.Contains(own.SharedWriter, fixture.config) {
		t.Fatalf("machine-managed Copilot does not own the agent config %s: %+v", fixture.config, own)
	}
	dirs, err := WatchDirs(fixture.opts)
	if err != nil || !slices.Contains(dirs, filepath.Dir(policyPath)) {
		t.Fatalf("machine policy directory is not watched: %v, %v", dirs, err)
	}
}
