// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsInstallLaneAgents is testdata/enterprise_install_lane/windows-agents.json,
// the agent version claims scripts/test-enterprise-windows-install.ps1
// stages in the CI runner account's profile.
type windowsInstallLaneAgents struct {
	Agents []struct {
		Connector string `json:"connector"`
		Package   string `json:"package"`
		Version   string `json:"version"`
	} `json:"agents"`
}

// TestWindowsInstallLaneAgentsEnrollClaudeCodeAndCodex keeps the Windows
// install lane's machine-policy checks meaningful. The hosted runner has
// neither agent, so the lane writes a package.json for each where the
// standalone enumerator probes a user's npm global packages. Standalone
// discovery must find every one of them and admit an enabled Claude Code and
// Codex row at exactly that version; otherwise the lane enrolls nobody and
// applies no machine policy.
func TestWindowsInstallLaneAgentsEnrollClaudeCodeAndCodex(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "enterprise_install_lane", "windows-agents.json"))
	if err != nil {
		t.Fatalf("read the lane's agent list: %v", err)
	}
	var lane windowsInstallLaneAgents
	if err := json.Unmarshal(body, &lane); err != nil {
		t.Fatalf("parse the lane's agent list: %v", err)
	}
	withStandaloneProcess(t, true)
	stubMachineWinGet(t, nil)

	home := t.TempDir()
	connectors := map[string]config.PerConnectorGuardrailConfig{}
	want := map[string]string{}
	for _, agent := range lane.Agents {
		// The lane's layout and body: <ProfileImagePath>\AppData\Roaming\npm\
		// node_modules\<package>\package.json holding {"name","version"}.
		directory := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", filepath.FromSlash(agent.Package))
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		manifest, err := json.Marshal(map[string]string{"name": agent.Package, "version": agent.Version})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "package.json"), append(manifest, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if version, reason := standaloneWindowsAgentVersionExplain(home, agent.Connector); version != agent.Version {
			t.Fatalf("standalone discovery of %s = %q (%s), want the lane's %s", agent.Connector, version, reason, agent.Version)
		}
		if ok, reason := windowsStandaloneRowAdmission(home, agent.Connector, agent.Version); !ok {
			t.Fatalf("standalone admission refuses the lane's %s %s: %s", agent.Connector, agent.Version, reason)
		}
		if err := requireWindowsEnterpriseStandaloneAgentFloor(agent.Connector, agent.Version); err != nil {
			t.Fatalf("the guardian's standalone floor refuses the lane's %s %s: %v", agent.Connector, agent.Version, err)
		}
		connectors[agent.Connector] = config.PerConnectorGuardrailConfig{}
		want[agent.Connector] = agent.Version
	}
	if len(want) != 2 || want["claudecode"] == "" || want["codex"] == "" {
		t.Fatalf("the lane enables Claude Code and Codex, but its agent list covers %v", want)
	}

	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	cfg := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Connectors: connectors},
	}
	manifest, err := EnumerateWindows(context.Background(), cfg, EnumerateOptions{})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	got := map[string]string{}
	for _, target := range manifest.Targets {
		if target.SID != testLocalUserSID || !target.IsEnabled() {
			t.Fatalf("unexpected row %+v, want enabled rows for the lane's account only", target)
		}
		got[target.Connector] = target.AgentVersion
	}
	if len(got) != len(want) {
		t.Fatalf("enumerated rows %v, want %v", got, want)
	}
	for name, version := range want {
		if got[name] != version {
			t.Fatalf("enumerated %s row at %q, want %q (rows %v)", name, got[name], version, got)
		}
	}
}
