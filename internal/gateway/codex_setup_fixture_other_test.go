// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func stageCodexDiscoveryAuthorityFixture(
	t *testing.T,
	dataDir string,
	entry connector.HookContractLockEntry,
) {
	t.Helper()
	discoveryPath := filepath.Join(dataDir, "agent_discovery.json")
	payload := map[string]any{}
	if existing, err := os.ReadFile(discoveryPath); err == nil {
		if err := json.Unmarshal(existing, &payload); err != nil {
			t.Fatalf("parse existing non-Windows agent discovery fixture: %v", err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("read existing non-Windows agent discovery fixture: %v", err)
	}
	agents, ok := payload["agents"].(map[string]any)
	if !ok {
		agents = map[string]any{}
	}
	payload["version"] = 3
	payload["agents"] = agents
	agents["codex"] = map[string]any{
		"installed":   true,
		"version":     entry.RawAgentVersion,
		"binary_path": entry.AgentExecutable,
		"error":       "",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal non-Windows Codex discovery fixture: %v", err)
	}
	if err := os.WriteFile(discoveryPath, body, 0o600); err != nil {
		t.Fatalf("write non-Windows Codex discovery fixture: %v", err)
	}
}

func prepareCodexSetupPolicyFixture(
	_ *testing.T,
	_ string,
	_ *connector.SetupOpts,
) {
}
