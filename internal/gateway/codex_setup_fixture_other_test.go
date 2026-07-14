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
	payload := map[string]any{
		"version": 3,
		"agents": map[string]any{
			"codex": map[string]any{
				"installed":   true,
				"version":     entry.RawAgentVersion,
				"binary_path": entry.AgentExecutable,
				"error":       "",
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal non-Windows Codex discovery fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), body, 0o600); err != nil {
		t.Fatalf("write non-Windows Codex discovery fixture: %v", err)
	}
}

func prepareCodexSetupPolicyFixture(
	_ *testing.T,
	_ string,
	_ *connector.SetupOpts,
) {
}
