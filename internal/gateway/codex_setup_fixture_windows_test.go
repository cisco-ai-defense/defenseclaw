// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const codexSetupAppServerHelperEnv = "DEFENSECLAW_GATEWAY_CODEX_APP_SERVER_HELPER"

func stageCodexDiscoveryAuthorityFixture(
	_ *testing.T,
	_ string,
	_ connector.HookContractLockEntry,
) {
	// Windows tests deliberately prove that generic agent discovery is not
	// executable authority. Their caller persists the protected lock entry.
}

func TestMain(m *testing.M) {
	if os.Getenv(codexSetupAppServerHelperEnv) == "1" &&
		len(os.Args) == 3 && os.Args[1] == "app-server" && os.Args[2] == "--stdio" {
		os.Exit(runCodexSetupAppServerHelper())
	}
	os.Exit(m.Run())
}

func runCodexSetupAppServerHelper() int {
	if len(os.Args) != 3 || os.Args[1] != "app-server" || os.Args[2] != "--stdio" {
		return 64
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	encoder := json.NewEncoder(os.Stdout)
	for requestCount := 0; requestCount < 8; requestCount++ {
		var request struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := decoder.Decode(&request); err != nil {
			return 65
		}
		switch request.Method {
		case "initialize":
			if request.ID != 1 || encoder.Encode(map[string]any{
				"id": request.ID, "result": map[string]any{},
			}) != nil {
				return 66
			}
		case "initialized":
			// JSON-RPC notifications intentionally have no response.
		case "configRequirements/read":
			if request.ID != 2 || encoder.Encode(map[string]any{
				"id": request.ID,
				"result": map[string]any{
					"requirements": map[string]any{"allowManagedHooksOnly": false},
				},
			}) != nil {
				return 67
			}
			return 0
		default:
			return 68
		}
	}
	return 69
}

func prepareCodexSetupPolicyFixture(
	t *testing.T,
	dataDir string,
	opts *connector.SetupOpts,
) {
	t.Helper()
	entry := stageCodexExecutableEvidenceFixture(t, dataDir)
	if err := connector.SaveHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("save protected Codex executable evidence: %v", err)
	}
	opts.AgentVersion = entry.RawAgentVersion
	opts.AgentExecutable = entry.AgentExecutable
	opts.HookContractID = entry.ContractID
	t.Setenv(codexSetupAppServerHelperEnv, "1")
}
