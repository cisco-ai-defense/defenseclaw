// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func publishCodexSetupSelectionFixture(
	t *testing.T,
	dataDir string,
	opts connector.SetupOpts,
) {
	t.Helper()
	body, err := os.ReadFile(opts.AgentExecutable)
	if err != nil {
		t.Fatalf("read selected Codex fixture executable: %v", err)
	}
	digest := sha256.Sum256(body)
	resolution := connector.ResolveHookContract("codex", opts.AgentVersion)
	now := time.Now().UTC().Truncate(time.Second)
	receipt := map[string]interface{}{
		"schema_version": 1,
		"updated_at":     now.Format(time.RFC3339),
		"selections": map[string]interface{}{
			"codex": map[string]interface{}{
				"connector":          "codex",
				"source":             "setup-selected",
				"executable":         opts.AgentExecutable,
				"raw_version":        resolution.RawVersion,
				"normalized_version": resolution.NormalizedVersion,
				"sha256":             hex.EncodeToString(digest[:]),
				"selected_at":        now.Format(time.RFC3339),
				"expires_at":         now.Add(15 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("marshal Codex setup selection fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_selection.json"), append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("publish Codex setup selection fixture: %v", err)
	}
}
