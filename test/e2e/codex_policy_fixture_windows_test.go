// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package e2e

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

const e2eCodexPolicyHelperEnv = "DEFENSECLAW_E2E_CODEX_POLICY_HELPER"

func runCodexPolicyFixtureIfRequested() (bool, int) {
	if os.Getenv(e2eCodexPolicyHelperEnv) != "1" ||
		len(os.Args) != 3 || os.Args[1] != "app-server" || os.Args[2] != "--stdio" {
		return false, 0
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	encoder := json.NewEncoder(os.Stdout)
	for requestCount := 0; requestCount < 8; requestCount++ {
		var request struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := decoder.Decode(&request); err != nil {
			return true, 65
		}
		switch request.Method {
		case "initialize":
			if request.ID != 1 || encoder.Encode(map[string]any{
				"id": request.ID, "result": map[string]any{},
			}) != nil {
				return true, 66
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
				return true, 67
			}
			return true, 0
		default:
			return true, 68
		}
	}
	return true, 69
}

func seedCodexPolicyFixture(t *testing.T, dataDir string, opts *connector.SetupOpts) {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve e2e test executable: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open e2e test executable: %v", err)
	}
	defer source.Close() //nolint:errcheck

	executable := filepath.Join(dataDir, "codex.exe")
	target, err := os.OpenFile(executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatalf("create native Codex e2e fixture: %v", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(target, hasher), source); err != nil {
		_ = target.Close()
		t.Fatalf("copy native Codex e2e fixture: %v", err)
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		t.Fatalf("sync native Codex e2e fixture: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("close native Codex e2e fixture: %v", err)
	}

	const rawVersion = "codex 0.144.3"
	resolution := connector.ResolveHookContract("codex", rawVersion)
	if resolution.Status != connector.HookCompatibilityKnown {
		t.Fatalf("Codex e2e fixture contract = %+v, want known", resolution)
	}
	entry := connector.HookContractLockEntry{
		Connector:              "codex",
		RawAgentVersion:        resolution.RawVersion,
		NormalizedAgentVersion: resolution.NormalizedVersion,
		AgentExecutable:        executable,
		AgentExecutableSource:  "setup-selected",
		AgentExecutableSHA256:  hex.EncodeToString(hasher.Sum(nil)),
		ContractID:             resolution.Contract.ContractID,
		CompatibilityStatus:    resolution.Status,
		CompatibilityReason:    resolution.Reason,
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	if err := connector.SaveHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("save protected Codex e2e evidence: %v", err)
	}
	opts.AgentVersion = entry.RawAgentVersion
	opts.AgentExecutable = entry.AgentExecutable
	opts.HookContractID = entry.ContractID
	t.Setenv(e2eCodexPolicyHelperEnv, "1")
}
