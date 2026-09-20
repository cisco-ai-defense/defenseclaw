// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func prepareOpenCodeSetupAuthorityFixture(t *testing.T, dataDir string) connector.SetupOpts {
	t.Helper()
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatalf("protect OpenCode fixture data directory: %v", err)
	}
	root := testenv.PrivateTempDir(t)
	executable := filepath.Join(root, "opencode.exe")
	body := []byte("MZ OpenCode 1.18.19 gateway fixture")
	if err := os.WriteFile(executable, body, 0o700); err != nil {
		t.Fatalf("write OpenCode fixture executable: %v", err)
	}
	digest := sha256.Sum256(body)
	now := time.Now().UTC().Truncate(time.Second)
	receipt := map[string]any{
		"schema_version": 1,
		"updated_at":     now.Format(time.RFC3339),
		"selections": map[string]any{
			"opencode": map[string]any{
				"connector":          "opencode",
				"source":             "setup-selected",
				"executable":         executable,
				"raw_version":        "1.18.19",
				"normalized_version": "1.18.19",
				"sha256":             fmt.Sprintf("%x", digest[:]),
				"selected_at":        now.Format(time.RFC3339),
				"expires_at":         now.Add(15 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("encode OpenCode setup authority fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_selection.json"), encoded, 0o600); err != nil {
		t.Fatalf("publish OpenCode setup authority fixture: %v", err)
	}
	previous := connector.OpenCodeExecutablePathOverride
	connector.OpenCodeExecutablePathOverride = executable
	t.Cleanup(func() { connector.OpenCodeExecutablePathOverride = previous })
	return connector.SetupOpts{
		DataDir:         dataDir,
		AgentVersion:    "1.18.19",
		AgentExecutable: executable,
		HookContractID:  "opencode-hooks-v1",
	}
}
