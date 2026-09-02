// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func prepareProxyConnectorSwitchAuthorityFixture(
	t *testing.T,
	target string,
	opts *connector.SetupOpts,
) {
	t.Helper()
	if runtime.GOOS != "darwin" || target != "openhands" {
		return
	}
	if opts == nil {
		t.Fatal("proxy connector switch authority fixture received nil setup options")
	}

	opts.DataDir = testenv.PrivateTempDir(t)
	executableRoot := testenv.PrivateTempDir(t)
	executable := filepath.Join(executableRoot, "openhands")
	executableBody := []byte("OpenHands executable parity fixture\n")
	if err := os.WriteFile(executable, executableBody, 0o700); err != nil {
		t.Fatalf("write OpenHands fixture executable: %v", err)
	}
	digest := sha256.Sum256(executableBody)
	now := time.Now().UTC().Truncate(time.Second)
	receipt := map[string]any{
		"schema_version": 1,
		"updated_at":     now.Format(time.RFC3339),
		"selections": map[string]any{
			"openhands": map[string]any{
				"connector":          "openhands",
				"source":             "setup-selected",
				"executable":         executable,
				"raw_version":        "OpenHands CLI 1.16.0",
				"normalized_version": "1.16.0",
				"sha256":             fmt.Sprintf("%x", digest[:]),
				"selected_at":        now.Format(time.RFC3339),
				"expires_at":         now.Add(10 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("encode OpenHands setup authority fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(opts.DataDir, "agent_selection.json"), encoded, 0o600); err != nil {
		t.Fatalf("publish OpenHands setup authority fixture: %v", err)
	}
	opts.AgentVersion = "OpenHands CLI 1.16.0"
	opts.AgentExecutable = executable
}
