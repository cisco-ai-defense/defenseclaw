// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-0825, GAP-0826: status and verify name the account and path of an
// asset the gateway could not scan or move to quarantine, while it is still
// in the folder.
func TestAdmissionIssuesAreStatusWarnings(t *testing.T) {
	dataDir := t.TempDir()
	present := filepath.Join(t.TempDir(), "crit-k")
	if err := os.MkdirAll(present, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"issues": []watcher.AdmissionIssue{
		{Type: "skill", Name: "crit-k", Path: present, Account: "DCLAB\\dcad-pw1", Kind: watcher.AdmissionNotQuarantined, Detail: "not enough space"},
		{Type: "skill", Name: "gone", Path: filepath.Join(dataDir, "gone"), Kind: watcher.AdmissionUnscanned},
		{Type: "mcp", Name: "notes", Path: "mcp:codex:notes", Kind: watcher.AdmissionUnscanned, Detail: "loopback"},
	}}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dataDir, watcher.AdmissionStateFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// GAP-0829: an enrolled user's Claude Code state the enumerator could not
	// read names the account and the file.
	guardian := filepath.Join(dataDir, "guardian")
	spool := enterprisehooks.ClaudeMCPSpoolDir(guardian)
	if err := os.MkdirAll(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	marker, _ := enterprisehooks.MarshalClaudeMCPSpoolUnreadable("S-1-5-21-1-1001", enterprisehooks.ClaudeStateUnreadable{
		User: "DCLAB\\dcw-std1", Home: `C:\Users\dcw-std1`, Path: `C:\Users\dcw-std1\.claude.json`, Reason: "access denied",
	})
	if err := os.WriteFile(filepath.Join(spool, "S-1-5-21-1-1001.json"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	result := &enterprisestatus.Result{}
	appendAdmissionIssueWarnings(result, dataDir, guardian)
	if len(result.Warnings) != 3 || result.Warnings[0].Code != "claude_state_unreadable" ||
		!strings.Contains(result.Warnings[0].Message, `DCLAB\dcw-std1 are blocked: the hook enumerator could not read C:\Users\dcw-std1\.claude.json`) ||
		result.Warnings[1].Code != "asset_not_quarantined" ||
		!strings.Contains(result.Warnings[1].Message, "DCLAB\\dcad-pw1 ("+present+")") ||
		result.Warnings[2].Code != "asset_not_scanned" || !strings.Contains(result.Warnings[2].Message, "MCP server notes") {
		t.Fatalf("warnings %+v", result.Warnings)
	}
}
