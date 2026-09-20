// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestCodeGuardPostLogVerdictUsesCanonicalRuleID(t *testing.T) {
	target := filepath.Join(t.TempDir(), "finding.py")
	privateValue := strings.Join([]string{"private", strings.Repeat("v", 32)}, "-")
	if err := os.WriteFile(target, []byte(`api_key = "`+privateValue+`"`), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(t.TempDir(), "empty-codeguard-rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		connector string
		scan      func(*APIServer) *ToolInspectVerdict
	}{
		{
			name: "codex", connector: "codex",
			scan: func(api *APIServer) *ToolInspectVerdict {
				return api.scanCodexChangedFiles(context.Background(), codexHookRequest{})
			},
		},
		{
			name: "claude-code", connector: "claudecode",
			scan: func(api *APIServer) *ToolInspectVerdict {
				return api.scanClaudeCodeChangedFiles(context.Background(), claudeCodeHookRequest{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, logger := testStoreAndV8Logger(t)
			cfg := &config.Config{
				Scanners: config.ScannersConfig{CodeGuard: rulesDir},
				ConnectorHooks: map[string]config.AgentHookConfig{
					test.connector: {ScanPaths: []string{target}},
				},
			}
			verdict := test.scan(&APIServer{scannerCfg: cfg, logger: logger})
			if verdict == nil || len(verdict.Findings) != 1 || verdict.Findings[0] != "CG-CRED-001" {
				t.Fatalf("post-log connector verdict lost canonical identity: %+v", verdict)
			}
		})
	}
}

func TestScanAPIResponseEnvelopeRetainsCanonicalFindingIdentity(t *testing.T) {
	result := &scanner.ScanResult{Findings: []scanner.Finding{{
		RuleID: "redacted.secret.id-0123456789abcdef.mac-fedcba9876543210", FindingOccurrenceID: "finding-occurrence",
		Severity: scanner.SeverityHigh, Title: "Secret finding",
	}}}
	encoded, err := json.Marshal(scanAPIResponseEnvelope(result))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result scanner.ScanResult `json:"result"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Result.Findings) != 1 ||
		envelope.Result.Findings[0].RuleID != result.Findings[0].RuleID ||
		envelope.Result.Findings[0].FindingOccurrenceID != result.Findings[0].FindingOccurrenceID {
		t.Fatalf("API response lost canonical finding identity: %s", encoded)
	}
}
