// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP1919StartProcessDQKeepsNestedFindings (rel-1-0-10:GAP-1919): a
// Windows-host shell call Start-Process powershell -ArgumentList "... \`"c\`""
// whose command c holds a ; is read in statements cut at that ; (the POSIX
// reading), and the first statement is a PowerShell text that ends inside a
// string. Its host script reading keeps the findings of the command, as at
// 1.0.10 and T21b: the ps_unterminated diagnostic (T20 review P2-4) is lexical
// and does not stop a raise-only reading. Red at 06f1da5b94 (allow NONE).
func TestGAP1919StartProcessDQKeepsNestedFindings(t *testing.T) {
	bt := "\x60"
	psdq := strings.NewReplacer(bt, bt+bt, "$", bt+"$", "\"", "\\"+bt+"\"")
	inner := "New-ItemProperty -Path HKLM:\\Software\\Microsoft\\.NETFramework -Name ETWEnabled -Value 0 -PropertyType DWord -Force ; Write-Output done"
	cmd := "Start-Process powershell -ArgumentList \"" + psdq.Replace("-NoProfile -Command \""+inner+"\"") + "\" -Wait"
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg}
	r := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": cmd},
	})
	found := false
	for _, id := range r.RuleIDs {
		if id == "tamper.windows_telemetry_disable" {
			found = true
		}
	}
	if !found || r.Severity != "HIGH" {
		t.Fatalf("%q: severity %s rules %v, want HIGH with tamper.windows_telemetry_disable", cmd, r.Severity, r.RuleIDs)
	}
}
