// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP0554WindowsCurlConnectorRuleIsolation(t *testing.T) {
	resetConnectorRuleCategories(t)
	mustApplyConnectorRulePack(t, "claudecode",
		secretOverridePack("GAP0554-FIXTURE", `gap0554_fixture_[a-f0-9]+`))
	t.Run("default connector labels", TestWindowsCurlActualConnectorToolLabels)
}

func TestGAP0554WindowsCurlConnectorRuleIsolationBenign(t *testing.T) {
	resetConnectorRuleCategories(t)
	mustApplyConnectorRulePack(t, "claudecode",
		secretOverridePack("GAP0554-FIXTURE", `gap0554_fixture_[a-f0-9]+`))
	installDefaultProfileConnector(t, "claudecode")

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	response := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": `cmd.exe /d /c "curl.exe https://docs.example.test/"`},
	})
	if response.Action != "allow" || response.RawAction != "allow" {
		t.Fatalf("action=%q raw_action=%q, want allow", response.Action, response.RawAction)
	}
}
