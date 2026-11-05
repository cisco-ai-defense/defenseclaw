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

func TestGAP0554WindowsCurlPreservesPinnedGeneration(t *testing.T) {
	resetConnectorRuleCategories(t)
	mustApplyConnectorRulePack(t, "claudecode",
		secretOverridePack("GAP0554-FIXTURE", `gap0554_fixture_[a-f0-9]+`))
	generation := &Generation{activeRules: snapshotRulePackGeneration("")}
	bindRegisteredConnectorRules(generation)
	previous := registeredRuleGenerationOf(generation, "claudecode")
	if previous == nil {
		t.Fatal("missing registered connector generation")
	}
	defaults, err := compileRulePackCategories(nil)
	if err != nil {
		t.Fatal(err)
	}
	publishConnectorRulePackGeneration([]string{"claudecode"},
		map[string]*compiledRulePackCategories{"claudecode": defaults})

	t.Run("default connector labels", TestWindowsCurlActualConnectorToolLabels)
	if got := registeredRuleGenerationOf(generation, "claudecode"); got != previous {
		t.Fatal("fixture changed the pinned connector registration")
	}
}

func TestGAP0554WindowsCurlRestoresOriginalGenerationAfterRebind(t *testing.T) {
	resetConnectorRuleCategories(t)
	mustApplyConnectorRulePack(t, "claudecode",
		secretOverridePack("GAP0554-FIXTURE", `gap0554_fixture_[a-f0-9]+`))
	original := &Generation{activeRules: snapshotRulePackGeneration("")}
	bindRegisteredConnectorRules(original)
	pinned := registeredRuleGenerationOf(original, "claudecode")
	if pinned == nil {
		t.Fatal("missing registered connector generation")
	}

	var rebound *Generation
	var reboundRules *compiledRulePackCategories
	if !t.Run("default connector fixture", func(t *testing.T) {
		installDefaultProfileConnector(t, "claudecode")
		rebound = &Generation{activeRules: snapshotRulePackGeneration("")}
		bindRegisteredConnectorRules(rebound)
		reboundRules = registeredRuleGenerationOf(rebound, "claudecode")
		if reboundRules == nil || reboundRules == pinned {
			t.Fatal("missing rebound connector registration")
		}
	}) {
		return
	}
	if got := registeredRuleGenerationOf(original, "claudecode"); got != pinned {
		t.Fatal("fixture changed the original generation registration")
	}
	if got := registeredRuleGenerationOf(rebound, "claudecode"); got != reboundRules {
		t.Fatal("fixture changed the rebound generation registration")
	}
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
