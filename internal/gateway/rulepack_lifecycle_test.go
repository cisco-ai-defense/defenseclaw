// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestNewSidecarRejectsInvalidGlobalRulePackBeforeClientConstruction(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	cfg.Guardrail.RulePackDir = invalidRulePackDir(t)
	// If rule-pack preflight regresses behind client construction, this
	// deliberately nonexistent key path will obscure the policy error.
	cfg.Gateway.DeviceKeyFile = t.TempDir() + "/missing-device-key"

	sidecar, err := NewSidecar(cfg, nil, nil, nil)
	if err == nil || sidecar != nil {
		t.Fatalf("NewSidecar = (%p, %v), want invalid global rule-pack failure", sidecar, err)
	}
	if !strings.Contains(err.Error(), "global rule pack") {
		t.Fatalf("NewSidecar error = %v, want global rule-pack context", err)
	}
}

func TestNewSidecarRejectsInvalidEffectiveSingleConnectorRulePack(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.RulePackDir = ""
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {RulePackDir: invalidRulePackDir(t)},
	}
	cfg.Gateway.DeviceKeyFile = t.TempDir() + "/missing-device-key"

	sidecar, err := NewSidecar(cfg, nil, nil, nil)
	if err == nil || sidecar != nil {
		t.Fatalf("NewSidecar = (%p, %v), want invalid connector rule-pack failure", sidecar, err)
	}
	if !strings.Contains(err.Error(), "connector codex rule pack") {
		t.Fatalf("NewSidecar error = %v, want connector-scoped rule-pack context", err)
	}
}

func TestNewSidecarJudgePreparationClosesClientOnlyOnFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Judge.Enabled = true

	failedClient := &Client{disconnCh: make(chan struct{})}
	judge, err := buildInitialSidecarJudge(failedClient, cfg, nil)
	if err == nil || judge != nil {
		t.Fatalf("failed judge preparation = judge:%v error:%v", judge, err)
	}
	if !failedClient.closed {
		t.Fatal("failed judge preparation left the construction-owned client open")
	}
	select {
	case <-failedClient.Disconnected():
	default:
		t.Fatal("failed judge preparation did not signal client shutdown")
	}

	successClient := &Client{disconnCh: make(chan struct{})}
	cfg.LLM.Model = "test-model"
	cfg.LLM.BaseURL = "http://127.0.0.1:11434/v1"
	judge, err = buildInitialSidecarJudge(successClient, cfg, mustLoadRulePack(t, ""))
	if err != nil || judge == nil {
		t.Fatalf("successful judge preparation = judge:%v error:%v", judge, err)
	}
	if successClient.closed {
		t.Fatal("successful judge preparation closed the client before Sidecar ownership transfer")
	}
	select {
	case <-successClient.Disconnected():
		t.Fatal("successful judge preparation signaled client shutdown")
	default:
	}
}

func TestNewSidecarLateFailurePreservesPublishedRulePackState(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	restoreRetainJudgeBodies(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() {
		setManagedEnterpriseRedactionPosture(priorManaged)
	})

	priorPatterns := &guardrail.LocalPatterns{
		Version:          1,
		Injection:        []string{"prior-injection"},
		InjectionRegexes: []string{`prior\s+injection`},
		PIIRequests:      []string{"prior-pii-request"},
		PIIDataRegexes:   []string{`prior-pii-\d+`},
		Secrets:          []string{"prior-secret"},
		Exfiltration:     []string{"prior-exfiltration"},
	}
	if err := ApplyRulePackOverrides(secretOverridePack("PRIOR-RULE", `prior_token`)); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLocalPatternsOverride(priorPatterns); err != nil {
		t.Fatal(err)
	}

	candidateDir := t.TempDir()
	writeRulePackFixtureFile(t, candidateDir, "rules/candidate.yaml", `version: 1
category: secret
rules:
  - id: CANDIDATE-RULE
    pattern: 'candidate_token'
    title: candidate rule
    severity: HIGH
    confidence: 0.9
    tags: [test]
`)
	writeRulePackFixtureFile(t, candidateDir, "rules/local-patterns.yaml", `version: 1
injection: [candidate-injection]
injection_regexes: ['candidate\s+injection']
pii_requests: [candidate-pii-request]
pii_data_regexes: ['candidate-pii-\d+']
secrets: [candidate-secret]
exfiltration: [candidate-exfiltration]
`)

	dataDir := t.TempDir()
	store, err := audit.NewStore(filepath.Join(dataDir, "audit.db"))
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blockedParent := filepath.Join(dataDir, "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	cfg.DataDir = dataDir
	cfg.Gateway.DeviceKeyFile = filepath.Join(dataDir, "device.key")
	cfg.Guardrail.RulePackDir = candidateDir
	cfg.Guardrail.RetainJudgeBodies = true
	cfg.JudgeBodiesDB = filepath.Join(blockedParent, "judge_bodies.db")

	sidecar, err := NewSidecar(cfg, store, nil, nil)
	if err == nil || sidecar != nil {
		t.Fatalf("late-failing constructor = sidecar:%v error:%v", sidecar, err)
	}

	if ids := findingIDs(ScanAllRules("prior_token", "exec")); !containsRuleID(ids, "PRIOR-RULE") {
		t.Fatalf("late failure replaced the prior global rule pack: findings=%v", ids)
	}
	if ids := findingIDs(ScanAllRules("candidate_token", "exec")); containsRuleID(ids, "CANDIDATE-RULE") {
		t.Fatalf("late failure published the rejected global rule pack: findings=%v", ids)
	}

	localPatternsMu.RLock()
	gotInjection := append([]string(nil), injectionPatterns...)
	gotInjectionRegexes := regexSources(injectionRegexes)
	gotPIIRequests := append([]string(nil), piiRequestPatterns...)
	gotPIIDataRegexes := regexSources(piiDataRegexes)
	gotSecrets := append([]string(nil), secretPatterns...)
	gotExfiltration := append([]string(nil), exfilPatterns...)
	localPatternsMu.RUnlock()
	if !reflect.DeepEqual(gotInjection, priorPatterns.Injection) ||
		!reflect.DeepEqual(gotInjectionRegexes, priorPatterns.InjectionRegexes) ||
		!reflect.DeepEqual(gotPIIRequests, priorPatterns.PIIRequests) ||
		!reflect.DeepEqual(gotPIIDataRegexes, priorPatterns.PIIDataRegexes) ||
		!reflect.DeepEqual(gotSecrets, priorPatterns.Secrets) ||
		!reflect.DeepEqual(gotExfiltration, priorPatterns.Exfiltration) {
		t.Fatalf(
			"late failure changed local patterns:\n injection=%v\n injection_regexes=%v\n pii_requests=%v\n pii_data_regexes=%v\n secrets=%v\n exfiltration=%v",
			gotInjection,
			gotInjectionRegexes,
			gotPIIRequests,
			gotPIIDataRegexes,
			gotSecrets,
			gotExfiltration,
		)
	}
}

func TestColdStartDefersMultiConnectorRulePacksToIsolatedSetup(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.RulePackDir = ""
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {RulePackDir: invalidRulePackDir(t)},
		"claudecode": {RulePackDir: invalidRulePackDir(t)},
	}

	rp, err := loadInitialSidecarRulePack(cfg)
	if err != nil {
		t.Fatalf("multi-connector cold-start global preflight: %v", err)
	}
	if rp == nil {
		t.Fatal("multi-connector cold-start returned no validated global pack")
	}
}

func TestRulePackCandidatePreflightChecksOnlyEnabledConnectorOverrides(t *testing.T) {
	disabled := false
	enabled := true
	invalidDir := invalidRulePackDir(t)
	cfg := config.DefaultConfig()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.RulePackDir = ""
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {Enabled: &disabled, RulePackDir: invalidDir},
		"claudecode": {Enabled: &enabled, RulePackDir: ""},
	}

	candidate, err := preflightSidecarRulePacks(cfg)
	if err != nil {
		t.Fatalf("disabled connector pack was incorrectly preflighted: %v", err)
	}
	if candidate == nil || candidate.active == nil || len(candidate.connectors) != 1 ||
		candidate.connectors["claudecode"] == nil {
		t.Fatalf("enabled candidate packs = %#v", candidate)
	}

	cfg.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{
		Enabled: &enabled, RulePackDir: invalidDir,
	}
	if _, err := preflightSidecarRulePacks(cfg); err == nil ||
		!strings.Contains(err.Error(), "connector codex rule pack") {
		t.Fatalf("enabled invalid connector preflight error = %v", err)
	}
}

func TestRulePackNeedsReloadTracksEffectiveActiveSingleConnector(t *testing.T) {
	singleConnectorConfig := func(connector, rulePackDir string) *config.Config {
		cfg := config.DefaultConfig()
		cfg.Guardrail.Enabled = true
		cfg.Guardrail.RulePackDir = "/global"
		cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
			connector: {RulePackDir: rulePackDir},
		}
		return cfg
	}

	t.Run("scoped pack A to B", func(t *testing.T) {
		oldCfg := singleConnectorConfig("codex", "/scoped/a")
		newCfg := singleConnectorConfig("codex", "/scoped/b")
		if !rulePackNeedsReload(oldCfg, newCfg) {
			t.Fatal("single-connector scoped rule-pack change did not require reload")
		}
	})

	t.Run("active connector A to B", func(t *testing.T) {
		oldCfg := singleConnectorConfig("codex", "/scoped/a")
		newCfg := singleConnectorConfig("claudecode", "/scoped/b")
		if !rulePackNeedsReload(oldCfg, newCfg) {
			t.Fatal("active single-connector rule-pack change did not require reload")
		}
	})
}

func TestSingleConnectorScopedRulePackReloadPublishesActiveCandidate(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() {
		setManagedEnterpriseRedactionPosture(priorManaged)
	})

	writePack := func(dir, id, pattern string) {
		writeRulePackFixtureFile(t, dir, "rules/scoped.yaml", fmt.Sprintf(`version: 1
category: secret
rules:
  - id: %s
    pattern: %q
    title: scoped reload fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`, id, pattern))
	}
	oldDir := t.TempDir()
	newDir := t.TempDir()
	writePack(oldDir, "SCOPED-A", `scoped_a_token`)
	writePack(newDir, "SCOPED-B", `scoped_b_token`)

	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	rulePackRaw := func(dir string) []byte {
		return []byte(fmt.Sprintf(
			"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\n  connectors:\n    codex:\n      rule_pack_dir: %q\nobservability: {}\n",
			fixture.dataDir,
			dir,
		))
	}
	oldRaw := rulePackRaw(oldDir)
	newRaw := rulePackRaw(newDir)
	oldCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, oldRaw)
	if err != nil {
		t.Fatalf("load old scoped rule-pack config: %v", err)
	}
	newCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, newRaw)
	if err != nil {
		t.Fatalf("load new scoped rule-pack config: %v", err)
	}
	fixture.sidecar.publishConfig(oldCfg)
	oldPack := mustLoadRulePack(t, oldDir)
	if err := ApplyRulePackOverrides(oldPack); err != nil {
		t.Fatalf("apply old scoped rule pack: %v", err)
	}
	fixture.sidecar.router = routerWithDefaultRulePack(t)
	fixture.sidecar.router.SetRulePack(oldPack)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, oldRaw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		fixture.configPath,
		newRaw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir},
	)
	if err != nil {
		t.Fatalf("compile new observability plan: %v", err)
	}

	err = fixture.sidecar.applyConfigReloadSnapshot(
		context.Background(),
		oldCfg,
		newCfg,
		ConfigDiff{Changed: []string{"guardrail"}},
		configReloadSource{
			sourceName: fixture.configPath,
			raw:        newRaw,
			compiledV8: compiled,
		},
	)
	if err != nil {
		t.Fatalf("apply scoped rule-pack reload: %v", err)
	}

	if ids := findingIDs(ScanAllRules("scoped_b_token", "exec")); !containsRuleID(ids, "SCOPED-B") {
		t.Fatalf("global scanner did not receive scoped candidate: findings=%v", ids)
	}
	if ids := findingIDs(ScanAllRules("scoped_a_token", "exec")); containsRuleID(ids, "SCOPED-A") {
		t.Fatalf("global scanner retained prior scoped pack: findings=%v", ids)
	}
	routerPack := fixture.sidecar.router.rulePack()
	if routerPack == nil || routerPack == oldPack {
		t.Fatal("router did not receive the new scoped rule-pack candidate")
	}
	foundRouterRule := false
	for _, ruleFile := range routerPack.RuleFiles {
		for _, rule := range ruleFile.Rules {
			if rule.ID == "SCOPED-B" {
				foundRouterRule = true
			}
		}
	}
	if !foundRouterRule {
		t.Fatal("router rule pack does not contain SCOPED-B")
	}
}

func TestConnectorRosterOnlyReloadRetiresRemovedPreviousManualConnector(t *testing.T) {
	// This helper snapshots and restores both global and connector rule
	// generations through t.Cleanup, including the GLOBAL-BEFORE override below.
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() {
		setManagedEnterpriseRedactionPosture(priorManaged)
	})

	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")

	oldRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\n  connectors:\n    codex: {}\n    claudecode: {}\nobservability: {}\n",
		fixture.dataDir,
	))
	newRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\n  connectors:\n    codex: {}\nobservability: {}\n",
		fixture.dataDir,
	))
	oldCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, oldRaw)
	if err != nil {
		t.Fatalf("load old rule-pack config: %v", err)
	}
	newCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, newRaw)
	if err != nil {
		t.Fatalf("load new rule-pack config: %v", err)
	}
	fixture.sidecar.publishConfig(oldCfg)
	fixture.sidecar.router = routerWithDefaultRulePack(t)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, oldRaw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		fixture.configPath,
		newRaw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir},
	)
	if err != nil {
		t.Fatalf("compile new observability plan: %v", err)
	}

	activeRouter := fixture.sidecar.router
	activeRouterPack := activeRouter.rulePack()
	if err := ApplyRulePackOverrides(secretOverridePack("GLOBAL-BEFORE", `global_before_token`)); err != nil {
		t.Fatal(err)
	}
	priorPatterns := &guardrail.LocalPatterns{
		Version:   1,
		Injection: []string{"roster-only-prior-pattern"},
	}
	if err := ApplyLocalPatternsOverride(priorPatterns); err != nil {
		t.Fatal(err)
	}
	mustApplyConnectorRulePack(t, "codex", secretOverridePack("OLD-CODEX", `old_codex_token`))
	mustApplyConnectorRulePack(t, "claudecode", secretOverridePack("OLD-CLAUDE", `old_claude_token`))

	// Exercise the connector-generation commit directly. Connector roster
	// restart classification is independent of this regression: a roster-only
	// candidate must still retire stale manual overlays when no router is
	// attached, without republishing the unchanged global rule pack, local
	// patterns, or the detached router's rule pack.
	fixture.sidecar.router = nil
	err = fixture.sidecar.applyConfigReloadSnapshot(
		context.Background(),
		oldCfg,
		newCfg,
		ConfigDiff{Changed: []string{"guardrail"}},
		configReloadSource{
			sourceName: fixture.configPath,
			raw:        newRaw,
			compiledV8: compiled,
		},
	)
	fixture.sidecar.router = activeRouter
	if err != nil {
		t.Fatalf("apply global rule-pack reload: %v", err)
	}

	ruleCategoriesMu.RLock()
	_, codexPresent := connectorRuleCategories["codex"]
	_, removedPresent := connectorRuleCategories["claudecode"]
	ruleCategoriesMu.RUnlock()
	if !codexPresent || removedPresent {
		t.Fatalf(
			"connector generation after reload: codex=%t removed claudecode=%t, want true/false",
			codexPresent,
			removedPresent,
		)
	}
	if containsRuleID(ruleIDsForConnector("codex", "old_codex_token"), "OLD-CODEX") ||
		!containsRuleID(ruleIDsForConnector("codex", "AKIAIOSFODNN7EXAMPLE"), "SEC-AWS-KEY") {
		t.Fatal("retained connector did not receive the candidate default generation")
	}
	if !containsRuleID(findingIDs(ScanAllRules("global_before_token", "exec")), "GLOBAL-BEFORE") {
		t.Fatal("roster-only reload replaced the unchanged global rule pack")
	}
	localPatternsMu.RLock()
	gotInjectionPatterns := append([]string(nil), injectionPatterns...)
	localPatternsMu.RUnlock()
	if !reflect.DeepEqual(gotInjectionPatterns, priorPatterns.Injection) {
		t.Fatalf("roster-only reload replaced local patterns: %v", gotInjectionPatterns)
	}
	if activeRouter.rulePack() != activeRouterPack {
		t.Fatal("roster-only reload replaced the detached router rule pack")
	}
}
