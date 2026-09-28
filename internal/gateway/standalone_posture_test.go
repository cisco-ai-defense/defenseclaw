// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// withRestoredManagedPosture restores the process-global posture flags that
// NewSidecar and a committed reload publish.
func withRestoredManagedPosture(t *testing.T) {
	t.Helper()
	priorAIDOnly := ManagedEnterpriseActive()
	priorHosted := managedServiceHosted.Load()
	t.Cleanup(func() {
		setManagedEnterpriseRedactionPosture(priorAIDOnly)
		setManagedServiceHosted(priorHosted)
	})
}

type profilePosture struct {
	name    string
	mode    string
	profile string
	// aidOnly is ManagedEnterpriseActive: local detectors off, AI Defense
	// the only decision-maker. Only the Secure Client profile runs it.
	aidOnly bool
	// hosted is "the gateway runs as a service account", so its own OS
	// identity is never an end user's.
	hosted bool
}

var profilePostures = []profilePosture{
	{name: "standalone", mode: managed.DeploymentModeManagedEnterprise, profile: managed.ProfileStandalone, aidOnly: false, hosted: true},
	{name: "secure client", mode: managed.DeploymentModeManagedEnterprise, profile: "", aidOnly: true, hosted: true},
	{name: "unmanaged", mode: string(config.DeploymentModeUnmanagedBYOD), profile: "", aidOnly: false, hosted: false},
}

func assertProfilePosture(t *testing.T, want profilePosture) {
	t.Helper()
	if got := ManagedEnterpriseActive(); got != want.aidOnly {
		t.Fatalf("%s: ManagedEnterpriseActive() = %t, want %t", want.name, got, want.aidOnly)
	}
	user := newLLMEventUser("", "", false)
	if want.hosted {
		if user.ID != "" || user.Name != "" || user.IDKind != "" {
			t.Fatalf("%s: an event without identity was attributed to the gateway's own account: %+v", want.name, user)
		}
		if home := daemonHomeForInventoryAttribution(); home != "" {
			t.Fatalf("%s: the gateway's own home %q was offered for inventory attribution", want.name, home)
		}
		return
	}
	if current, err := osuser.Current(); err == nil && current != nil && user.ID == "" {
		t.Fatalf("%s: an unmanaged gateway runs as its user and must fall back to that identity", want.name)
	}
}

// bootProfileSidecar constructs a Sidecar for posture through NewSidecar,
// starting from the opposite process posture so a constructor that skipped
// the wiring could not pass by accident.
func bootProfileSidecar(t *testing.T, posture profilePosture) *config.Config {
	t.Helper()
	dataDir := testenv.PrivateTempDir(t)
	store, err := audit.NewStore(filepath.Join(dataDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	cfg.DataDir = dataDir
	cfg.Gateway.DeviceKeyFile = filepath.Join(dataDir, "device.key")
	cfg.Guardrail.RulePackDir = installDefaultRulePackForDataDir(t, dataDir)
	cfg.DeploymentMode = posture.mode
	cfg.Enterprise.Profile = posture.profile
	setManagedEnterpriseRedactionPosture(!posture.aidOnly)
	setManagedServiceHosted(!posture.hosted)
	sidecar, err := NewSidecar(cfg, store, nil, nil)
	if err != nil || sidecar == nil {
		t.Fatalf("NewSidecar(%s) = %v", posture.name, err)
	}
	// Release what the constructor opened in the data dir so the temp dir
	// can be removed (Windows refuses to delete open files).
	t.Cleanup(func() {
		if svc := sidecar.aiDiscoverySnapshot(); svc != nil {
			_, _ = svc.CloseIfNeverStarted()
		}
		SetJudgeResponseStore(nil)
		_ = shutdownJudgeStore(sidecar.judgeStore)
		if sidecar.judgeBodyStore != nil {
			_ = sidecar.judgeBodyStore.Close()
		}
		if sidecar.webhooks != nil {
			sidecar.webhooks.Close()
		}
		sidecar.alertCancel()
	})
	return cfg
}

func TestNewSidecarPublishesTheProfilePosture(t *testing.T) {
	withRestoredManagedPosture(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	restoreRetainJudgeBodies(t)
	t.Setenv("DEFENSECLAW_RUN_ID", "profile-posture-test")

	for _, test := range profilePostures {
		t.Run(test.name, func(t *testing.T) {
			bootProfileSidecar(t, test)
			assertProfilePosture(t, test)
		})
	}
}

func TestConfigReloadPublishesTheProfilePosture(t *testing.T) {
	withRestoredManagedPosture(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)

	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nobservability: {}\n", fixture.dataDir))
	oldCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, raw)
	if err != nil {
		t.Fatalf("load reload fixture: %v", err)
	}
	fixture.sidecar.publishConfig(oldCfg)
	fixture.sidecar.router = routerWithDefaultRulePack(t)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		fixture.configPath,
		raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir},
	)
	if err != nil {
		t.Fatalf("compile observability plan: %v", err)
	}

	// The Secure Client candidate needs a managed AI Defense destination to
	// commit, so the reload side covers standalone and unmanaged; boot covers
	// all three profiles above.
	for _, test := range []profilePosture{profilePostures[0], profilePostures[2]} {
		t.Run(test.name, func(t *testing.T) {
			next := cloneConfig(oldCfg)
			next.DeploymentMode = test.mode
			next.Enterprise.Profile = test.profile
			next.Guardrail.Mode = "strict"
			setManagedEnterpriseRedactionPosture(!test.aidOnly)
			setManagedServiceHosted(!test.hosted)
			err := fixture.sidecar.applyConfigReloadSnapshot(
				context.Background(),
				fixture.sidecar.currentConfig(),
				next,
				ConfigDiff{Changed: []string{"guardrail"}},
				configReloadSource{sourceName: fixture.configPath, raw: raw, compiledV8: compiled},
			)
			if err != nil {
				t.Fatalf("apply %s reload: %v", test.name, err)
			}
			assertProfilePosture(t, test)
		})
	}
}

// TestStandaloneHookLaneBlocksOnTheLocalEngine drives the standalone posture
// through the real boot wiring and then the hook lane: the local engine must
// keep deciding with AI Defense unwired, and with AI Defense returning no
// verdict. Two harmless markers stand in for the local detectors: an
// administrator tool block (the static policy lane) and a rule-pack pattern
// (the process-wide scanner that ManagedEnterpriseActive switches off). The
// Secure Client posture, AI Defense only, is the reverse.
func TestStandaloneHookLaneBlocksOnTheLocalEngine(t *testing.T) {
	withRestoredManagedPosture(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	restoreRetainJudgeBodies(t)
	t.Setenv("DEFENSECLAW_RUN_ID", "standalone-local-engine-test")

	const (
		markerTool    = "dc_marker_tool"
		markerPattern = "dc_marker_standalone_4f2a91"
		markerRule    = "STANDALONE-MARKER"
	)
	hookServer := func(t *testing.T, posture profilePosture, inspector Inspector) *APIServer {
		t.Helper()
		cfg := bootProfileSidecar(t, posture)
		cfg.Guardrail.Mode = "action"
		if err := ApplyRulePackOverrides(secretOverridePack(markerRule, markerPattern)); err != nil {
			t.Fatal(err)
		}
		store, logger := testStoreAndLogger(t)
		if err := enforce.NewPolicyEngine(store).BlockToolForConnector(markerTool, "", "marker"); err != nil {
			t.Fatal(err)
		}
		a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
		if inspector != nil {
			a.SetCiscoInspector(inspector)
		}
		return a
	}
	blockedTool := func() *ToolInspectRequest {
		return &ToolInspectRequest{Tool: markerTool, Args: json.RawMessage(`{}`)}
	}
	patternWrite := func() *ToolInspectRequest {
		return &ToolInspectRequest{
			Tool: "write",
			Args: json.RawMessage(`{"path":"notes.txt","content":"value ` + markerPattern + `"}`),
		}
	}
	hasMarkerFinding := func(verdict *ToolInspectVerdict) bool {
		if verdict == nil {
			return false
		}
		for _, finding := range verdict.DetailedFindings {
			if finding.RuleID == markerRule {
				return true
			}
		}
		return false
	}

	for name, inspector := range map[string]Inspector{
		"ai defense unwired":    nil,
		"ai defense no verdict": &stubAIDInspector{verdict: nil},
	} {
		a := hookServer(t, profilePostures[0], inspector)
		if ManagedEnterpriseActive() || a.managedAIDOnly() {
			t.Fatalf("standalone, %s: boot published the Secure Client AI Defense-only posture", name)
		}
		if verdict := a.inspectToolPolicy(blockedTool()); verdict == nil || verdict.Action != "block" {
			t.Fatalf("standalone, %s: administrator tool block verdict = %+v, want block", name, verdict)
		}
		if verdict := a.inspectToolPolicy(patternWrite()); !hasMarkerFinding(verdict) {
			t.Fatalf("standalone, %s: rule-pack scanner did not run: %+v", name, verdict)
		}
	}

	aid := &stubAIDInspector{verdict: nil}
	a := hookServer(t, profilePostures[1], aid)
	if !ManagedEnterpriseActive() || !a.managedAIDOnly() {
		t.Fatal("Secure Client boot did not publish the AI Defense-only posture")
	}
	if verdict := a.inspectToolPolicy(blockedTool()); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("Secure Client with no AI Defense verdict = %+v, want allow (local detectors off)", verdict)
	}
	if verdict := a.inspectToolPolicy(patternWrite()); hasMarkerFinding(verdict) {
		t.Fatalf("Secure Client ran the local rule-pack scanner: %+v", verdict)
	}
}
