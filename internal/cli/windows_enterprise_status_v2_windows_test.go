// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func fakeWindowsStatusV2(t *testing.T, in windowsEnterpriseStatusV2Inputs) {
	t.Helper()
	previous := windowsEnterpriseStatusV2Read
	windowsEnterpriseStatusV2Read = func() windowsEnterpriseStatusV2Inputs { return in }
	t.Cleanup(func() { windowsEnterpriseStatusV2Read = previous })
}

func windowsStatusV2Config() *config.Config {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Mode: "action"}, "amp": {HookFailMode: "open"}, "hermes": {}, "copilot": {},
	}
	return cfg
}

// A standalone Windows status reports the three blocks from the files Go
// reads; the fail mode is what the Windows hook renderer writes, and no block
// names an account or SID.
func TestWindowsStatusV2Blocks(t *testing.T) {
	cfg := windowsStatusV2Config()
	fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
		cfg: cfg,
		manifest: []enterprisestatus.ConnectorInstall{
			{Connector: "codex", Version: "0.160.0", Enabled: true}, {Connector: "amp", Version: "0.0.1760", Enabled: true},
		},
		unprotected:   []enterprisehooks.UnprotectedAgent{{User: `DCLAB\dcad-alice`, SID: "S-1-5-21-1-2-3-1103", Connector: "hermes", Version: "0.9.0"}},
		guardianKnown: true,
		guardian: []enterprisestatus.ConnectorTarget{
			{Connector: "codex", OK: true}, {Connector: "amp", Pending: true}, {Connector: "copilot", OK: true},
		},
		machinePolicy: func(name string) bool { return name == "copilot" },
		gatewayHealth: func() ([]byte, error) {
			return []byte(`{"identity":{"sources":[{"source":"windows_lsa","directory":"active_directory","last_ok_age_seconds":9}],"failing":0,"stale":0}}`), nil
		},
	})
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.3")
	result.Installed, result.InstalledVersion = true, "1.0.3"
	result.Readiness.Gateway = true
	result.MachinePolicy["codex"] = windowsEnterpriseMachinePolicy(true)
	applyWindowsEnterpriseStatusV2(result)
	result.Finish("windows", 0)

	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	contracttest.Compile(t).Validate(t, "lifecycle-result.schema.json", document)
	for _, leak := range []string{"dcad-alice", "S-1-5-21", "DCLAB"} {
		if strings.Contains(string(document), leak) {
			t.Fatalf("status names %q:\n%s", leak, document)
		}
	}
	for name, state := range result.Connectors {
		if want := enterprisehooks.ManagedHookFailMode(cfg, name); state.EffectiveHookFailMode != want {
			t.Fatalf("%s: effective_hook_fail_mode %q, the Windows renderer writes %q", name, state.EffectiveHookFailMode, want)
		}
	}
	if codex := result.Connectors["codex"]; codex.ManagedHook == nil || !*codex.ManagedHook || codex.HooksInstalled != "all" || codex.EffectiveMode != "action" {
		t.Fatalf("codex = %+v", codex)
	}
	if copilot := result.Connectors["copilot"]; copilot.ManagedHook == nil || !*copilot.ManagedHook {
		t.Fatalf("copilot (runtime-only) = %+v", copilot)
	}
	if amp := result.Connectors["amp"]; amp.ManagedHook == nil || *amp.ManagedHook || amp.Targets == nil || amp.Targets.Pending != 1 {
		t.Fatalf("amp = %+v", amp)
	}
	if hermes := result.Connectors["hermes"]; hermes.Detected == nil || !*hermes.Detected || strings.Join(hermes.Versions, ",") != "0.9.0" || hermes.HooksInstalled != enterprisestatus.HooksInstalledUnknown {
		t.Fatalf("hermes = %+v", hermes)
	}
	if result.SecurityComplete || result.CoverageComplete {
		t.Fatalf("unverified Hermes home reported complete coverage: security=%v coverage=%v", result.SecurityComplete, result.CoverageComplete)
	}
	if !strings.Contains(string(document), "session-only HERMES_HOME") {
		t.Fatalf("managed Hermes status omitted the unverified session home: %s", document)
	}
	if result.OpenShell == nil || result.OpenShell.ReasonCode != enterprisestatus.CodePlatformUnsupported || result.OpenShell.DriverAvailable != "none" {
		t.Fatalf("openshell = %+v", result.OpenShell)
	}
	if result.Identity == nil || result.Identity.State != enterprisestatus.IdentityStateOK || result.Identity.Sources[0].Source != "windows_lsa" {
		t.Fatalf("identity = %+v", result.Identity)
	}
}

// The session-only HERMES_HOME limit keeps coverage and security incomplete
// with a warning. It is not a verify error, so Setup /ensure of a verified
// managed Hermes deployment is not rolled back for it.
func TestWindowsVerifyV2ReportsUnobservableHermesSessionHomeAsIncomplete(t *testing.T) {
	cfg := windowsStatusV2Config()
	fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
		cfg: cfg,
		manifest: []enterprisestatus.ConnectorInstall{
			{Connector: "hermes", Version: "0.9.0", Enabled: true},
		},
		guardianKnown: true,
		guardian:      []enterprisestatus.ConnectorTarget{{Connector: "hermes", OK: true}},
	})
	result := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.4")
	result.Installed, result.CoverageComplete, result.SecurityComplete = true, true, true
	applyWindowsEnterpriseStatusV2(result)
	if code := result.Finish("windows", 0); code != 0 || !result.OK || len(result.Errors) != 0 ||
		result.SecurityComplete || result.CoverageComplete {
		t.Fatalf("unverified Hermes verify result: code=%d ok=%v errors=%+v security=%v coverage=%v",
			code, result.OK, result.Errors, result.SecurityComplete, result.CoverageComplete)
	}
	var warned string
	for _, warning := range result.Warnings {
		if warning.Code == enterprisestatus.CodeStatusDetailUnavailable {
			warned += warning.Message + "; "
		}
	}
	if !strings.Contains(warned, "session-only HERMES_HOME") ||
		result.Connectors["hermes"].HooksInstalled != enterprisestatus.HooksInstalledUnknown {
		t.Fatalf("unverified Hermes cause or coverage missing: warnings=%+v connector=%+v", result.Warnings, result.Connectors["hermes"])
	}
	// The unknown state publishes no targets: the lifecycle schema forbids them.
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	contracttest.Compile(t).Validate(t, "lifecycle-result.schema.json", document)
	if result.Connectors["hermes"].Targets != nil {
		t.Fatalf("unknown Hermes coverage kept targets: %+v", result.Connectors["hermes"])
	}
	// Ensure prints no block but cannot certify what verify refuses.
	ensure := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.4")
	ensure.Installed, ensure.CoverageComplete, ensure.SecurityComplete = true, true, true
	applyWindowsEnterpriseStatusV2(ensure)
	if code := ensure.Finish("windows", 0); code != 0 || ensure.SecurityComplete || ensure.CoverageComplete || ensure.Connectors != nil ||
		messagesWithCode(ensure.Warnings, enterprisestatus.CodeStatusDetailUnavailable) != 1 {
		t.Fatalf("ensure with unverified Hermes: code=%d security=%v coverage=%v connectors=%v warnings=%+v",
			code, ensure.SecurityComplete, ensure.CoverageComplete, ensure.Connectors, ensure.Warnings)
	}
}

func TestWindowsVerifyV2KeepsCompleteResultWhenHermesIsNotInstalled(t *testing.T) {
	// Keep the fixture limited to a connector whose hook process is not
	// separately known to fail open. This assertion is about Hermes absence.
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"amp": {}}
	fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
		cfg: cfg, guardianKnown: true,
	})
	result := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.4")
	result.Installed, result.CoverageComplete, result.SecurityComplete = true, true, true
	applyWindowsEnterpriseStatusV2(result)
	if code := result.Finish("windows", 0); code != 0 || !result.SecurityComplete || !result.CoverageComplete {
		t.Fatalf("absent Hermes changed a complete verify: code=%d security=%v coverage=%v", code, result.SecurityComplete, result.CoverageComplete)
	}
}

func TestWindowsStatusV2GatewayAndConfigFailures(t *testing.T) {
	health := 0
	fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
		configErr:     errors.New("parse config.yaml: bad"),
		manifestErr:   os.ErrNotExist,
		gatewayHealth: func() ([]byte, error) { health++; return nil, errors.New("connection refused") },
	})
	notReady := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.3")
	applyWindowsEnterpriseStatusV2(notReady)
	if health != 0 || notReady.Identity.ReasonCode != enterprisestatus.CodeGatewayNotReady {
		t.Fatalf("not ready: %d health reads, identity %+v", health, notReady.Identity)
	}
	if messagesWithCode(notReady.Warnings, enterprisestatus.CodeStatusDetailUnavailable) != 1 {
		t.Fatalf("warnings = %+v", notReady.Warnings)
	}
	ready := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.3")
	ready.Readiness.Gateway = true
	applyWindowsEnterpriseStatusV2(ready)
	if health != 1 || ready.Identity.ReasonCode != enterprisestatus.CodeGatewayDidNotReport {
		t.Fatalf("ready: %d health reads, identity %+v", health, ready.Identity)
	}
	ensure := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.3")
	applyWindowsEnterpriseStatusV2(ensure)
	if ensure.Connectors != nil || ensure.OpenShell != nil || ensure.Identity != nil {
		t.Fatal("ensure carries status v2 blocks")
	}
}

// Every action names the hook-process limit and lowers security_complete;
// only status and verify print the connectors block (ensure reported
// security_complete true where status and verify reported false).
func TestWindowsManagedCodexStatusAndVerifyShowHookProcessFailure(t *testing.T) {
	for _, action := range []string{"status", "verify", "ensure", "install", "repair", "upgrade"} {
		t.Run(action, func(t *testing.T) {
			cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action"}}
			fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{cfg: cfg})
			result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
			result.Installed, result.SecurityComplete = true, true
			applyWindowsEnterpriseStatusV2(result)
			if messagesWithCode(result.Warnings, "hook_process_fail_open") != 1 || result.SecurityComplete {
				t.Fatalf("%s warning=%v security_complete=%v", action, result.Warnings, result.SecurityComplete)
			}
			if published := result.Connectors != nil; published != (action == "status" || action == "verify") {
				t.Fatalf("%s connectors block published=%v", action, published)
			}
		})
	}
}

func messagesWithCode(messages []enterprisestatus.Message, code string) int {
	n := 0
	for _, message := range messages {
		if message.Code == code {
			n++
		}
	}
	return n
}
