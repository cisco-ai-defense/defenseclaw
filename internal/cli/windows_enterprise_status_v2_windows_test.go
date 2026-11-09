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
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
		if want := enterprisehooks.ManagedStatusHookFailMode(cfg, name, "windows", state.ManagedHook != nil && *state.ManagedHook); state.EffectiveHookFailMode != want {
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
	if !strings.Contains(string(document), "NOT COVERED") {
		t.Fatalf("managed Hermes status did not label unobservable coverage: %s", document)
	}
	if result.OpenShell == nil || result.OpenShell.ReasonCode != enterprisestatus.CodePlatformUnsupported || result.OpenShell.DriverAvailable != "none" {
		t.Fatalf("openshell = %+v", result.OpenShell)
	}
	if result.Identity == nil || result.Identity.State != enterprisestatus.IdentityStateOK || result.Identity.Sources[0].Source != "windows_lsa" {
		t.Fatalf("identity = %+v", result.Identity)
	}
}

// GAP-1433: the unobservable session-only home is reported NOT COVERED, never
// certified, and never a verify failure: lifecycle verify exits 0 with
// security incomplete, as on Linux and macOS. Public hooks verify still
// refuses to attest the home (GAP-0766). GAP-1593: the installed hooks keep
// coverage_complete true; the platform limit is a warning.
func TestWindowsVerifyV2ReportsUnobservableHermesSessionHomeNotCovered(t *testing.T) {
	previousAudit := windowsManagedHermesCoverageAudit
	checks := 0
	windowsManagedHermesCoverageAudit = func() error { checks++; return nil }
	t.Cleanup(func() { windowsManagedHermesCoverageAudit = previousAudit })
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
		result.SecurityComplete || !result.CoverageComplete {
		t.Fatalf("unverified Hermes verify result: code=%d ok=%v errors=%+v security=%v coverage=%v", code, result.OK, result.Errors, result.SecurityComplete, result.CoverageComplete)
	}
	if message := strings.Join(messagesOfCode(result.Warnings, enterprisestatus.CodeStatusDetailUnavailable), "\n"); !strings.Contains(message, "session-only HERMES_HOME") ||
		!strings.Contains(message, "NOT COVERED") ||
		result.Connectors["hermes"].HooksInstalled != enterprisestatus.HooksInstalledUnknown {
		t.Fatalf("unverified Hermes cause or coverage missing: warnings=%+v connector=%+v", result.Warnings, result.Connectors["hermes"])
	}
	if err := enterprisehooks.ManagedHermesSessionHomeAttestation("windows", "hermes", true, false); err == nil {
		t.Fatal("public coverage attestation certified a session-only Hermes home")
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
	ensure.Readiness.Gateway = true
	applyWindowsEnterpriseStatusV2(ensure)
	if code := ensure.Finish("windows", 0); code != 0 || ensure.SecurityComplete || !ensure.CoverageComplete || ensure.Connectors != nil ||
		messagesWithCode(ensure.Warnings, enterprisestatus.CodeStatusDetailUnavailable) != 1 {
		t.Fatalf("ensure with unverified Hermes: code=%d security=%v coverage=%v connectors=%v warnings=%+v",
			code, ensure.SecurityComplete, ensure.CoverageComplete, ensure.Connectors, ensure.Warnings)
	}
	if checks != 1 || !strings.Contains(ensure.Warnings[0].Message, "NOT COVERED") {
		t.Fatalf("ensure omitted Hermes coverage audit or reason: checks=%d warnings=%+v", checks, ensure.Warnings)
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

func messagesOfCode(messages []enterprisestatus.Message, code string) []string {
	var out []string
	for _, message := range messages {
		if message.Code == code {
			out = append(out, message.Message)
		}
	}
	return out
}

// cowork-1-0-8 GAP-0028: before any account enrolls, status counts the one
// machine-wide Claude Code drop-in, laid out as a standalone install leaves
// it (managed-settings.d\00-defenseclaw-version-floor.json and
// 90-defenseclaw.json rendered as the guardian renders it, the hook
// executable in BinDir). machine_policy.claudecode owns every hook in it,
// connectors.claudecode has its hooks installed from the machine policy and
// Cowork is configured; the attestation alone still sets effective_lock.
// With the drop-in gone all three say it is not in place.
func TestWindowsStatusV2CountsTheClaudeCodeDropInBeforeAnyAccountEnrolls(t *testing.T) {
	root := t.TempDir()
	programFiles, programData := filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData")
	layout, err := managed.StandaloneWindowsLayoutForRoots(programFiles, programData)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// A temp tree is not administrator-owned; the trust rules have their own tests.
	opts.SkipTrustChecks = true
	if err := os.MkdirAll(filepath.Dir(opts.HookBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.HookBinary, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := connector.NewClaudeCodeConnector().ManagedHookPolicy(connector.SetupOpts{
		APIAddr: "127.0.0.1:18970", HookFailMode: "closed", ManagedEnterprise: true,
		HookExecutable: opts.HookBinary, ClaudeAllowManagedHooksOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Hooks map[string][]struct {
			Hooks []json.RawMessage `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &rendered); err != nil {
		t.Fatal(err)
	}
	handlers := 0
	for _, groups := range rendered.Hooks {
		for _, group := range groups {
			handlers += len(group.Hooks)
		}
	}
	floor, err := enterprisepolicy.Export(opts, enterprisepolicy.ConnectorClaudeCode, "version-floor")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(programFiles, "ClaudeCode", "managed-settings.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dir, "90-defenseclaw.json")
	for path, data := range map[string][]byte{dropIn: body, filepath.Join(dir, "00-defenseclaw-version-floor.json"): floor} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	schemas := contracttest.Compile(t)
	status := func() *enterprisestatus.Result {
		fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
			cfg: cfg, guardianKnown: true,
			machinePolicyStates: func(_ *config.Config, names []string) (map[string]enterprisestatus.MachinePolicyState, error) {
				return windowsEnterpriseMachinePolicyStates(opts, names)
			},
		})
		result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.8")
		result.Installed, result.InstalledVersion = true, "1.0.8"
		result.MachinePolicy["claudecode"] = windowsEnterpriseMachinePolicy(false)
		applyWindowsEnterpriseStatusV2(result)
		// Nobody is enrolled: the guardian has no row, so zero targets,
		// which the lifecycle schema requires of a Windows entry whose
		// hooks_installed is known.
		if targets := result.Connectors["claudecode"].Targets; targets == nil || *targets != (enterprisestatus.ConnectorTargets{}) {
			t.Fatalf("connectors.claudecode.targets = %+v, want zero", targets)
		}
		result.Finish("windows", 0)
		document, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		schemas.Validate(t, "lifecycle-result.schema.json", document)
		return result
	}

	result := status()
	policy := result.MachinePolicy["claudecode"]
	if handlers == 0 || policy.OwnedEntries != handlers || policy.ForeignEntries != 0 || len(policy.Conflicts) != 0 || policy.EffectiveLock != "" {
		t.Fatalf("machine_policy.claudecode = %+v, want %d owned entries, no conflict and no attested lock", policy, handlers)
	}
	if state := result.Connectors["claudecode"]; state.HooksInstalled != enterprisestatus.HooksInstalledAll || state.ManagedHook == nil || !*state.ManagedHook {
		t.Fatalf("connectors.claudecode = %+v", state)
	}
	if result.Cowork == nil || !result.Cowork.Configured || result.Cowork.Reason != "" {
		t.Fatalf("cowork = %+v", result.Cowork)
	}

	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	result = status()
	if policy := result.MachinePolicy["claudecode"]; policy.OwnedEntries != 0 {
		t.Fatalf("machine_policy.claudecode without the drop-in = %+v", policy)
	}
	if state := result.Connectors["claudecode"]; state.HooksInstalled != enterprisestatus.HooksInstalledNone {
		t.Fatalf("connectors.claudecode without the drop-in = %+v", state)
	}
	if result.Cowork == nil || result.Cowork.Configured || result.Cowork.Reason != enterprisestatus.CoworkReasonMachinePolicyUnset {
		t.Fatalf("cowork without the drop-in = %+v", result.Cowork)
	}
}

// A machine policy that cannot be read is reported, not counted as empty
// coverage: the entry keeps owned_entries 0, status says why, and the
// connector's hooks_installed is unknown (not none, not all) with no targets,
// as the lifecycle schema wants of an unknown entry. Cowork stays not
// configured. A config that cannot be loaded is reported the same way.
func TestWindowsStatusV2ReportsAnUnreadableMachinePolicy(t *testing.T) {
	cfg := windowsStatusV2Config()
	cfg.Guardrail.Connectors["claudecode"] = config.PerConnectorGuardrailConfig{}
	for _, tc := range []struct {
		name, cause string
		cfg         *config.Config
	}{
		{"inspection fails", "access is denied", cfg},
		{"config not loaded", "the installed config could not be loaded", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
				cfg: tc.cfg, guardianKnown: true,
				machinePolicyStates: func(*config.Config, []string) (map[string]enterprisestatus.MachinePolicyState, error) {
					return nil, errors.New("access is denied")
				},
			})
			result := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.8")
			result.Installed = true
			result.MachinePolicy["codex"] = windowsEnterpriseMachinePolicy(true)
			result.MachinePolicy["claudecode"] = windowsEnterpriseMachinePolicy(true)
			applyWindowsEnterpriseStatusV2(result)
			if policy := result.MachinePolicy["codex"]; policy.OwnedEntries != 0 || policy.EffectiveLock != "enforce" {
				t.Fatalf("machine_policy.codex = %+v", policy)
			}
			found := false
			for _, warning := range result.Warnings {
				found = found || warning.Code == enterprisestatus.CodeStatusDetailUnavailable &&
					strings.Contains(warning.Message, "machine policy of claudecode, codex could not be read ("+tc.cause+")")
			}
			if !found {
				t.Fatalf("warnings = %+v", result.Warnings)
			}
			if tc.cfg == nil {
				return
			}
			for _, name := range []string{"codex", "claudecode"} {
				if state, ok := result.Connectors[name]; !ok || state.HooksInstalled != enterprisestatus.HooksInstalledUnknown || state.Targets != nil {
					t.Fatalf("connectors.%s = %+v (listed %v), want hooks_installed unknown and no targets", name, state, ok)
				}
			}
			if result.Cowork == nil || result.Cowork.Configured {
				t.Fatalf("cowork = %+v", result.Cowork)
			}
			result.Finish("windows", 0)
			document, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			contracttest.Compile(t).Validate(t, "lifecycle-result.schema.json", document)
		})
	}
}

// Before the guardian state exists the connectors block does not count the
// machine policy (a known hooks_installed on Windows carries the guardian's
// targets): hooks_installed is unknown, without targets.
func TestWindowsStatusV2MachinePolicyCoverageNeedsTheGuardianState(t *testing.T) {
	cfg := windowsStatusV2Config()
	cfg.Guardrail.Connectors["claudecode"] = config.PerConnectorGuardrailConfig{}
	fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
		cfg: cfg,
		machinePolicyStates: func(_ *config.Config, names []string) (map[string]enterprisestatus.MachinePolicyState, error) {
			return map[string]enterprisestatus.MachinePolicyState{"claudecode": {OwnedEntries: 9}}, nil
		},
	})
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.8")
	result.Installed = true
	result.MachinePolicy["claudecode"] = windowsEnterpriseMachinePolicy(true)
	applyWindowsEnterpriseStatusV2(result)
	if policy := result.MachinePolicy["claudecode"]; policy.OwnedEntries != 9 {
		t.Fatalf("machine_policy.claudecode = %+v", policy)
	}
	if state := result.Connectors["claudecode"]; state.HooksInstalled != enterprisestatus.HooksInstalledUnknown || state.Targets != nil {
		t.Fatalf("connectors.claudecode = %+v", state)
	}
	result.Finish("windows", 0)
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	contracttest.Compile(t).Validate(t, "lifecycle-result.schema.json", document)
}

// GAP-0856, GAP-0879. While a link sits at the machine-policy folder of Codex,
// Cursor or Claude Code, status and verify carry one named warning per
// connector with the command that removes it; no link, or no machine policy
// for the connector, carries none.
func TestWindowsStatusNamesALinkAtAVendorFolderOnce(t *testing.T) {
	previous := windowsEnterpriseVendorFolderLink
	t.Cleanup(func() { windowsEnterpriseVendorFolderLink = previous })
	links := map[string]string{
		"codex":      `C:\ProgramData\OpenAI\Codex`,
		"cursor":     `C:\ProgramData\Cursor`,
		"claudecode": `C:\Program Files\ClaudeCode\managed-settings.d`,
	}
	codes := map[string]string{"codex": "codex_machine_folder_link", "cursor": "cursor_machine_folder_link", "claudecode": "claudecode_machine_folder_link"}
	newResult := func(connectors ...string) *enterprisestatus.Result {
		result := &enterprisestatus.Result{Action: "status", MachinePolicy: map[string]enterprisestatus.MachinePolicyState{}}
		for _, name := range connectors {
			result.MachinePolicy[name] = windowsEnterpriseMachinePolicy(true)
		}
		return result
	}
	count := func(result *enterprisestatus.Result, code string) int {
		n := 0
		for _, warning := range result.Warnings {
			if warning.Code == code {
				n++
			}
		}
		return n
	}

	windowsEnterpriseVendorFolderLink = func(connectorName string) string { return links[connectorName] }
	result := newResult("codex", "cursor", "claudecode")
	noteWindowsEnterpriseVendorFolderLinks(result)
	noteWindowsEnterpriseVendorFolderLinks(result)
	for name, code := range codes {
		if count(result, code) != 1 {
			t.Fatalf("%s: the link was named %d times, want once: %+v", name, count(result, code), result.Warnings)
		}
	}
	for _, warning := range result.Warnings {
		var name string
		for connectorName, code := range codes {
			if warning.Code == code {
				name = connectorName
			}
		}
		if !strings.Contains(warning.Message, `cmd /c rmdir "`+links[name]+`"`) || !strings.Contains(warning.Message, "link only, not its target") {
			t.Fatalf("%s: the warning does not carry the fix: %s", name, warning.Message)
		}
	}

	result = newResult("claudecode")
	noteWindowsEnterpriseVendorFolderLinks(result)
	if count(result, codes["codex"]) != 0 || count(result, codes["cursor"]) != 0 || count(result, codes["claudecode"]) != 1 {
		t.Fatalf("only the connector with a machine policy is warned: %+v", result.Warnings)
	}

	windowsEnterpriseVendorFolderLink = func(string) string { return "" }
	result = newResult("codex", "cursor", "claudecode")
	noteWindowsEnterpriseVendorFolderLinks(result)
	if len(result.Warnings) != 0 {
		t.Fatalf("no link, but a warning: %+v", result.Warnings)
	}
}

// GAP-0650 (owner decision for 1.0.9): a requirements.toml a user holds open
// is a documented Windows platform limit. Status names the holder and says
// the enforced policy stays in place; a file nobody holds adds nothing.
func TestWindowsStatusV2NamesTheHolderOfTheCodexRequirements(t *testing.T) {
	const path = `C:\ProgramData\OpenAI\Codex\requirements.toml`
	for _, held := range []bool{true, false} {
		fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
			cfg: windowsStatusV2Config(),
			codexRequirementsHold: func() (string, []string, bool) {
				return path, []string{"codex.exe (PID 4242)"}, held
			},
		})
		result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.9")
		result.Installed, result.InstalledVersion = true, "1.0.9"
		applyWindowsEnterpriseStatusV2(result)
		found := ""
		for _, warning := range result.Warnings {
			if warning.Code == windowsCodexRequirementsHeldCode {
				found = warning.Message
			}
		}
		if !held {
			if found != "" {
				t.Fatalf("a requirements.toml nobody holds is reported held: %s", found)
			}
			continue
		}
		for _, want := range []string{path, "codex.exe (PID 4242)", "the enforced Codex policy stays in place", "the guardian applies it at its next pass, about a minute later", "a failed Setup run needs the administrator to run it again"} {
			if !strings.Contains(found, want) {
				t.Fatalf("held warning = %q, want %q", found, want)
			}
		}
	}
}

func TestWindowsEnterpriseStatusNamesTheLinkOfAPendingTransaction(t *testing.T) {
	previous := windowsEnterpriseVendorFolderLink
	t.Cleanup(func() { windowsEnterpriseVendorFolderLink = previous })
	links := map[string]string{
		"cursor":     `C:\ProgramData\Cursor`,
		"claudecode": `C:\Program Files\ClaudeCode`,
	}
	windowsEnterpriseVendorFolderLink = func(connectorName string) string { return links[connectorName] }
	count := func(result *enterprisestatus.Result) int {
		n := 0
		for _, warning := range result.Warnings {
			if warning.Code == "transaction_pending_link" {
				n++
			}
		}
		return n
	}

	// Not pending: the link is named by the machine-folder warning only.
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.9")
	noteWindowsEnterprisePendingTransactionLink(result)
	if count(result) != 0 {
		t.Fatalf("no pending transaction, but a pending-link warning: %+v", result.Warnings)
	}

	// Pending: each link is named with the pending state and the rmdir fix.
	result = enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.9")
	result.TransactionPending = true
	noteWindowsEnterprisePendingTransactionLink(result)
	if count(result) != 2 {
		t.Fatalf("pending with two links: %d warnings, want 2: %+v", count(result), result.Warnings)
	}
	for _, warning := range result.Warnings {
		for _, want := range []string{"transaction is pending", "stay stopped", "cmd /c rmdir \"", "link only, not its target"} {
			if !strings.Contains(warning.Message, want) {
				t.Fatalf("pending-link warning lacks %q: %s", want, warning.Message)
			}
		}
	}
	if !strings.Contains(result.Warnings[0].Message, `Cursor machine-policy folder`) || !strings.Contains(result.Warnings[1].Message, `Claude Code machine-policy folder`) {
		t.Fatalf("the links are not named by connector: %+v", result.Warnings)
	}

	// Pending, no link: nothing is added.
	windowsEnterpriseVendorFolderLink = func(string) string { return "" }
	result = enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.9")
	result.TransactionPending = true
	noteWindowsEnterprisePendingTransactionLink(result)
	if count(result) != 0 {
		t.Fatalf("no link, but a pending-link warning: %+v", result.Warnings)
	}
}
