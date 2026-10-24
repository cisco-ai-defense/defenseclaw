// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// statusV2Host is an installed host with the published sample config
// (codex and claudecode), two enrolled accounts and the guardian's last
// reconcile: codex protected for both, claudecode failed for one.
func statusV2Host(t *testing.T, goos string) *testHost {
	t.Helper()
	h := newTestHost(t, goos)
	file := "linux-standalone.yaml"
	if goos == "darwin" {
		file = "macos-standalone.yaml"
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, readSampleConfig(t, file))}))
	home := "/home/"
	if goos == "darwin" {
		home = "/Users/"
	}
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
		"  - user: alice\n    uid: 1001\n    user_home: "+home+"alice\n    connector: codex\n    agent_version: 0.160.0\n"+
		"  - user: bob\n    uid: 1002\n    user_home: "+home+"bob\n    connector: codex\n    agent_version: 0.161.0\n"+
		"  - user: alice\n    uid: 1001\n    user_home: "+home+"alice\n    connector: claudecode\n    agent_version: 2.1.0\n")
	writeFreshLedger(t, h)
	state, _ := json.Marshal(map[string]any{"results": []map[string]any{
		{"user": "alice", "user_home": home + "alice", "connector": "codex", "ok": true},
		{"user": "bob", "user_home": home + "bob", "connector": "codex", "ok": true},
		{"user": "alice", "user_home": home + "alice", "connector": "claudecode", "ok": false, "error": "enterprise hooks: something failed"},
	}})
	if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
		t.Fatal(err)
	}
	return h
}

// installedConfig is the installed config as status loads it.
func installedConfig(t *testing.T, h *testHost) *config.Config {
	t.Helper()
	cfg, err := h.env.loadConfigCandidate([]byte(h.read(h.env.Layout.ConfigPath)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestStatusV2BlocksLinuxAndMacOS(t *testing.T) {
	schemas := contracttest.Compile(t)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := statusV2Host(t, goos)
			cfg := installedConfig(t, h)
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				document, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				schemas.Validate(t, "lifecycle-result.schema.json", document)
				for _, name := range []string{"alice", "bob", "1001", "/home", "/Users"} {
					if strings.Contains(string(mustJSON(t, map[string]any{"c": r.Connectors, "o": r.OpenShell, "i": r.Identity})), name) {
						t.Fatalf("%s: a status v2 block names %q:\n%s", action, name, document)
					}
				}
				codex, claude := r.Connectors["codex"], r.Connectors["claudecode"]
				if !codex.Enabled || codex.Detected == nil || !*codex.Detected || codex.HooksInstalled != enterprisestatus.HooksInstalledAll ||
					*codex.Targets != (enterprisestatus.ConnectorTargets{Total: 2, Protected: 2}) || strings.Join(codex.Versions, ",") != "0.160.0,0.161.0" {
					t.Fatalf("%s: codex = %+v", action, codex)
				}
				if claude.HooksInstalled != enterprisestatus.HooksInstalledNone || *claude.Targets != (enterprisestatus.ConnectorTargets{Total: 1, Failed: 1}) {
					t.Fatalf("%s: claudecode = %+v", action, claude)
				}
				// Honest values: what the hook renderer resolves (GAP-0037),
				// whatever the resolver answers on this branch.
				for name, state := range r.Connectors {
					if want := enterprisehooks.ManagedHookFailMode(cfg, name); state.EffectiveHookFailMode != want {
						t.Fatalf("%s: %s effective_hook_fail_mode %q, the renderer resolves %q", action, name, state.EffectiveHookFailMode, want)
					}
					if want := cfg.EffectiveGuardrailModeForConnector(name); state.EffectiveMode != want {
						t.Fatalf("%s: %s effective_mode %q, config resolves %q", action, name, state.EffectiveMode, want)
					}
				}
				if r.OpenShell == nil || r.OpenShell.Enabled || r.OpenShell.ReasonCode != enterprisestatus.CodeOpenShellDisabled {
					t.Fatalf("%s: openshell = %+v", action, r.OpenShell)
				}
				if r.Identity == nil || r.Identity.State == "" {
					t.Fatalf("%s: identity = %+v", action, r.Identity)
				}
			}
			// ensure keeps its document unchanged.
			if r := h.run(Options{Action: ActionEnsure}); r.Connectors != nil || r.OpenShell != nil || r.Identity != nil {
				t.Fatalf("ensure carries status v2 blocks: %+v %+v %+v", r.Connectors, r.OpenShell, r.Identity)
			}
		})
	}
}

// A shell that was already running can export HERMES_HOME after its process
// environment was captured. The guardian's healthy default-home receipt
// cannot prove what a later Hermes process launched from that shell reads.
func TestStatusAndVerifyDoNotCertifyManagedHermesSessionHome(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			file, home := "linux-standalone.yaml", "/home/alice"
			if goos == "darwin" {
				file, home = "macos-standalone.yaml", "/Users/alice"
			}
			raw := strings.Replace(string(readSampleConfig(t, file)), "    claudecode: {}", "    claudecode: {}\n    hermes: {}", 1)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(raw))}))
			writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
				"  - user: alice\n    uid: 1001\n    user_home: "+home+"\n    connector: hermes\n    agent_version: 0.21.0\n")
			writeFreshLedger(t, h)
			state, err := json.Marshal(map[string]any{"results": []map[string]any{{
				"user": "alice", "user_home": home, "connector": "hermes", "ok": true,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
				t.Fatal(err)
			}
			readiness := "defenseclaw-gateway enterprise hooks readiness --manifest " + h.env.Layout.ManifestPath + " --json"
			h.runner.replies = map[string]fakeReply{readiness: {result: CommandResult{Stdout: []byte(`{"ok":true,"scope":"machine_hook_registration","hermes_session_coverage":"not_covered","results":[{"connector":"hermes","ok":true}]}`)}}}
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				contracttest.Compile(t).ValidateValue(t, "lifecycle-result.schema.json", r)
				if got := r.Connectors["hermes"].HooksInstalled; got != enterprisestatus.HooksInstalledUnknown {
					t.Fatalf("%s certified Hermes hooks from a persistent-home receipt: %q", action, got)
				}
				if r.CoverageComplete || r.SecurityComplete {
					t.Fatalf("%s certified universal Hermes coverage: coverage=%t security=%t", action, r.CoverageComplete, r.SecurityComplete)
				}
				messages := messagesOf(r.Warnings, enterprisestatus.CodeStatusDetailUnavailable) +
					messagesOf(r.Errors, enterprisestatus.CodeStatusDetailUnavailable)
				if !strings.Contains(messages, "session-only HERMES_HOME") {
					t.Fatalf("%s did not name the unknown home: %q", action, messages)
				}
				if action == ActionVerify && (r.ExitCode != 0 || !r.OK) {
					t.Fatalf("registration proof was rejected even though coverage remains incomplete: errors=%+v", r.Errors)
				}
			}
			h.runner.replies[readiness] = fakeReply{err: errors.New("owned Hermes hook command is missing")}
			missing := h.run(Options{Action: ActionVerify})
			if missing.ExitCode == 0 || !strings.Contains(messagesOf(missing.Errors, codeVerify), "owned Hermes hook command is missing") {
				t.Fatalf("missing owned hook passed lifecycle verify: %+v", missing.Errors)
			}
			// A no-op ensure describes the same managed deployment without
			// status-v2 blocks. It must not certify coverage that verify rejects.
			ensure := h.run(Options{Action: ActionEnsure})
			if ensure.CoverageComplete || ensure.SecurityComplete || ensure.Connectors != nil {
				t.Fatalf("ensure certified Hermes or changed its result shape: coverage=%t security=%t connectors=%+v",
					ensure.CoverageComplete, ensure.SecurityComplete, ensure.Connectors)
			}
			if message := messagesOf(ensure.Warnings, enterprisestatus.CodeStatusDetailUnavailable); !strings.Contains(message, "session-only HERMES_HOME") {
				t.Fatalf("ensure did not name the unobservable home: %q", message)
			}
			if message := messagesOf(ensure.Warnings, enterprisestatus.CodeStatusDetailUnavailable); !strings.Contains(message, "NOT COVERED") {
				t.Fatalf("ensure did not label the Hermes limit: %q", message)
			}
			if len(audited) == 0 || audited[len(audited)-1].Connector != "hermes" ||
				audited[len(audited)-1].Reason != "session_only_hermes_home_unobservable" {
				t.Fatalf("ensure did not audit the managed Hermes coverage limit: %+v", audited)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// On a real host Codex and Claude Code are in vendor machine policy and get
// no per-user target: the block omits detected, versions and targets instead
// of reporting not detected and zero, and hooks_installed follows the
// machine policy (GAP-0002, GAP-0004).
func TestStatusV2MachinePolicyConnectorsWithoutRows(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := statusV2Host(t, goos)
			writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets: []\n")
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), []byte(`{"results":[]}`), 0o640); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionStatus})
			if len(r.MachinePolicy) == 0 {
				t.Fatalf("the fake host published no machine policy: %+v", r.MachinePolicy)
			}
			for name := range r.MachinePolicy {
				state, ok := r.Connectors[name]
				if !ok {
					t.Fatalf("%s is in machine policy but not in the connectors block: %+v", name, r.Connectors)
				}
				if state.Detected != nil || state.Versions != nil || state.Targets != nil ||
					state.HooksInstalled != enterprisestatus.HooksInstalledAll || state.ManagedHook == nil || !*state.ManagedHook {
					t.Fatalf("%s = %+v", name, state)
				}
			}
			contracttest.Compile(t).ValidateValue(t, "lifecycle-result.schema.json", r)
		})
	}
}

// A guardian state the root-only attestation does not vouch for (the
// service account can replace it) counts nothing: hooks_installed unknown.
func TestStatusV2UnattestedGuardianStateIsUnknown(t *testing.T) {
	h := statusV2Host(t, "linux")
	if err := os.Remove(h.env.attestationPath()); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionStatus})
	for name, state := range r.Connectors {
		if state.HooksInstalled != enterprisestatus.HooksInstalledUnknown || state.Targets != nil {
			t.Fatalf("%s = %+v", name, state)
		}
	}
	contracttest.Compile(t).ValidateValue(t, "lifecycle-result.schema.json", r)
}

// A version string an agent in a user home reports that is not a plain
// version is never printed; the warning only counts it.
func TestStatusV2DropsVersionsThatAreNotTokens(t *testing.T) {
	h := statusV2Host(t, "linux")
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
		"  - user: alice\n    uid: 1001\n    user_home: /home/alice\n    connector: codex\n    agent_version: \"0.160 /home/alice/x\"\n")
	r := h.run(Options{Action: ActionStatus})
	if got := r.Connectors["codex"].Versions; len(got) != 0 {
		t.Fatalf("versions = %v", got)
	}
	message := messagesOf(r.Warnings, enterprisestatus.CodeStatusDetailUnavailable)
	if !strings.Contains(message, "1 agent version(s) not shown") || strings.Contains(message, "/home/alice") {
		t.Fatalf("warning = %q", message)
	}
}

// The identity block comes from the same /health body status reads; a
// gateway that is not ready gives unknown/gateway_not_ready.
func TestStatusV2IdentityFromGatewayHealth(t *testing.T) {
	h := newTestHost(t, "linux")
	l := &lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: enterprisestatus.New(ActionStatus, "standalone", "linux", "1.0.3")}
	l.readGatewayPosture([]byte(`{"identity":{"sources":[{"source":"sssd","directory":"active_directory","last_ok_age_seconds":4}],"failing":0,"stale":0}}`))
	if got := l.result.Identity; got == nil || got.State != enterprisestatus.IdentityStateOK || len(got.Sources) != 1 {
		t.Fatalf("identity = %+v", got)
	}
	l.readGatewayPosture([]byte(`{"directory":{"failing":1}}`))
	if got := l.result.Identity; got.State != enterprisestatus.IdentityStateUnknown || got.ReasonCode != enterprisestatus.CodeGatewayDidNotReport {
		t.Fatalf("older gateway identity = %+v", got)
	}
	ensure := &lifecycle{env: h.env, opts: Options{Action: ActionEnsure}, result: enterprisestatus.New(ActionEnsure, "standalone", "linux", "1.0.3")}
	ensure.readGatewayPosture([]byte(`{"identity":{"sources":[],"failing":0,"stale":0}}`))
	if ensure.result.Identity != nil {
		t.Fatal("ensure carries the identity block")
	}
	notReady := &lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: enterprisestatus.New(ActionStatus, "standalone", "linux", "1.0.3")}
	notReady.describeStatusV2(nil)
	if got := notReady.result.Identity; got.State != enterprisestatus.IdentityStateUnknown || got.ReasonCode != enterprisestatus.CodeGatewayNotReady {
		t.Fatalf("not ready identity = %+v", got)
	}
}

// A live local audit-write failure makes managed enforcement incomplete even
// while the gateway and its hook socket remain healthy.
func TestStatusAndVerifyReportActiveGatewayAuditWriteFailure(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	for _, action := range []string{ActionStatus, ActionVerify} {
		baseline := h.run(Options{Action: action})
		if !baseline.SecurityComplete || hasWarning(baseline, codeAuditWriteFailed) {
			t.Fatalf("%s baseline: security_complete=%t warnings=%+v", action, baseline.SecurityComplete, baseline.Warnings)
		}
	}
	health := h.env.HealthGet
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		return 200, []byte(`{"api":{"state":"running"},"telemetry":{"state":"error","details":{"event_history_failure":"sqlite_write_failed","event_history_last_sqlite_class":"constraint_corrupt"}}}`), nil
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if result.SecurityComplete || !hasWarning(result, "audit_write_failed") {
			t.Fatalf("%s: security_complete=%t warnings=%+v, want the active audit failure", action, result.SecurityComplete, result.Warnings)
		}
		if message := messagesOf(result.Warnings, "audit_write_failed"); !strings.Contains(message, "sqlite_write_failed") || !strings.Contains(message, "constraint_corrupt") {
			t.Fatalf("%s: audit warning %q", action, message)
		}
	}
	h.env.HealthGet = health
	recovered := h.run(Options{Action: ActionStatus})
	if hasWarning(recovered, "audit_write_failed") {
		t.Fatalf("recovered status retained an active audit warning: %+v", recovered.Warnings)
	}
}

// Every combination of sandbox rows maps to one driver and reason code;
// details and fixes (which name paths) are never copied.
func TestOpenShellCapabilityMapping(t *testing.T) {
	ok := func(name, version string) prereqRow {
		return prereqRow{Name: name, OK: true, Detail: "/usr/bin/" + name, Version: version}
	}
	missing := func(name, code string) prereqRow {
		return prereqRow{Name: name, Detail: "/usr/bin/" + name + " missing", Fix: "fix", Code: code}
	}
	vm := openshellSettings{Enabled: true, Install: "prerequisite", Driver: "vm", Fallback: "docker"}
	docker := openshellSettings{Enabled: true, Install: "prerequisite", Driver: "docker"}
	setup := openshellSettings{Enabled: true, Install: "setup", Driver: "docker", Version: "0.0.36"}
	parts := []prereqRow{ok("openshell cli", "0.0.36"), ok("openshell gateway", "0.0.36"), ok("microvm driver", "0.0.36")}
	cases := []struct {
		name              string
		s                 openshellSettings
		primary, fallback []prereqRow
		want              enterprisestatus.OpenShellCapability
	}{
		{"vm ready", vm, append(parts, ok("kvm", "")), []prereqRow{ok("docker", "")},
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: boolRef(true), Version: "0.0.36", Driver: "vm", DriverAvailable: "vm"}},
		{"vm falls back to docker", vm, append(parts, missing("kvm", "")), []prereqRow{ok("docker", "")},
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: boolRef(true), Version: "0.0.36", Driver: "vm", DriverAvailable: "docker", ReasonCode: codeDriverFallback}},
		{"vm and fallback missing", vm, append(parts, missing("kvm", "")), []prereqRow{missing("docker", "")},
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: boolRef(true), Version: "0.0.36", Driver: "vm", DriverAvailable: "none", ReasonCode: codeOpenShellPrerequisite}},
		{"launcher conflict", docker, []prereqRow{ok("openshell cli", "0.0.36"), ok("openshell gateway", "0.0.36"), missing("launcher", codeLauncherConflict)}, nil,
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: boolRef(true), Version: "0.0.36", Driver: "docker", DriverAvailable: "none", ReasonCode: codeLauncherConflict}},
		{"parts disagree, pin refused", docker, []prereqRow{ok("openshell cli", "0.0.36"), {Name: "openshell gateway", Version: "0.0.35"}, ok("docker", "")}, nil,
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: boolRef(true), Driver: "docker", DriverAvailable: "none", ReasonCode: codeOpenShellPrerequisite}},
		{"not installed", docker, []prereqRow{missing("openshell cli", ""), missing("openshell gateway", ""), ok("docker", "")}, nil,
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: boolRef(false), Driver: "docker", DriverAvailable: "none", ReasonCode: codeOpenShellPrerequisite}},
		{"setup mode", setup, []prereqRow{ok("openshell pin", ""), ok("docker", "")}, nil,
			enterprisestatus.OpenShellCapability{Enabled: true, Install: "setup", Version: "0.0.36", Driver: "docker", DriverAvailable: "docker"}},
	}
	for _, tc := range cases {
		got := openShellCapability(tc.s, true, tc.primary, tc.fallback)
		if string(mustJSON(t, got)) != string(mustJSON(t, tc.want)) {
			t.Errorf("%s: got %s, want %s", tc.name, mustJSON(t, got), mustJSON(t, tc.want))
		}
		if strings.Contains(string(mustJSON(t, got)), "/usr/bin") {
			t.Errorf("%s: a row detail leaked: %s", tc.name, mustJSON(t, got))
		}
	}
	if got := openShellCapability(openshellSettings{}, false, nil, nil); got.Enabled || got.ReasonCode != enterprisestatus.CodeOpenShellDisabled {
		t.Fatalf("disabled = %+v", got)
	}
}

func boolRef(v bool) *bool { return &v }

// The docker row only says Docker is installed. On Linux a block that would
// report docker asks the engine: a stopped engine is driver_available none
// with openshell_prerequisite_missing and a warning (GAP-0006); a Mac is not
// asked (Docker Desktop runs per user).
func TestOpenShellCapabilityAsksTheDockerEngine(t *testing.T) {
	docker := openshellSettings{Enabled: true, Install: "setup", Driver: "docker", Version: "0.0.36"}
	vm := openshellSettings{Enabled: true, Install: "setup", Driver: "vm", Fallback: "docker", Version: "0.0.36"}
	rows := []prereqRow{{Name: "openshell pin", OK: true}, {Name: "docker", OK: true}}
	vmRows := []prereqRow{{Name: "openshell pin", OK: true}, {Name: "kvm"}}
	for _, tc := range []struct {
		name, goos     string
		s              openshellSettings
		primary        []prereqRow
		fallback       []prereqRow
		socket, answer bool
		want, reason   string
		asked          bool
	}{
		{"linux engine answers", "linux", docker, rows, nil, true, true, "docker", "", true},
		{"linux engine stopped", "linux", docker, rows, nil, true, false, "none", codeOpenShellPrerequisite, true},
		{"linux no engine socket", "linux", docker, rows, nil, false, true, "none", codeOpenShellPrerequisite, false},
		{"linux vm fallback, engine stopped", "linux", vm, vmRows, rows, true, false, "none", codeOpenShellPrerequisite, true},
		{"macOS is not asked", "darwin", docker, rows, nil, false, false, "docker", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, tc.goos)
			if tc.socket {
				writeHostFile(t, h, "/var/run/docker.sock", "")
			}
			asked := false
			h.env.DockerEngine = func(_ context.Context, socket string) error {
				asked = true
				if socket != h.env.P("/var/run/docker.sock") {
					t.Errorf("asked %s", socket)
				}
				if !tc.answer {
					return errors.New("connection refused")
				}
				return nil
			}
			l := &lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: enterprisestatus.New(ActionStatus, "standalone", tc.goos, "1.0.3")}
			l.noteOpenShellCapability(context.Background(), tc.s, true, tc.primary, tc.fallback)
			got := l.result.OpenShell
			if got.DriverAvailable != tc.want || got.ReasonCode != tc.reason || asked != tc.asked {
				t.Fatalf("openshell = %+v, asked %v", got, asked)
			}
			warned := messagesOf(l.result.Warnings, codeOpenShellPrerequisite) != ""
			if warned != (tc.want == "none") {
				t.Fatalf("warnings = %+v", l.result.Warnings)
			}
		})
	}
	// ensure does not ask.
	h := newTestHost(t, "linux")
	h.env.DockerEngine = func(context.Context, string) error { t.Fatal("ensure asked the engine"); return nil }
	l := &lifecycle{env: h.env, opts: Options{Action: ActionEnsure}, result: enterprisestatus.New(ActionEnsure, "standalone", "linux", "1.0.3")}
	l.noteOpenShellCapability(context.Background(), docker, true, rows, nil)
	if l.result.OpenShell != nil {
		t.Fatal("ensure carries the openshell block")
	}
}
