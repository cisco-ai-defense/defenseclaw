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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
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

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
