// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"gopkg.in/yaml.v3"
)

func commonConfigSource(t *testing.T, ta *testApp, body string) {
	t.Helper()
	version := "9"
	if strings.Contains(body, "profile: secure_client") {
		version = "8"
	}
	writeFile(t, ta.ConfigPath, "config_version: "+version+"\ndata_dir: "+ta.Cfg.DataDir+"\n"+body)
}

func commonConfigDocument(t *testing.T, ta *testApp) *yaml.Node {
	t.Helper()
	raw, err := os.ReadFile(ta.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := sandboxSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCommonSandboxTeardownTurnsMasterOff(t *testing.T) {
	ta := newTestApp(t, "")
	commonConfigSource(t, ta, "openshell: {enabled: false}\nsandbox:\n  enabled: true\n  runtime: openshell\n  runtimes: {openshell: {enabled: false}}\n  wrappers: [claudecode]\n")
	ta.Cfg = loadConfig(t, ta)
	if ta.Cfg.OpenShell.Enabled || !ta.sandboxesOn() {
		t.Fatal("teardown did not recognize the common master switch independently of the runtime lane")
	}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true, KeepImages: true}))
	if got := loadConfig(t, ta); got.SandboxEnabled() || got.OpenShell.Enabled || len(got.Sandbox.Wrappers) != 0 {
		t.Fatalf("teardown left sandboxes enabled: %+v", got.Sandbox)
	}
	has(t, ta.output(), "openshell.enabled is off", "teardown complete")
}

func TestCommonSandboxTeardownDoesNotReportOffAfterRefusal(t *testing.T) {
	ta := newTestApp(t, "")
	commonConfigSource(t, ta, "deployment_mode: managed_enterprise\nenterprise: {profile: standalone}\n")
	err := ta.runTeardown(bg, &teardownPlan{disable: true}, TeardownOptions{Yes: true})
	wantErr(t, err, "administrator-owned")
	lacks(t, ta.output(), "openshell.enabled is off", "teardown complete")
}

func TestCommonSandboxWritesFollowCurrentSourceAndMirrorOnlyIntendedLeaves(t *testing.T) {
	ta := newTestApp(t, "") // deliberately stale, legacy-only a.Cfg
	commonConfigSource(t, ta, "# operator note\nopenshell:\n  enabled: false\n  binary: /vendor/openshell\n  upstream_telemetry: false\n  workdir: {mode: copy, git_depth: 12}\n  egress: {allow: [old.example], block: [retained.example]}\nsandbox:\n  enabled: false\n  runtime: openshell\n  workdir: {mode: copy}\n  egress: {allow: [old.example]}\n")
	ta.ok(t, ta.patchConfig(map[string]any{
		"openshell.enabled": true, "openshell.workdir.mode": "mount",
		"openshell.egress.allow": []string{"new.example"}, "openshell.upstream_telemetry": true,
	}))
	root := commonConfigDocument(t, ta)
	for _, key := range []string{"sandbox.enabled", "sandbox.runtimes.openshell.enabled", "openshell.enabled", "openshell.upstream_telemetry"} {
		if node := sandboxSourceAt(root, key); node == nil || node.Value != "true" {
			t.Fatalf("%s = %+v; want true", key, node)
		}
	}
	for _, key := range []string{"sandbox.workdir.mode", "openshell.workdir.mode"} {
		if node := sandboxSourceAt(root, key); node == nil || node.Value != "mount" {
			t.Fatalf("%s = %+v; want mount", key, node)
		}
	}
	if sandboxSourceAt(root, "openshell.workdir.git_depth").Value != "12" || sandboxSourceAt(root, "openshell.binary").Value != "/vendor/openshell" || sandboxSourceAt(root, "sandbox.binary") != nil {
		t.Fatal("a shared leaf write replaced unrelated policy or moved vendor settings")
	}
	if got := loadConfig(t, ta); !slices.Equal(got.OpenShell.Egress.Allow, []string{"new.example"}) || !slices.Equal(got.OpenShell.Egress.Block, []string{"retained.example"}) {
		t.Fatalf("effective egress = %+v", got.OpenShell.Egress)
	}
}

func TestCommonSandboxPolicyListEditsUseCurrentLists(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Egress.Allow = []string{"stale.example"}
	ta.Cfg.OpenShell.Egress.Block = []string{"stale.example"}
	commonConfigSource(t, ta, "openshell:\n  enabled: true\n  egress: {allow: [first.example], block: [remove.example, keep.example]}\nsandbox:\n  enabled: true\n  runtime: openshell\n  runtimes: {openshell: {enabled: true}}\n  egress: {allow: [first.example], block: [remove.example, keep.example]}\n")
	ta.ok(t, ta.PolicyEdit(bg, "allow", []string{"second.example"}))
	ta.ok(t, ta.PolicyRemove(bg, "block", []string{"remove.example"}))
	got := loadConfig(t, ta).OpenShell.Egress
	if !slices.Equal(got.Allow, []string{"first.example", "second.example"}) || !slices.Equal(got.Block, []string{"keep.example"}) {
		t.Fatalf("current lists were lost or stale lists restored: %+v", got)
	}
	ta.ok(t, ta.patchConfig(map[string]any{"openshell.wrappers": []string{"codex"}}))
	root := commonConfigDocument(t, ta)
	if sandboxSourceAt(root, "sandbox.wrappers") == nil || sandboxSourceAt(root, "openshell.wrappers") != nil {
		t.Fatal("a new shared leaf was written to the legacy source")
	}
}

func TestCommonSandboxPolicyListEditRetainsInheritedLegacyEntries(t *testing.T) {
	ta := newTestApp(t, "")
	commonConfigSource(t, ta, "openshell:\n  enabled: true\n  egress: {block: [inherited.example]}\nsandbox: {enabled: false}\n")
	ta.ok(t, ta.PolicyEdit(bg, "block", []string{"new.example"}))
	ta.ok(t, ta.PolicyRemove(bg, "block", []string{"inherited.example"}))
	if got := loadConfig(t, ta).OpenShell.Egress.Block; !slices.Equal(got, []string{"new.example"}) {
		t.Fatalf("legacy fallback was not retained and edited: %v", got)
	}
}

func TestCommonSandboxWriteRefusalsLeaveBytesAndGeneration(t *testing.T) {
	for _, tc := range []struct {
		name, body, expect, want string
		update                   map[string]any
	}{
		{"axis enable", "sandbox: {enabled: false, runtime: axis}\n", "", "sandbox.runtime is axis", map[string]any{"openshell.enabled": true}},
		{"stale hash", "sandbox: {enabled: false, runtime: axis}\n", strings.Repeat("0", 64), "", map[string]any{"openshell.enabled": false}},
		{"standalone managed", "deployment_mode: managed_enterprise\nenterprise: {profile: standalone}\n", "", "administrator-owned", map[string]any{"openshell.enabled": false}},
		{"Secure Client managed", "deployment_mode: managed_enterprise\nenterprise: {profile: secure_client}\n", "", "administrator-owned", map[string]any{"openshell.enabled": false}},
		{"unrelated conflict", "openshell: {profile: strict}\nsandbox: {enabled: false, profile: balanced}\n", "", "conflicts", map[string]any{"openshell.wrappers": []string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "") // a.Cfg never learns the managed/common source
			commonConfigSource(t, ta, tc.body)
			before, _ := os.ReadFile(ta.ConfigPath)
			err := ta.patchConfigIf(tc.update, tc.expect)
			if tc.name == "stale hash" {
				if !errors.Is(err, configwrite.ErrConflict) {
					t.Fatalf("stale hash = %v; want ErrConflict", err)
				}
			} else {
				wantErr(t, err, tc.want)
			}
			after, _ := os.ReadFile(ta.ConfigPath)
			if string(after) != string(before) {
				t.Fatal("refused mutation changed source bytes")
			}
			if _, err := configwrite.ReadGenerationState(ta.ConfigPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused mutation created a generation: %v", err)
			}
		})
	}
}

func TestCommonSandboxSetupRefusesAXISBeforeExternalActions(t *testing.T) {
	ta := newTestApp(t, "")
	commonConfigSource(t, ta, "sandbox: {enabled: false, runtime: axis}\n")
	called := false
	ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { called = true; return nil }
	ta.Installer = func(func(*openshell.InstallPlan) (bool, error)) Installer { called = true; return nil }
	before, _ := os.ReadFile(ta.ConfigPath)
	err := ta.Setup(bg, SetupOptions{Yes: true, InstallOpenShell: true})
	wantErr(t, err, "sandbox.runtime is axis")
	if called || len(ta.gateway.planned) != 0 || ta.gateway.applied != 0 || ta.gateway.restarts != 0 {
		t.Fatal("AXIS-selected setup performed external OpenShell actions")
	}
	after, _ := os.ReadFile(ta.ConfigPath)
	if string(after) != string(before) {
		t.Fatal("AXIS-selected setup modified configuration")
	}
}

func TestCommonSandboxAbsentKeepsLegacyWrite(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.ok(t, ta.patchConfig(map[string]any{"openshell.enabled": false, "openshell.wrappers": []string{"codex"}}))
	if root := commonConfigDocument(t, ta); sandboxSourceAt(root, "sandbox") != nil || sandboxSourceAt(root, "openshell.enabled").Value != "false" {
		t.Fatal("a legacy-only write introduced the common namespace or ignored enablement")
	}
}

func TestCommonSandboxWriterCoversModeledPolicyFields(t *testing.T) {
	common := make(map[string]bool)
	model := reflect.TypeFor[config.SandboxConfig]()
	for i := 0; i < model.NumField(); i++ {
		field := model.Field(i)
		if !field.IsExported() {
			continue
		}
		key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if key == "enabled" || key == "runtime" || key == "runtimes" {
			continue
		}
		common[key] = true
		if !commonSandboxPolicySuffix(key) || !commonSandboxPolicySuffix(key+".nested") {
			t.Errorf("modeled shared policy field %s is missing from the sandbox writer", key)
		}
	}
	legacy := reflect.TypeFor[config.OpenShellConfig]()
	for i := 0; i < legacy.NumField(); i++ {
		key, _, _ := strings.Cut(legacy.Field(i).Tag.Get("yaml"), ",")
		if commonSandboxPolicySuffix(key) != common[key] {
			t.Errorf("legacy field %s has the wrong policy authority", key)
		}
	}
}
