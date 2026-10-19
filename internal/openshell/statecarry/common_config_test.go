// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package statecarry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

const commonSandboxAfterSetup = `openshell:
  enabled: false
  upstream_telemetry: false
` + commonOnlySandboxAfterSetup

const commonOnlySandboxAfterSetup = `sandbox:
  enabled: true
  runtime: openshell
  runtimes:
    openshell: {enabled: true}
  harnesses: [codex]
  profile: strict
  workdir: {mode: copy}
`

func TestCarryCommonOnlySourceRefusesDestinationOpenShell(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	for _, tc := range []struct{ name, destination string }{
		{"legacy policy", "openshell: {egress: {allow: [old.example]}}\n"},
		{"vendor settings", "openshell: {binary: reviewed-openshell}\n"},
		{"common with legacy floor", "openshell: {admin: {allow_yolo: false}}\nsandbox: {enabled: false}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			live := newInstall(t, root, "live", tc.destination)
			left := newInstall(t, root, "left", commonOnlySandboxAfterSetup)
			plantSandboxState(t, live.data, "own-run", "own-binding")
			plantSandboxState(t, left.data, "source-run", "source-binding")
			if _, err := configwrite.Apply(context.Background(), live.config, []configwrite.Change{{Path: "guardrail.mode", Value: "action"}}, configwrite.Options{Actor: "cli:test"}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(live.config)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := os.ReadFile(configwrite.GenerationPath(live.config))
			if err != nil {
				t.Fatal(err)
			}
			beforeTree := tree(t, live.data)
			result, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
			if err == nil || result.Carried || !strings.Contains(err.Error(), "explicitly reconcile the sandbox policy") {
				t.Fatalf("common-only carry over openshell settings = %+v, %v; want reconciliation refusal", result, err)
			}
			after, configErr := os.ReadFile(live.config)
			afterGeneration, generationErr := os.ReadFile(configwrite.GenerationPath(live.config))
			if configErr != nil || generationErr != nil || string(after) != string(before) || string(afterGeneration) != string(generation) || !reflect.DeepEqual(tree(t, live.data), beforeTree) {
				t.Fatalf("refused carry changed destination config, generation or state: %v, %v", configErr, generationErr)
			}
		})
	}
}

func TestCarryCommonOnlySourceWithoutDestinationOpenShell(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	for _, destination := range []string{"", "sandbox: {enabled: false, profile: balanced}\n"} {
		t.Run(map[bool]string{false: "unconfigured", true: "common destination"}[destination != ""], func(t *testing.T) {
			root := t.TempDir()
			live := newInstall(t, root, "live", destination)
			left := newInstall(t, root, "left", commonOnlySandboxAfterSetup)
			plantSandboxState(t, left.data, "source-run", "source-binding")
			result, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
			if err != nil || !result.Carried {
				t.Fatalf("common-only carry without legacy settings = %+v, %v", result, err)
			}
			cfg, err := config.LoadRuntimeV8File(live.config)
			if err != nil || !cfg.SandboxRuntimeEnabled("openshell") || cfg.OpenShell.Profile != "strict" || len(cfg.OpenShell.Egress.Allow) != 0 {
				t.Fatalf("carried common policy differs from source: %+v, %v", cfg, err)
			}
			if !reflect.DeepEqual(tree(t, live.data), tree(t, left.data)) {
				t.Fatal("common-only setup state was not carried")
			}
			state, err := configwrite.ReadGenerationState(live.config)
			if err != nil || state.Generation != 1 {
				t.Fatalf("expected one configuration generation: %+v, %v", state, err)
			}
		})
	}
}

func TestCarryCommonSandboxPolicyAndVendorSettingsTogether(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	for _, commonDestination := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy destination", true: "common destination"}[commonDestination], func(t *testing.T) {
			root := t.TempDir()
			destination := "openshell: {enabled: false, profile: balanced}\n"
			if commonDestination {
				destination += "sandbox: {enabled: false, profile: balanced, runtime: auto}\n"
			}
			live := newInstall(t, root, "live", destination)
			left := newInstall(t, root, "left", commonSandboxAfterSetup)
			plantSandboxState(t, left.data, "common-run", "common-binding")
			res, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
			if err != nil || !res.Carried {
				t.Fatalf("Carry common setup = %+v, %v", res, err)
			}
			cfg, err := config.LoadRuntimeV8File(live.config)
			if err != nil || !cfg.SandboxEnabled() || !cfg.SandboxRuntimeEnabled("openshell") || cfg.OpenShell.Profile != "strict" || !reflect.DeepEqual(cfg.Sandbox.Harnesses, []string{"codex"}) {
				t.Fatalf("carried common setup = %+v, %v", cfg, err)
			}
			if !reflect.DeepEqual(tree(t, live.data), tree(t, left.data)) {
				t.Fatal("common setup state was not carried")
			}
			state, err := configwrite.ReadGenerationState(live.config)
			if err != nil || state.Generation != 1 {
				t.Fatalf("expected one atomic configuration generation: %+v, %v", state, err)
			}
		})
	}
}

func TestCarryRefusesLegacySourceOverCommonDestination(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	root := t.TempDir()
	live := newInstall(t, root, "live", "sandbox: {enabled: false, profile: strict}\n")
	plantSandboxState(t, live.data, "own-run", "own-binding")
	left := newInstall(t, root, "left", openShellAfterSetup)
	plantSandboxState(t, left.data, "legacy-run", "legacy-binding")
	accepted, err := configwrite.Apply(context.Background(), live.config, []configwrite.Change{{Path: "openshell.upstream_telemetry", Value: true}}, configwrite.Options{Actor: "cli:test"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(live.config)
	beforeTree := tree(t, live.data)
	_, err = Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
	if err == nil || !strings.Contains(err.Error(), "explicitly reconcile the sandbox policy") {
		t.Fatalf("legacy carry over common destination = %v; want explicit reconciliation refusal", err)
	}
	after, _ := os.ReadFile(live.config)
	state, stateErr := configwrite.ReadGenerationState(live.config)
	if string(after) != string(before) || !reflect.DeepEqual(tree(t, live.data), beforeTree) || stateErr != nil || state.Generation != accepted.Generation || state.ConfigSHA256 != accepted.SHA256 {
		t.Fatalf("refused carry changed destination configuration, state or generation: %+v, %v", state, stateErr)
	}
}

func TestCarryCommonMasterControlsSourceAndDestination(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	root := t.TempDir()
	left := newInstall(t, root, "left", "openshell: {enabled: true}\nsandbox: {enabled: false}\n")
	live := newInstall(t, root, "live", "")
	res, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
	if err != nil || res.Carried || !strings.Contains(res.Skipped, "sandboxes off") {
		t.Fatalf("common-disabled source = %+v, %v; want skipped", res, err)
	}
	if _, err := configwrite.ReadGenerationState(live.config); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("skipped carry created a generation: %v", err)
	}
	active := newInstall(t, root, "active", commonSandboxAfterSetup)
	legacy := newInstall(t, root, "legacy", openShellAfterSetup)
	res, err = Carry(context.Background(), Options{FromDataDir: legacy.data, FromConfig: legacy.config, DataDir: active.data, Config: active.config, OnlyIfUnset: true})
	if err != nil || res.Carried || !strings.Contains(res.Skipped, "setup of its own") {
		t.Fatalf("active common destination = %+v, %v; want skipped", res, err)
	}
}

func TestCarryOnlyIfUnsetRefusesLateEnablementAfterStateInstall(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	root := t.TempDir()
	live := newInstall(t, root, "live", "sandbox: {enabled: false, runtime: openshell, runtimes: {openshell: {enabled: true}}}\n")
	left := newInstall(t, root, "left", commonSandboxAfterSetup)
	plantSandboxState(t, left.data, "source-run", "source-binding")
	write(t, filepath.Join(live.data, "sandboxes", "cache", "own-state"), "keep", 0o600)
	beforeTree := tree(t, live.data)
	var concurrentBytes []byte
	var concurrentGeneration configwrite.GenerationState
	result, err := Carry(context.Background(), Options{
		FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config,
		OnlyIfUnset: true,
		afterInstall: func() error {
			if !reflect.DeepEqual(tree(t, live.data), tree(t, left.data)) {
				t.Fatal("test did not reach the post-install boundary")
			}
			if _, err := configwrite.Apply(context.Background(), live.config,
				[]configwrite.Change{{Path: "sandbox.enabled", Value: true}},
				configwrite.Options{Actor: "cli:test"}); err != nil {
				return err
			}
			var err error
			concurrentBytes, err = os.ReadFile(live.config)
			if err != nil {
				return err
			}
			concurrentGeneration, err = configwrite.ReadGenerationState(live.config)
			return err
		},
	})
	if err != nil || result.Carried || result.Skipped != liveSetupSkipped {
		t.Fatalf("late enablement = %+v, %v; want a clean skip", result, err)
	}
	after, readErr := os.ReadFile(live.config)
	generation, generationErr := configwrite.ReadGenerationState(live.config)
	if readErr != nil || generationErr != nil || string(after) != string(concurrentBytes) ||
		generation != concurrentGeneration || !reflect.DeepEqual(tree(t, live.data), beforeTree) {
		t.Fatalf("late refusal changed concurrent config, generation or own state: %v, %v", readErr, generationErr)
	}
}
