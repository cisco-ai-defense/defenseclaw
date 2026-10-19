// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func sandboxReloadSource(dataDir, sandbox string) []byte {
	return []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\nobservability: {}\n%s\n", dataDir, sandbox))
}

func loadSandboxReloadConfig(t *testing.T, path, dataDir, sandbox string) *config.Config {
	t.Helper()
	cfg, err := loadRuntimeConfigCandidate(path, sandboxReloadSource(dataDir, sandbox))
	if err != nil {
		t.Fatalf("load sandbox config: %v", err)
	}
	return cfg
}

// Common policy reaches the existing listener lifecycle through its validated
// OpenShell projection. Metadata changes still belong to the config generation.
func TestSandboxCommonReloadClassification(t *testing.T) {
	const on = "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}}"
	const off = "sandbox: {enabled: false, runtime: openshell, runtimes: {openshell: {enabled: true}}}"
	const laneOff = "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: false}}}"
	for _, tc := range []struct {
		name, oldSource, newSource string
		rebind                     bool
	}{
		{"enable", off, on, true},
		{"disable", on, off, true},
		{"enable lane", laneOff, on, true},
		{"disable lane", on, laneOff, true},
		{"common off overrides legacy on", "openshell: {enabled: true}", "openshell: {enabled: true}\nsandbox: {enabled: false}", true},
		{"ingress port", on, "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}, ingress_port: 19971}", true},
		{"egress port", on, "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}, egress_port: 19972}", true},
		{"derived ingress port unchanged", on, "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}, ingress_port: 18971}", false},
		{"disabled ports", off, "sandbox: {enabled: false, ingress_port: 19971, egress_port: 19972}", false},
		{"policy only", on, "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}, profile: strict, egress: {block: [blocked.example]}}", false},
		{"stored runtime only", "sandbox: {enabled: false, runtime: auto}", "sandbox: {enabled: false, runtime: axis}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			oldCfg := loadSandboxReloadConfig(t, path, dir, tc.oldSource)
			newCfg := loadSandboxReloadConfig(t, path, dir, tc.newSource)
			diff := diffConfigs(oldCfg, newCfg)
			if !slices.Contains(diff.Changed, "sandbox") || len(diff.RestartRequired) != 0 {
				t.Fatalf("common sandbox diff = %+v, want hot sandbox change", diff)
			}
			if got := apiNeedsRestart(oldCfg, newCfg); got != tc.rebind {
				t.Fatalf("apiNeedsRestart = %v, want %v", got, tc.rebind)
			}
		})
	}
}

func TestSandboxCommonReloadPublishesMetadataOnlyChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	before := sandboxReloadSource(dir, "sandbox: {enabled: false, runtime: auto}")
	after := sandboxReloadSource(dir, "sandbox: {enabled: false, runtime: axis}")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := loadRuntimeConfigCandidate(path, before)
	if err != nil {
		t.Fatal(err)
	}
	applied := 0
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff, _ configReloadSource) error {
		applied++
		if !reflect.DeepEqual(oldCfg.OpenShell, newCfg.OpenShell) || !slices.Equal(diff.Changed, []string{"sandbox"}) || len(diff.RestartRequired) != 0 {
			t.Fatalf("metadata-only reload changed effective policy or restart class: %+v", diff)
		}
		return nil
	})
	// Prepare the exact initial compiler-derived paths without starting stores,
	// listeners, watchers or an audit fixture.
	baseline, source, err := mgr.loadStableCandidate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	mgr.current.Store(cloneConfig(baseline))
	mgr.bindInitialObservabilityV8Plan(source.compiledV8.Plan)
	mgr.appliedRaw = append([]byte(nil), before...)
	if err := os.WriteFile(path, after, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || mgr.gen.Load() != 1 || mgr.Current().SandboxDefaultRuntime() != "axis" || mgr.Current().OpenShell.Enabled {
		t.Fatalf("metadata was not published once: applied=%d generation=%d", applied, mgr.gen.Load())
	}
	if err := mgr.Reload(t.Context(), "test unchanged"); err != nil || applied != 1 || mgr.gen.Load() != 1 {
		t.Fatalf("unchanged source reapplied: err=%v applied=%d generation=%d", err, applied, mgr.gen.Load())
	}
}

func TestSandboxCommonReloadRejectsActiveAXISAndKeepsGeneration(t *testing.T) {
	t.Cleanup(clearGenerationBuildError)
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initial := loadSandboxReloadConfig(t, path, dir, "sandbox: {enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}}")
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		t.Fatal("active AXIS candidate reached apply")
		return nil
	})
	mgr.gen.Store(7)
	before := mgr.Current()
	raw := sandboxReloadSource(dir, "sandbox: {enabled: true, runtime: axis, runtimes: {axis: {enabled: true}}}")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err := mgr.Reload(t.Context(), "test")
	if err == nil || !strings.Contains(err.Error(), "AXIS runtime is not available") {
		t.Fatalf("active AXIS reload error = %v", err)
	}
	if mgr.gen.Load() != 7 || !reflect.DeepEqual(mgr.Current(), before) {
		t.Fatal("rejected AXIS candidate changed the current generation")
	}
}
