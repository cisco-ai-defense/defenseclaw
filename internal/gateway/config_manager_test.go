// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestConfigManagerReloadAppliesAndPublishesSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")

	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	applied := false
	health := NewSidecarHealth()
	mgr := newConfigManagerWithSnapshot(path, initial, nil, health, "", func(_ context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff, source configReloadSource) error {
		applied = true
		if source.compiledV8 == nil || source.compiledV8.Plan == nil {
			t.Fatal("apply did not receive a compiled v8 source")
		}
		if oldCfg.Guardrail.Mode != "observe" || newCfg.Guardrail.Mode != "action" {
			t.Fatalf("apply saw mode %q -> %q", oldCfg.Guardrail.Mode, newCfg.Guardrail.Mode)
		}
		if !slices.Contains(diff.Changed, "guardrail") {
			t.Fatalf("diff changed = %v, want guardrail", diff.Changed)
		}
		return nil
	})

	writeConfigForManagerTest(t, path, dir, "action")
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !applied {
		t.Fatal("apply callback was not called")
	}
	if got := mgr.Current().Guardrail.Mode; got != "action" {
		t.Fatalf("current mode = %q, want action", got)
	}
	// Nothing needs a restart: restart_required is [] as on main, not null
	// (GAP-0109).
	if raw, _ := json.Marshal(health.Snapshot().Config.Details["restart_required"]); string(raw) != "[]" {
		t.Fatalf("restart_required = %s, want []", raw)
	}
}

func TestConfigWatcherErrorReconcilesBeforeChangingHealth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	health := NewSidecarHealth()
	mgr := newConfigManagerWithSnapshot(path, initial, nil, health, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		return nil
	})
	health.SetConfig(StateError, "permission denied", map[string]interface{}{"path": path})
	mgr.reconcileWatchError(context.Background(), os.ErrPermission)
	if got := health.Snapshot().Config; got.State != StateRunning || got.LastError != "" {
		t.Fatalf("readable config after a watcher error: %+v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mgr.reconcileWatchError(context.Background(), os.ErrPermission)
	if got := health.Snapshot().Config; got.State != StateError || !strings.Contains(got.LastError, path) {
		t.Fatalf("unreadable config after a watcher error: %+v", got)
	}
}

// GAP-0264: the startup reconcile does not parse, validate and compile
// config.yaml again while the file still holds the bytes the gateway booted
// from; once they changed it reloads.
func TestConfigManagerStartupReconcileSkipsAnUnchangedSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		return nil
	})
	loads := 0
	load := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, data []byte) (*config.Config, error) {
		loads++
		return load(source, data)
	}
	mgr.setStartupSource(path, raw)
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsw.Close() })
	if err := mgr.reconcileStartup(t.Context(), fsw); err != nil || loads != 0 {
		t.Fatalf("reconcile of the boot source: err %v, %d loads, want none", err, loads)
	}
	writeConfigForManagerTest(t, path, dir, "action")
	if err := mgr.reconcileStartup(t.Context(), fsw); err != nil || loads == 0 || mgr.Current().Guardrail.Mode != "action" {
		t.Fatalf("reconcile of a changed source: err %v, %d loads, mode %q", err, loads, mgr.Current().Guardrail.Mode)
	}
}

func TestConfigManagerReloadRejectsInvalidAndKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")

	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		t.Fatal("apply callback must not run for invalid config")
		return nil
	})
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	mgr.bindObservabilityV8(runtime)

	raw := "config_version: 8\n" +
		"data_dir: " + dir + "\n" +
		"deployment_mode: invalid\n" +
		"guardrail:\n" +
		"  mode: observe\n" +
		"observability: {}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if err := mgr.Reload(context.Background(), "test"); err == nil {
		t.Fatal("reload succeeded with invalid deployment_mode")
	}
	if got := mgr.Current().Guardrail.Mode; got != "observe" {
		t.Fatalf("current mode changed to %q after failed reload", got)
	}
	metrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawConfigLoadErrors,
	)
	if len(metrics) != 1 || metrics[0].Attributes()["defenseclaw.metric.error_type"] != "candidate_invalid" {
		t.Fatalf("invalid reload config metrics=%v", metrics)
	}
}

func TestConfigManagerV8ReloadCompilesAndPassesExactStableSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initialRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	nextRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability:\n  local:\n    retention_days: 30\n")
	applied := false
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(_ context.Context, _, next *config.Config, diff ConfigDiff, source configReloadSource) error {
			applied = true
			if source.sourceName != path || !bytes.Equal(source.raw, nextRaw) {
				t.Fatalf("source snapshot = %q/%q", source.sourceName, source.raw)
			}
			if source.compiledV8 == nil || source.compiledV8.Plan == nil ||
				source.compiledV8.Plan.Snapshot().Local.RetentionDays != 30 {
				t.Fatalf("compiled source = %+v", source.compiledV8)
			}
			if next.DataDir != dir || next.AuditDB != filepath.Join(dir, config.DefaultAuditDBName) ||
				next.JudgeBodiesDB != filepath.Join(dir, config.DefaultJudgeBodiesDBName) {
				t.Fatalf("projected paths = data=%q audit=%q judge=%q", next.DataDir, next.AuditDB, next.JudgeBodiesDB)
			}
			if !slices.Contains(diff.Changed, "observability") {
				t.Fatalf("changed = %v, missing canonical plan change", diff.Changed)
			}
			return nil
		},
	)
	if err := os.WriteFile(path, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	// The config_version 8 file reloads as its in-memory v9 migration.
	if !applied || mgr.gen.Load() != 1 || mgr.Current().ConfigVersion != config.ConfigVersionV9 {
		t.Fatalf("applied/gen/version = %t/%d/%d", applied, mgr.gen.Load(), mgr.Current().ConfigVersion)
	}
	if got, want := version.Current().ContentHash, configContentHashForTest(nextRaw); got != want {
		t.Fatalf("successful reload content hash = %q, want %q", got, want)
	}
}

// A destination key written to .env after the gateway started resolves when
// the config that references it reloads (GAP-0017).
func TestConfigManagerReloadReadsDotEnvKeysAddedSinceStart(t *testing.T) {
	const keyName = "P0_RELOAD_DEST_KEY"
	t.Setenv(keyName, "")
	os.Unsetenv(keyName)
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initialRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	config.RegisterDotEnvLoader(func(string) { os.Setenv(keyName, "from-dotenv") })
	t.Cleanup(func() { config.RegisterDotEnvLoader(nil) })
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			return nil
		},
	)
	withDestination := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability:\n  destinations:\n" +
		"    - name: remote\n      kind: otlp\n      endpoint: https://otel.example.test\n" +
		"      headers:\n        Authorization: {env: " + keyName + "}\n")
	if err := os.WriteFile(path, withDestination, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload with a key that is only in .env: %v", err)
	}
}

func TestConfigManagerV8ReloadRejectsInvalidSourceBeforeApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initialRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initialHash := version.Current().ContentHash
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			t.Fatal("invalid v8 source reached apply")
			return nil
		},
	)
	invalid := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability:\n  destinationz: []\n")
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "test"); err == nil || !strings.Contains(err.Error(), "destinationz") {
		t.Fatalf("invalid v8 reload error = %v", err)
	}
	if mgr.gen.Load() != 0 || mgr.Current().ConfigVersion != 8 {
		t.Fatalf("invalid reload published generation/config = %d/%d", mgr.gen.Load(), mgr.Current().ConfigVersion)
	}
	if got := version.Current().ContentHash; got != initialHash {
		t.Fatalf("rejected reload changed content hash from %q to %q", initialHash, got)
	}
}

func TestConfigManagerApplyFailureDoesNotPublishCandidateProvenance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initialRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initialHash := version.Current().ContentHash
	wantErr := errors.New("candidate rejected")
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			return wantErr
		},
	)
	nextRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability:\n  local:\n    retention_days: 30\n")
	if err := os.WriteFile(path, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "test"); !errors.Is(err, wantErr) {
		t.Fatalf("apply error = %v", err)
	}
	if got := version.Current().ContentHash; got != initialHash {
		t.Fatalf("apply failure changed content hash from %q to %q", initialHash, got)
	}
}

func TestConfigManagerAcceptedNoOpPublishesSnapshotProvenance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	raw := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		path, raw, config.ObservabilityV8CompileOptions{DefaultDataDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, compiled.Plan.Digest(), nil)
	mgr.bindInitialObservabilityV8Plan(compiled.Plan)
	version.SetContentHash([]byte("unrelated prior provenance"))
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if got, want := version.Current().ContentHash, configContentHashForTest(raw); got != want {
		t.Fatalf("no-op reload content hash = %q, want %q", got, want)
	}
}

func TestConfigManagerManagedNoOpUsesEffectiveGeneratedPlan(t *testing.T) {
	for _, test := range []struct {
		name              string
		rawEndpoint       string
		effectiveEndpoint func(t *testing.T) string
	}{
		{
			name: "default endpoint",
			effectiveEndpoint: func(*testing.T) string {
				return config.DefaultConfig().CiscoAIDefense.Endpoint
			},
		},
		{
			name:        "environment-resolved endpoint overrides source",
			rawEndpoint: "https://raw-source.example.test",
			effectiveEndpoint: func(t *testing.T) string {
				t.Setenv("TEST_DEFENSECLAW_MANAGED_AID_ENDPOINT", "https://effective-env.example.test")
				return os.Getenv("TEST_DEFENSECLAW_MANAGED_AID_ENDPOINT")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			raw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
			if test.rawEndpoint != "" {
				raw = []byte("config_version: 8\ndata_dir: " + dir +
					"\ncisco_ai_defense:\n  endpoint: " + test.rawEndpoint + "\nobservability: {}\n")
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			effectiveEndpoint := test.effectiveEndpoint(t)
			initial.DeploymentMode = "managed_enterprise"
			initial.CiscoAIDefense.Endpoint = effectiveEndpoint

			compiled, err := config.ParseCompileObservabilityV8(
				path, raw, config.ObservabilityV8CompileOptions{DefaultDataDir: dir},
			)
			if err != nil {
				t.Fatal(err)
			}
			active, err := config.WithObservabilityV8ManagedAIDDestination(
				compiled.Plan,
				sidecarObservabilityV8ManagedOptionsFromConfig(initial, raw),
			)
			if err != nil {
				t.Fatal(err)
			}
			applyCalls := 0
			mgr := newConfigManagerWithSnapshot(
				path, initial, nil, nil, active.Digest(),
				func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
					applyCalls++
					return nil
				},
			)
			mgr.bindInitialObservabilityV8Plan(active)
			loadSnapshot := mgr.loadSnapshot
			// loadSnapshot represents the already-defaulted/environment-resolved
			// candidate returned by the authoritative config loader. The canonical
			// observability compiler intentionally operates on the immutable raw
			// document, so ConfigManager must join these two views before compare.
			mgr.loadSnapshot = func(source string, snapshot []byte) (*config.Config, error) {
				candidate, loadErr := loadSnapshot(source, snapshot)
				if loadErr != nil {
					return nil, loadErr
				}
				candidate.DeploymentMode = "managed_enterprise"
				candidate.CiscoAIDefense.Endpoint = effectiveEndpoint
				return candidate, nil
			}

			if err := mgr.Reload(context.Background(), "startup_reconcile"); err != nil {
				t.Fatal(err)
			}
			if applyCalls != 0 || mgr.gen.Load() != 0 {
				t.Fatalf("managed no-op apply calls/generation = %d/%d, want 0/0", applyCalls, mgr.gen.Load())
			}
			if mgr.v8Plan == nil || !mgr.v8Plan.ReloadEquivalent(active) || mgr.v8PlanDigest != active.Digest() {
				t.Fatalf("stored managed plan/digest diverged from active plan")
			}
			destination, ok := mgr.v8Plan.Destination(config.ObservabilityV8ManagedAIDDestinationName)
			wantEndpoint := effectiveEndpoint + config.ObservabilityV8ManagedAIDIngestPath
			if !ok || !destination.Generated || destination.Transport.Endpoint != wantEndpoint {
				t.Fatalf("managed destination=%+v present=%t, want endpoint %q", destination, ok, wantEndpoint)
			}
		})
	}
}

func TestConfigManagerManagedExactSourceChangePublishesNewGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	makeRaw := func(comment string) []byte {
		return []byte("# " + comment + "\nconfig_version: 8\ndata_dir: " + dir + `
observability: {}
`)
	}
	initialRaw := makeRaw("source generation A")
	changedRaw := makeRaw("source generation B")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.CiscoAIDefense.Endpoint = "https://aid.example.test"
	compiled, err := config.ParseCompileObservabilityV8(
		path, initialRaw, config.ObservabilityV8CompileOptions{DefaultDataDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	active, err := config.WithObservabilityV8ManagedAIDDestination(
		compiled.Plan, sidecarObservabilityV8ManagedOptionsFromConfig(initial, initialRaw),
	)
	if err != nil {
		t.Fatal(err)
	}
	applyCalls := 0
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, active.Digest(),
		func(_ context.Context, _ *config.Config, _ *config.Config, diff ConfigDiff, source configReloadSource) error {
			applyCalls++
			if len(diff.Changed) != 1 || diff.Changed[0] != "observability" ||
				!bytes.Equal(source.raw, changedRaw) {
				t.Fatalf("exact-source reload diff/source=%+v/%q", diff, source.raw)
			}
			return nil
		},
	)
	mgr.bindInitialObservabilityV8Plan(active)
	loadSnapshot := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, snapshot []byte) (*config.Config, error) {
		candidate, loadErr := loadSnapshot(source, snapshot)
		if loadErr == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.CiscoAIDefense.Endpoint = "https://aid.example.test"
		}
		return candidate, loadErr
	}
	if err := os.WriteFile(path, changedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "exact_source_change"); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 || mgr.gen.Load() != 1 || mgr.v8Plan == nil || mgr.v8Plan.ReloadEquivalent(active) {
		t.Fatalf("exact-source reload calls/generation/plan=%d/%d/%p", applyCalls, mgr.gen.Load(), mgr.v8Plan)
	}
	destination, ok := mgr.v8Plan.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName)
	if !ok {
		t.Fatal("managed destination missing after exact-source reload")
	}
	if got, ok := config.ObservabilityV8ManagedAIDSourceContentHash(destination); !ok ||
		got != config.ObservabilityV8SourceContentHash(changedRaw) {
		t.Fatalf("published exact source binding=%q/%t", got, ok)
	}
}

func TestStandaloneConfigManagerRejectsUnbundledConfigAndAssetReload(t *testing.T) {
	setPendingRestart(nil)
	t.Cleanup(func() { setPendingRestart(nil) })
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	asset := filepath.Join(dir, "asset.rego")
	if err := os.WriteFile(asset, []byte("package original"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.Enterprise.Profile = "standalone"
	if !initial.StandaloneEnterprise() {
		t.Fatal("fixture is not standalone enterprise")
	}
	applied := 0
	boot := true
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, _ ConfigDiff, source configReloadSource) error {
		if boot {
			boot = false
			return errGenerationUnchanged
		}
		if source.proveUnchanged {
			contents, err := os.ReadFile(asset)
			if err != nil {
				return err
			}
			if string(contents) != "package original" {
				return fmt.Errorf("config reload refused: referenced asset %s differs; apply a new signed policy bundle", asset)
			}
			return errGenerationUnchanged
		}
		applied++
		return nil
	})
	mgr.assetFiles = func() []string { return []string{asset} }
	loadSnapshot := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, snapshot []byte) (*config.Config, error) {
		candidate, loadErr := loadSnapshot(source, snapshot)
		if loadErr == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.Enterprise.Profile = "standalone"
		}
		return candidate, loadErr
	}
	compiled, err := config.ParseCompileObservabilityV8(path, raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	mgr.bindInitialObservabilityV8Plan(compiled.Plan)
	mgr.setStartupSource(path, raw)
	if err := mgr.Reload(context.Background(), "startup_reconcile"); err != nil {
		t.Fatalf("startup reconcile of boot bytes: %v", err)
	}
	unbundled := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\ngateway:\n  api_port: %d\nobservability: {}\n",
		dir, initial.Gateway.APIPort+1))
	if err := os.WriteFile(path, unbundled, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "watch"); err == nil || !strings.Contains(err.Error(), "signed policy bundle") {
		t.Fatalf("unbundled config reload = %v, want named refusal", err)
	}
	if pending, _ := livePendingRestart.Load().([]string); len(pending) != 0 {
		t.Fatalf("unbundled gateway port edit advertised a pending restart: %v", pending)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(context.Background(), "asset_watch"); err != nil || mgr.rejected {
		t.Fatalf("restored config recovery = %v, rejected=%t", err, mgr.rejected)
	}
	if err := mgr.ReloadAssets(context.Background(), "unchanged_asset_watch"); err != nil || mgr.rejected {
		t.Fatalf("unchanged later asset reload = %v, rejected=%t", err, mgr.rejected)
	}
	if err := os.WriteFile(asset, []byte("package changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(context.Background(), "unsigned_asset_watch"); err == nil || !strings.Contains(err.Error(), asset) {
		t.Fatalf("unbundled changed asset reload = %v, want named refusal", err)
	}
	if applied != 0 {
		t.Fatalf("unbundled reload applied %d times", applied)
	}
}

func TestStandaloneConfigManagerAppliesOnlyRecordedNoAnchorLifecycleGenerations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initialRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.Enterprise.Profile = "standalone"
	applied := 0
	boot := true
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		if boot {
			boot = false
			return errGenerationUnchanged
		}
		applied++
		return nil
	})
	loader := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
		candidate, err := loader(source, raw)
		if err == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.Enterprise.Profile = "standalone"
		}
		return candidate, err
	}
	mgr.setStartupSource(path, initialRaw)
	if err := mgr.Reload(t.Context(), "startup_reconcile"); err != nil {
		t.Fatal(err)
	}
	writeLifecycle := func(raw []byte) uint64 {
		t.Helper()
		result, err := configwrite.ReplaceDocument(t.Context(), path, raw, configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "enterprise ensure"})
		if err != nil {
			t.Fatal(err)
		}
		return result.Generation
	}
	commented := append([]byte("# managed comment\n"), initialRaw...)
	commentGeneration := writeLifecycle(commented)
	if err := mgr.Reload(t.Context(), "watch"); err != nil {
		t.Fatalf("lifecycle comment generation rejected: %v", err)
	}
	if !mgr.appliedGenerationKnown || mgr.appliedGeneration != commentGeneration {
		t.Fatalf("comment generation: applies=%d recorded=%d/%t, want %d", applied, mgr.appliedGeneration, mgr.appliedGenerationKnown, commentGeneration)
	}
	beforeAction := applied
	action := bytes.Replace(commented, []byte("mode: observe"), []byte("mode: action"), 1)
	actionGeneration := writeLifecycle(action)
	if err := mgr.Reload(t.Context(), "watch"); err != nil {
		t.Fatalf("lifecycle policy generation rejected: %v", err)
	}
	if applied != beforeAction+1 || mgr.appliedGeneration != actionGeneration || mgr.Current().Guardrail.Mode != "action" {
		t.Fatalf("policy generation: applies=%d recorded=%d mode=%q", applied, mgr.appliedGeneration, mgr.Current().Guardrail.Mode)
	}
	beforeRefusal := applied
	// Once bundle trust anchors exist, a lifecycle record without a signed
	// bundle is no longer an authorization to reload managed policy.
	anchorDir := filepath.Join(dir, "trust")
	if err := os.MkdirAll(anchorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(anchorDir, "bundle-anchors.json"), []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLifecycle(append([]byte("# another comment\n"), action...))
	if err := mgr.Reload(t.Context(), "watch"); err == nil || !strings.Contains(err.Error(), "signed policy bundle") {
		t.Fatalf("unbundled generation with anchors = %v, want signed-bundle refusal", err)
	}
	if applied != beforeRefusal || mgr.appliedGeneration != actionGeneration {
		t.Fatalf("refused generation applied: applies=%d recorded=%d", applied, mgr.appliedGeneration)
	}
}

// The Windows lifecycle asks /policy/reload to load the generation it just
// recorded, because the watcher can miss the atomic config replacement. The
// managed reload loads that recorded generation (unsigned before trust
// anchors, signed after), answers nil once it is applied, and refuses a hand
// edit or an unsigned record without touching the manager's state.
func TestStandaloneConfigManagerAPIReloadLoadsOnlyTheRecordedGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initialRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.Enterprise.Profile = "standalone"
	applied := 0
	boot := true
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		if boot {
			boot = false
			return errGenerationUnchanged
		}
		applied++
		return nil
	})
	loader := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
		candidate, err := loader(source, raw)
		if err == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.Enterprise.Profile = "standalone"
		}
		return candidate, err
	}
	mgr.setStartupSource(path, initialRaw)
	if err := mgr.Reload(t.Context(), "startup_reconcile"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload"); !errors.Is(err, errNoRecordedGeneration) || applied != 0 {
		t.Fatalf("reload with nothing recorded = %v (applies %d), want errNoRecordedGeneration", err, applied)
	}
	write := func(raw []byte, opt configwrite.Options) uint64 {
		t.Helper()
		result, err := configwrite.ReplaceDocument(t.Context(), path, raw, opt)
		if err != nil {
			t.Fatal(err)
		}
		return result.Generation
	}
	lifecycle := configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "enterprise ensure"}
	// No watcher event is delivered: the API request alone loads it.
	action := bytes.Replace(initialRaw, []byte("mode: observe"), []byte("mode: action"), 1)
	actionGeneration := write(action, lifecycle)
	if err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload"); err != nil {
		t.Fatalf("recorded lifecycle generation refused: %v", err)
	}
	if applied != 1 || mgr.appliedGeneration != actionGeneration || mgr.Current().Guardrail.Mode != "action" {
		t.Fatalf("recorded generation: applies=%d recorded=%d mode=%q", applied, mgr.appliedGeneration, mgr.Current().Guardrail.Mode)
	}
	// The watcher may load it first, and the lifecycle may ask twice.
	if err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload"); err != nil || applied != 1 {
		t.Fatalf("applied generation reload = %v (applies %d), want nil without a rebuild", err, applied)
	}
	refused := func(label string) {
		t.Helper()
		err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload")
		if !errors.Is(err, errNoRecordedGeneration) || applied != 1 || mgr.rejected ||
			mgr.appliedGeneration != actionGeneration || mgr.Current().Guardrail.Mode != "action" {
			t.Fatalf("%s: reload = %v, applies=%d rejected=%t recorded=%d mode=%q", label, err, applied, mgr.rejected,
				mgr.appliedGeneration, mgr.Current().Guardrail.Mode)
		}
	}
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	refused("hand edit")
	if err := os.WriteFile(path, action, 0o600); err != nil {
		t.Fatal(err)
	}
	anchorDir := filepath.Join(dir, "trust")
	if err := os.MkdirAll(anchorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(anchorDir, "bundle-anchors.json"), []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(append([]byte("# unsigned\n"), action...), lifecycle)
	refused("unsigned record with trust anchors")
	signed := bytes.Replace(action, []byte("mode: action"), []byte("mode: observe"), 1)
	signedGeneration := write(signed, configwrite.Options{Actor: "control-plane:t1/alice", Reason: "bundle", Lifecycle: true,
		Bundle: configwrite.BundleRef{ID: "b-01J9ZZZZZZZZZZZZZZZZZZZZZZ", Version: 7, SignerKeyID: "k1"}})
	if err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload"); err != nil {
		t.Fatalf("signed bundle generation refused: %v", err)
	}
	if applied != 2 || mgr.appliedGeneration != signedGeneration || mgr.Current().Guardrail.Mode != "observe" {
		t.Fatalf("signed generation: applies=%d recorded=%d mode=%q", applied, mgr.appliedGeneration, mgr.Current().Guardrail.Mode)
	}
}

func TestStandaloneConfigManagerProvesStartupAssetReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	asset := filepath.Join(dir, "asset.rego")
	if err := os.WriteFile(asset, []byte("package original"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.Enterprise.Profile = "standalone"
	called := 0
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		called++
		contents, err := os.ReadFile(asset)
		if err != nil {
			return err
		}
		if string(contents) != "package original" {
			return fmt.Errorf("config reload refused: referenced asset %s differs; apply a new signed policy bundle", asset)
		}
		return errGenerationUnchanged
	})
	mgr.assetFiles = func() []string { return []string{asset} }
	loadSnapshot := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, snapshot []byte) (*config.Config, error) {
		candidate, loadErr := loadSnapshot(source, snapshot)
		if loadErr == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.Enterprise.Profile = "standalone"
		}
		return candidate, loadErr
	}
	mgr.setStartupSource(path, raw)
	if err := mgr.ReloadAssets(context.Background(), "startup_reconcile"); err != nil {
		t.Fatalf("unchanged startup asset reload = %v", err)
	}
	if called != 1 || mgr.gen.Load() != 0 || mgr.rejected {
		t.Fatalf("startup asset proof: builds=%d gen=%d rejected=%t", called, mgr.gen.Load(), mgr.rejected)
	}
	if err := os.WriteFile(asset, []byte("package changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(context.Background(), "asset_watch"); err == nil || !strings.Contains(err.Error(), asset) {
		t.Fatalf("changed asset after startup = %v, want named refusal", err)
	}
	if called != 2 || mgr.gen.Load() != 0 || !mgr.rejected {
		t.Fatalf("changed asset proof: builds=%d gen=%d rejected=%t", called, mgr.gen.Load(), mgr.rejected)
	}
}

func TestConfigManagerDetectsSecretOnlyObservabilityReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	makeRaw := func(header, query, fragment string) []byte {
		return []byte("config_version: 8\ndata_dir: " + dir + `
observability:
  destinations:
    - name: archive
      kind: http_jsonl
      endpoint: https://archive.example.test/events?token=` + query + `#` + fragment + `
      headers:
        Authorization: "` + header + `"
`)
	}
	initialRaw := makeRaw("credential-one", "query-one", "fragment-one")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		path, initialRaw, config.ObservabilityV8CompileOptions{DefaultDataDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	applyCalls := 0
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, compiled.Plan.Digest(),
		func(_ context.Context, _ *config.Config, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
			applyCalls++
			if len(diff.Changed) != 1 || diff.Changed[0] != "observability" {
				t.Fatalf("secret-only diff = %+v", diff)
			}
			return nil
		},
	)
	mgr.bindInitialObservabilityV8Plan(compiled.Plan)
	changedRaw := makeRaw("credential-two", "query-two", "fragment-two")
	if err := os.WriteFile(path, changedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 || mgr.gen.Load() != 1 {
		t.Fatalf("secret-only reload apply calls/generation = %d/%d", applyCalls, mgr.gen.Load())
	}
}

func TestConfigManagerRejectsContinuouslyMutatingSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	first := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	second := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability:\n  local:\n    retention_days: 30\n")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			t.Fatal("unstable source reached apply")
			return nil
		},
	)
	realLoad := mgr.loadSnapshot
	writeSecond := true
	mgr.loadSnapshot = func(candidatePath string, raw []byte) (*config.Config, error) {
		candidate, loadErr := realLoad(candidatePath, raw)
		next := first
		if writeSecond {
			next = second
		}
		writeSecond = !writeSecond
		if writeErr := os.WriteFile(candidatePath, next, 0o600); writeErr != nil {
			t.Fatalf("mutate config during load: %v", writeErr)
		}
		return candidate, loadErr
	}

	err = mgr.Reload(context.Background(), "test")
	if err == nil || !strings.Contains(err.Error(), "changed during capture") {
		t.Fatalf("unstable source error = %v", err)
	}
	if mgr.gen.Load() != 0 {
		t.Fatalf("unstable source published generation %d", mgr.gen.Load())
	}
}

func TestConfigManagerABAReloadStillDecodesCapturedSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initialRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\n  block_message: initial---\nobservability: {}\n")
	snapshotA := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: action\n  block_message: snapshot-A\nobservability: {}\n")
	transientB := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: action\n  block_message: ambient--B\nobservability: {}\n")
	if len(snapshotA) != len(transientB) {
		t.Fatal("ABA fixture sources must have identical size")
	}
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(_ context.Context, _ *config.Config, next *config.Config, _ ConfigDiff, source configReloadSource) error {
			applied = true
			if !bytes.Equal(source.raw, snapshotA) || next.Guardrail.BlockMessage != "snapshot-A" {
				t.Fatalf("apply source/candidate = %q/%q", source.raw, next.Guardrail.BlockMessage)
			}
			return nil
		},
	)
	if err := os.WriteFile(path, snapshotA, 0o600); err != nil {
		t.Fatal(err)
	}
	realLoad := mgr.loadSnapshot
	loads := 0
	mgr.loadSnapshot = func(candidatePath string, captured []byte) (*config.Config, error) {
		loads++
		before, statErr := os.Stat(candidatePath)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if writeErr := os.WriteFile(candidatePath, transientB, before.Mode()); writeErr != nil {
			t.Fatal(writeErr)
		}
		candidate, loadErr := realLoad(candidatePath, captured)
		if writeErr := os.WriteFile(candidatePath, snapshotA, before.Mode()); writeErr != nil {
			t.Fatal(writeErr)
		}
		if timeErr := os.Chtimes(candidatePath, before.ModTime(), before.ModTime()); timeErr != nil {
			t.Fatal(timeErr)
		}
		return candidate, loadErr
	}
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if !applied || loads != 1 || mgr.Current().Guardrail.BlockMessage != "snapshot-A" {
		t.Fatalf("ABA applied/loads/current = %t/%d/%q", applied, loads, mgr.Current().Guardrail.BlockMessage)
	}
}

func TestConfigManagerRejectsV7ReloadBeforeApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	initialRaw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			applied = true
			return nil
		},
	)
	if err := os.WriteFile(path, []byte("config_version: 7\nguardrail:\n  mode: action\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = mgr.Reload(context.Background(), "test")
	if err == nil || !strings.Contains(err.Error(), "upgrade") || applied {
		t.Fatalf("v7 reload error/applied = %v/%t", err, applied)
	}
	if mgr.Current().ConfigVersion != config.ObservabilityV8ConfigVersion || mgr.gen.Load() != 0 {
		t.Fatalf("v7 reload published version/generation = %d/%d", mgr.Current().ConfigVersion, mgr.gen.Load())
	}
}

func TestConfigManagerCurrentReturnsDeepCopy(t *testing.T) {
	initial := config.DefaultConfig()
	initial.ConfigVersion = config.ObservabilityV8ConfigVersion
	initial.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Mode: "observe"},
	}
	initial.Guardrail.Judge.HookConnectors = []string{"codex"}
	mgr := newConfigManagerWithSnapshot("", initial, nil, nil, "", nil)

	snapshot := mgr.Current()
	snapshot.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{Mode: "action"}
	snapshot.Guardrail.Judge.HookConnectors[0] = "claudecode"

	fresh := mgr.Current()
	if got := fresh.Guardrail.Connectors["codex"].Mode; got != "observe" {
		t.Fatalf("connector mode = %q, want observe", got)
	}
	if got := fresh.Guardrail.Judge.HookConnectors[0]; got != "codex" {
		t.Fatalf("hook connector = %q, want codex", got)
	}
}

// GAP-1483: the gateway publishes its configuration through cloneConfig and
// the scanners read the AI Defense key from that copy. On a standalone
// deployment the copy keeps the protected credential as the only key source:
// an AI Defense key the gateway service inherited never stands in, and a
// credential file that is missing or moved away yields no key.
func TestPublishedStandaloneConfigIgnoresServiceAIDefenseKey(t *testing.T) {
	t.Setenv("AI_DEFENSE_API_KEY", "service-env-key")
	const doc = "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
		"  inspection:\n    ai_defense:\n      enabled: true\n      credential: aid-key\n" +
		"cisco_ai_defense:\n  api_key_env: AI_DEFENSE_API_KEY\n"
	loaded, err := config.LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "etc", "config.yaml"), []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	sidecar := &Sidecar{cfg: loaded}
	for name, cfg := range map[string]*config.Config{"cloned": cloneConfig(loaded), "published": sidecar.publishConfig(loaded)} {
		if got := cfg.CiscoAIDefense.ResolvedAPIKey(); got != "" {
			t.Fatalf("%s standalone AI Defense key = %q, want none without the protected credential", name, got)
		}
	}
}

func TestSidecarConfigSnapshotsAreConcurrentSafe(t *testing.T) {
	observe := config.DefaultConfig()
	observe.Guardrail.Mode = "observe"
	action := config.DefaultConfig()
	action.Guardrail.Mode = "action"
	sidecar := &Sidecar{cfg: observe}
	sidecar.publishConfig(observe)

	observe.Guardrail.Mode = "mutated-after-publish"
	if got := sidecar.currentConfig().Guardrail.Mode; got != "observe" {
		t.Fatalf("published mode = %q, want observe", got)
	}
	observe.Guardrail.Mode = "observe"

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 1000 {
				sidecar.publishConfig(action)
				sidecar.publishConfig(observe)
			}
		}()
		go func() {
			defer wg.Done()
			for range 2000 {
				mode := sidecar.currentConfig().Guardrail.Mode
				if mode != "observe" && mode != "action" {
					t.Errorf("observed partial config mode %q", mode)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestDiffConfigsMarksStorageIdentityRestartRequired(t *testing.T) {
	oldCfg := &config.Config{
		DataDir:       "/old/data",
		AuditDB:       "/old/audit.db",
		JudgeBodiesDB: "/old/judge.db",
	}
	newCfg := &config.Config{
		DataDir:       "/new/data",
		AuditDB:       "/new/audit.db",
		JudgeBodiesDB: "/new/judge.db",
	}
	oldCfg.Gateway.DeviceKeyFile = "/old/device.pem"
	newCfg.Gateway.DeviceKeyFile = "/new/device.pem"

	diff := diffConfigs(oldCfg, newCfg)
	for _, want := range []string{"data_dir", "audit_db", "judge_bodies_db", "gateway.device_key_file"} {
		if !slices.Contains(diff.RestartRequired, want) {
			t.Fatalf("restart_required = %v, missing %s", diff.RestartRequired, want)
		}
	}
}

func TestDiffConfigsMarksOpenShellChanged(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{}
	newCfg.OpenShell.Profile = "strict"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "openshell") {
		t.Fatalf("changed = %v, missing openshell", diff.Changed)
	}
}

func TestDiffConfigsApplicationProtectionAndAIDefenseAreHot(t *testing.T) {
	oldCfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	newCfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	newCfg.ApplicationProtection.Enabled = !oldCfg.ApplicationProtection.Enabled

	newCfg.CiscoAIDefense.Endpoint = "https://aid.example.test"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "application_protection") {
		t.Fatalf("changed = %v, missing application_protection", diff.Changed)
	}
	// Both reload hot on an open-source host (spec section 4).
	if len(diff.RestartRequired) != 0 {
		t.Fatalf("restart required = %v, want none", diff.RestartRequired)
	}
}

func TestDiffConfigsMarksACPChangedHotReloadable(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.ACP.Enabled = true

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "acp") {
		t.Fatalf("changed = %v, missing acp", diff.Changed)
	}
	if slices.Contains(diff.RestartRequired, "acp") {
		t.Fatalf("restart_required = %v, ACP must hot reload", diff.RestartRequired)
	}
}

// GAP-0104: an ai_discovery edit reloads hot (GAP-0047) except under Secure
// Client, which keeps the restart of main (issue #1092).
func TestDiffConfigsAIDiscoveryRestartOnlyForSecureClient(t *testing.T) {
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		oldCfg := config.DefaultConfig()
		oldCfg.DeploymentMode, oldCfg.Enterprise.Profile = managed.DeploymentModeManagedEnterprise, profile
		newCfg := cloneConfig(oldCfg)
		newCfg.AIDiscovery.Enabled = !oldCfg.AIDiscovery.Enabled
		diff := diffConfigs(oldCfg, newCfg)
		if got, want := slices.Contains(diff.RestartRequired, "ai_discovery"), profile == managed.ProfileSecureClient; got != want {
			t.Fatalf("%s: restart_required = %v, ai_discovery restart %t, want %t", profile, diff.RestartRequired, got, want)
		}
	}
}

func TestDiffConfigsMarksRoutingRestartRequired(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.Routing.Enabled = true
	newCfg.Routing.Models = []config.RoutingModelBackend{{
		Name:      "fast",
		Provider:  "openai",
		Model:     "gpt-4.1-mini",
		APIKeyEnv: "OPENAI_API_KEY",
	}}

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "routing") {
		t.Fatalf("changed = %v, missing routing", diff.Changed)
	}
	if !slices.Contains(diff.RestartRequired, "routing") {
		t.Fatalf("restart_required = %v, missing routing", diff.RestartRequired)
	}
}

func TestDiffConfigsMarksRuntimeTopologyRestartRequired(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.Gateway.Host = "gateway.example.test"
	newCfg.Guardrail.ScannerMode = "remote"
	newCfg.Guardrail.Connector = "codex"

	diff := diffConfigs(oldCfg, &newCfg)
	for _, want := range []string{"gateway", "guardrail.scanner_mode", "guardrail.connectors"} {
		if !slices.Contains(diff.RestartRequired, want) {
			t.Fatalf("restart_required = %v, missing %s", diff.RestartRequired, want)
		}
	}
}

func TestDiffConfigsTreatsSynthesizedAndTokenEnvGatewayCredentialsAsEquivalent(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "synthesized-token")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")

	oldCfg := config.DefaultConfig()
	oldCfg.Gateway.Token = "synthesized-token"
	newCfg := cloneConfig(oldCfg)
	newCfg.Gateway.Token = ""

	diff := diffConfigs(oldCfg, newCfg)
	if slices.Contains(diff.Changed, "gateway") {
		t.Fatalf("changed = %v, equivalent live gateway credentials must not look changed", diff.Changed)
	}
	if slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("restart_required = %v, equivalent live gateway credentials must not require restart", diff.RestartRequired)
	}
}

func TestDiffConfigsIgnoresDerivedGatewayTransportState(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.Gateway.NoTLS = true
	newCfg := cloneConfig(oldCfg)
	newCfg.Gateway.NoTLS = false

	diff := diffConfigs(oldCfg, newCfg)
	if slices.Contains(diff.Changed, "gateway") {
		t.Fatalf("changed = %v, derived gateway transport state must not look changed", diff.Changed)
	}
	if slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("restart_required = %v, derived gateway transport state must not require restart", diff.RestartRequired)
	}
}

func TestDiffConfigsRequiresRestartForEffectiveGatewayCredentialChange(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")

	oldCfg := config.DefaultConfig()
	oldCfg.Gateway.Token = "old-token"
	newCfg := cloneConfig(oldCfg)
	newCfg.Gateway.Token = "new-token"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "gateway") {
		t.Fatalf("changed = %v, missing gateway", diff.Changed)
	}
	if !slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("restart_required = %v, missing gateway", diff.RestartRequired)
	}
}

func TestDiffConfigsRequiresRestartForGatewayCredentialCustodyChange(t *testing.T) {
	t.Setenv("OLD_GATEWAY_TOKEN", "same-token")
	t.Setenv("NEW_GATEWAY_TOKEN", "same-token")

	oldCfg := config.DefaultConfig()
	oldCfg.Gateway.TokenEnv = "OLD_GATEWAY_TOKEN"
	newCfg := cloneConfig(oldCfg)
	newCfg.Gateway.TokenEnv = "NEW_GATEWAY_TOKEN"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "gateway") {
		t.Fatalf("changed = %v, missing gateway", diff.Changed)
	}
	if !slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("restart_required = %v, missing gateway", diff.RestartRequired)
	}
}

func TestDiffConfigsV8ResourceIdentityRequiresRestart(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	newCfg := cloneConfig(oldCfg)
	newCfg.Environment = "next"
	newCfg.TenantID = "tenant-next"
	newCfg.WorkspaceID = "workspace-next"
	newCfg.DiscoverySource = "source-next"
	diff := diffConfigs(oldCfg, newCfg)
	for _, field := range []string{"environment", "tenant_id", "workspace_id", "discovery_source"} {
		if !slices.Contains(diff.RestartRequired, field) {
			t.Fatalf("restart_required=%v field=%s", diff.RestartRequired, field)
		}
	}
}

// TestHoldRestartRequiredAppliesTheRest: a hook_self_heal, environment or
// gateway.api_port edit needs a restart, so it keeps its running value while
// an admission edit in the same (or a later) reload still applies hot
// (GAP-0275; a shared team config naming another account's api_port,
// GAP-0352). hook_fail_mode is hot: the hook guard reads it from the live
// config (GAP-0045).
func TestHoldRestartRequiredAppliesTheRest(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.Gateway.APIPort = oldCfg.Gateway.APIPort + 70
	newCfg.Environment = oldCfg.Environment + "-next"
	newCfg.Guardrail.HookSelfHeal = !oldCfg.Guardrail.HookSelfHeal
	newCfg.Guardrail.HookFailMode = "closed"
	newCfg.Guardrail.BlockAt = "HIGH"
	newCfg.Admission.Skill.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}

	diff := diffConfigs(oldCfg, newCfg)
	held := holdRestartRequired(oldCfg, newCfg, diff.RestartRequired)
	if !slices.Contains(diff.RestartRequired, "guardrail") || !slices.Contains(diff.RestartRequired, "gateway") || held == nil {
		t.Fatalf("restart_required = %v, held = %v", diff.RestartRequired, held != nil)
	}
	heldDiff := diffConfigs(oldCfg, held)
	if len(heldDiff.RestartRequired) != 0 || !slices.Contains(heldDiff.Changed, "admission") ||
		held.Guardrail.HookSelfHeal != oldCfg.Guardrail.HookSelfHeal || held.Environment != oldCfg.Environment ||
		held.Gateway.APIPort != oldCfg.Gateway.APIPort ||
		held.Guardrail.HookFailMode != "closed" || held.Guardrail.BlockAt != "HIGH" {
		t.Fatalf("held diff = %+v hook_self_heal=%v hook_fail_mode=%q block_at=%q",
			heldDiff, held.Guardrail.HookSelfHeal, held.Guardrail.HookFailMode, held.Guardrail.BlockAt)
	}
}

// TestDiffConfigsSecureClientV8ActionsRequireRestart: under Secure Client an
// edit of a v8 action key is restart-required, as on main (GAP-0279).
func TestDiffConfigsSecureClientV8ActionsRequireRestart(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	oldCfg.Enterprise.Profile = managed.ProfileSecureClient
	oldCfg.SecureClientV8Actions = map[string][5]config.SeverityAction{"skill_actions": {}}
	newCfg := cloneConfig(oldCfg)
	newCfg.SecureClientV8Actions["skill_actions"] = [5]config.SeverityAction{1: {Install: config.InstallNone}}
	if diff := diffConfigs(oldCfg, newCfg); !slices.Equal(diff.RestartRequired, []string{"skill_actions"}) {
		t.Fatalf("diff = %+v", diff)
	}
	if diff := diffConfigs(oldCfg, cloneConfig(oldCfg)); len(diff.Changed) != 0 {
		t.Fatalf("unchanged diff = %+v", diff)
	}
}

// TestDiffConfigsDirectoryKeys: a policy_dir or quarantine_dir edit applies
// hot (the generation rebuilds, the watcher restarts) and a plugin_dir edit is
// restart-required and held, instead of all three passing as no change
// (GAP-0277).
func TestDiffConfigsDirectoryKeys(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.PolicyDir = filepath.Join(t.TempDir(), "team-policies")
	newCfg.QuarantineDir = filepath.Join(t.TempDir(), "quarantine")
	newCfg.PluginDir = filepath.Join(t.TempDir(), "plugins")

	diff := diffConfigs(oldCfg, newCfg)
	held := holdRestartRequired(oldCfg, newCfg, diff.RestartRequired)
	if !slices.Contains(diff.Changed, "policy_dir") || !slices.Contains(diff.Changed, "quarantine_dir") ||
		strings.Join(diff.RestartRequired, ",") != "plugin_dir" || held == nil || held.PluginDir != oldCfg.PluginDir ||
		!watcherNeedsRestart(oldCfg, newCfg) {
		t.Fatalf("diff = %+v held = %v", diff, held != nil)
	}
}

func TestDiffConfigsAllowsHotGuardrailPolicyFields(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.Guardrail.Mode = "action"
	newCfg.Guardrail.BlockMessage = "updated block message"
	newCfg.Guardrail.HILT.Enabled = !oldCfg.Guardrail.HILT.Enabled
	newCfg.Guardrail.HILT.MinSeverity = "MEDIUM"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "guardrail") {
		t.Fatalf("changed = %v, missing guardrail", diff.Changed)
	}
	if slices.Contains(diff.RestartRequired, "guardrail") {
		t.Fatalf("restart_required = %v, pure policy fields should hot-apply", diff.RestartRequired)
	}
}

func TestDiffConfigsRequiresRestartForJudgeBodyRetentionTransitions(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("to_%t", enabled), func(t *testing.T) {
			oldCfg := config.DefaultConfig()
			newCfg := cloneConfig(oldCfg)
			oldCfg.Guardrail.RetainJudgeBodies = !enabled
			newCfg.Guardrail.RetainJudgeBodies = enabled

			diff := diffConfigs(oldCfg, newCfg)
			if !slices.Contains(diff.RestartRequired, "guardrail.retain_judge_bodies") {
				t.Fatalf("restart_required = %v, missing exact judge-body retention boundary", diff.RestartRequired)
			}
			if slices.Contains(diff.RestartRequired, "guardrail") {
				t.Fatalf("restart_required = %v, broad guardrail reason obscures exact boundary", diff.RestartRequired)
			}
		})
	}
}

func TestAPIServerHookPostureUsesPublishedRuntimeConfig(t *testing.T) {
	boot := config.DefaultConfig()
	boot.Guardrail.Enabled = true
	boot.Guardrail.Connector = "codex"
	boot.Guardrail.Mode = "observe"
	boot.Guardrail.HookFailMode = "open"
	boot.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {Mode: "observe", HookFailMode: "open"},
		"claudecode": {Mode: "observe", HookFailMode: "open"},
	}

	live := cloneConfig(boot)
	live.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {Mode: "action", HookFailMode: "closed"},
		"claudecode": {Mode: "action", HookFailMode: "closed"},
	}

	api := NewAPIServer("", nil, nil, nil, nil, cloneConfig(boot))
	api.SetConfigRuntime(nil, func() *config.Config { return live })

	if got := api.codexMode(context.Background()); got != "action" {
		t.Fatalf("Codex mode = %q, want published action", got)
	}
	if got := api.claudeCodeMode(context.Background()); got != "action" {
		t.Fatalf("Claude Code mode = %q, want published action", got)
	}
	rows := api.connectorModesSummary(context.Background())
	if len(rows) != 2 {
		t.Fatalf("connector mode rows = %d, want 2: %#v", len(rows), rows)
	}
	for _, row := range rows {
		name, _ := row["connector"].(string)
		if row["policy_mode"] != "action" || row["hook_fail_mode"] != "closed" || row["enabled"] != true {
			t.Fatalf("%s published posture = %#v, want action/closed/enabled", name, row)
		}
	}
	if boot.EffectiveGuardrailModeForConnector("codex") != "observe" ||
		boot.Guardrail.HookFailMode != "open" || boot.Guardrail.Connectors["codex"].HookFailMode != "open" ||
		boot.EffectiveHookFailModeForConnector("codex") != "closed" {
		t.Fatal("API posture read mutated the immutable boot snapshot")
	}
}

// llm and scanner edits reload hot: the judge is rebuilt, the install
// watcher restarts in-process and API scans read the live config.
func TestReloadPredicatesRestartLLMConsumers(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{}
	oldCfg.LLM.Model = "openai/gpt-4o-mini"
	newCfg.LLM.Model = "openai/gpt-4.1-mini"
	newCfg.Scanners.SkillScanner.FailOnSeverity = "MEDIUM"

	if diff := diffConfigs(oldCfg, newCfg); len(diff.RestartRequired) != 0 {
		t.Fatalf("llm and scanners diff = %+v, want a hot reload", diff)
	}
	if !watcherNeedsRestart(oldCfg, newCfg) {
		t.Fatal("watcherNeedsRestart returned false for llm change")
	}

	// An operator block/allow (asset_policy) or an admission edit applies to
	// the next decision without a restart, which would cancel an install
	// scan in flight and fail it closed (GAP-0315).
	listEdit := &config.Config{}
	listEdit.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "foo"}}
	scanOff := false
	listEdit.Admission.Skill.ScanOnInstall = &scanOff
	if watcherNeedsRestart(&config.Config{}, listEdit) {
		t.Fatal("watcherNeedsRestart returned true for an asset_policy or admission edit")
	}
}

func TestGuardrailRestartPredicateIncludesSingularConnector(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := config.DefaultConfig()
	oldCfg.Guardrail.Connector = "codex"
	newCfg.Guardrail.Connector = "claudecode"

	if !guardrailNeedsRestart(oldCfg, newCfg) {
		t.Fatal("guardrailNeedsRestart returned false for singular connector change")
	}
}

// The connector set applies in-process off Secure Client: disabling a
// connector re-runs the connector setup (and the install watcher) without a
// gateway restart, enabled: true is the unset default, and Secure Client
// keeps the restart (GAP-0072, GAP-0032).
func TestConnectorSetChangeIsHotOffSecureClient(t *testing.T) {
	yes, no := true, false
	withCodex := func(enabled *bool, profile string) *config.Config {
		cfg := config.DefaultConfig()
		cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Enabled: enabled}, "claudecode": {}}
		if profile != "" {
			cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
			cfg.Enterprise.Profile = profile
		}
		return cfg
	}
	if connectorSetChanged(withCodex(nil, ""), withCodex(&yes, "")) {
		t.Fatal("enabled: true (the default) changed the connector set")
	}
	oldCfg, newCfg := withCodex(&yes, ""), withCodex(&no, "")
	if diff := diffConfigs(oldCfg, newCfg); len(diff.RestartRequired) != 0 || !connectorSetChanged(oldCfg, newCfg) {
		t.Fatalf("disable codex: diff = %+v, connector set changed = %v; want a hot connector-set change", diff, connectorSetChanged(oldCfg, newCfg))
	}
	sc := managed.ProfileSecureClient
	if diff := diffConfigs(withCodex(&yes, sc), withCodex(&no, sc)); !slices.Contains(diff.RestartRequired, "guardrail.connectors") {
		t.Fatalf("Secure Client disable codex: restart_required = %v, want guardrail.connectors", diff.RestartRequired)
	}
}

// A legacy per-user open-to-closed edit cannot change the already-closed
// runtime or the set of connectors that setup must install.
func TestLegacyPerUserOpenEditDoesNotChangeConnectorSetup(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.Guardrail.Enabled = true
	oldCfg.Guardrail.Connector = "codex"
	oldCfg.Guardrail.Mode = "action"
	oldCfg.Guardrail.HookSelfHeal = false
	oldCfg.Guardrail.HookFailMode = "open"
	newCfg := cloneConfig(oldCfg)
	newCfg.Guardrail.HookFailMode = "closed"
	if oldCfg.EffectiveHookFailModeForConnector("codex") != "closed" ||
		newCfg.EffectiveHookFailModeForConnector("codex") != "closed" ||
		connectorSetChanged(oldCfg, newCfg) {
		t.Fatal("legacy per-user open edit changed effective setup posture")
	}
}

// A custom rule-pack folder that is deleted and created again is watched
// again (and reported as added, so the 30 s tick reloads the generation from
// it) instead of staying in the watched set with a dead watch (GAP-0266).
func TestAssetWatchesReaddARecreatedFolder(t *testing.T) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()
	pack := filepath.Join(t.TempDir(), "pack")
	if err := os.Mkdir(pack, 0o700); err != nil {
		t.Fatal(err)
	}
	watches := &assetWatches{fsw: fsw, watched: map[string]struct{}{}}
	want := map[string]struct{}{pack: {}}
	if !watches.sync(want) {
		t.Fatal("first sync did not watch the pack folder")
	}
	if err := os.RemoveAll(pack); err != nil {
		t.Fatal(err)
	}
	watches.removed(pack)
	if watches.sync(want) {
		t.Fatal("sync watched a folder that is gone")
	}
	if err := os.Mkdir(pack, 0o700); err != nil {
		t.Fatal(err)
	}
	if !watches.sync(want) {
		t.Fatal("the recreated pack folder was not watched again")
	}
}

func TestAIDiscoveryRestartPredicateIncludesLiveManagedModeTransitions(t *testing.T) {
	for _, test := range []struct {
		name string
		from string
		to   string
	}{
		{name: "unmanaged to managed", from: string(config.DeploymentModeUnmanagedBYOD), to: string(config.DeploymentModeManagedEnterprise)},
		{name: "managed to unmanaged", from: string(config.DeploymentModeManagedEnterprise), to: string(config.DeploymentModeUnmanagedBYOD)},
	} {
		t.Run(test.name, func(t *testing.T) {
			oldCfg := config.DefaultConfig()
			newCfg := config.DefaultConfig()
			oldCfg.DeploymentMode = test.from
			newCfg.DeploymentMode = test.to
			if !reflect.DeepEqual(oldCfg.AIDiscovery, newCfg.AIDiscovery) {
				t.Fatal("fixture changed ai_discovery config")
			}
			if !aiDiscoveryNeedsRestart(oldCfg, newCfg) {
				t.Fatal("deployment-mode-only transition did not restart AI discovery")
			}
		})
	}
	// A hot exclude_users apply on the standalone profile rebuilds the scan,
	// so the excluded account leaves discovery at the next scan (GAP-1024).
	oldCfg := config.DefaultConfig()
	oldCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	oldCfg.Enterprise.Profile = managed.ProfileStandalone
	newCfg := *oldCfg
	newCfg.Enterprise.Enrollment.ExcludeUsers = []string{"dcw-qv"}
	if !aiDiscoveryNeedsRestart(oldCfg, &newCfg) {
		t.Fatal("an exclude_users change did not restart AI discovery")
	}
}

func TestEventRouterConfigurationAccessorsAreConcurrentSafe(t *testing.T) {
	router := &EventRouter{}
	guardrailCfg := &config.GuardrailConfig{Connector: "codex"}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 1000 {
				router.SetGuardrailConfig(guardrailCfg)
				router.SetDefaultAgentName("codex")
				router.SetDefaultPolicyID("action")
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = router.guardrailConfig()
				_ = router.connectorName()
				_, _ = router.defaultRoutingMetadata()
				_ = router.rulePack()
			}
		}()
	}
	wg.Wait()
}

func TestConfigRestartHelperArgsPreservesOnlySafeRootFlags(t *testing.T) {
	got := configRestartHelperArgs([]string{
		"defenseclaw-gateway",
		"--host", "10.0.0.5",
		"--token", "secret",
		"--port=18790",
		"--log-level", "debug",
	})
	want := []string{"restart", "--host", "10.0.0.5", "--port=18790"}
	if !slices.Equal(got, want) {
		t.Fatalf("configRestartHelperArgs = %v, want %v", got, want)
	}
}

func TestDiffConfigsDeploymentModeRequiresRestart(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	oldCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	newCfg.DeploymentMode = string(config.DeploymentModeUnmanagedBYOD)
	diff := diffConfigs(oldCfg, &newCfg)
	if !slices.Contains(diff.RestartRequired, "deployment_mode") {
		t.Fatalf("restart required = %v, want deployment_mode", diff.RestartRequired)
	}
}

func TestReloadableSubsystemSnapshotsAreSynchronized(t *testing.T) {
	sidecar := &Sidecar{}
	dispatchers := []*WebhookDispatcher{{}, {}}
	discoveryServices := []*inventory.ContinuousDiscoveryService{{}, {}}

	const iterations = 1000
	var wg sync.WaitGroup
	for _, run := range []func(){
		func() {
			for i := 0; i < iterations; i++ {
				sidecar.swapWebhooks(dispatchers[i%len(dispatchers)])
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				_ = sidecar.webhooksSnapshot()
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				sidecar.swapAIDiscovery(discoveryServices[i%len(discoveryServices)])
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				_ = sidecar.aiDiscoverySnapshot()
			}
		},
	} {
		wg.Add(1)
		go func(run func()) {
			defer wg.Done()
			run()
		}(run)
	}
	wg.Wait()
}

func writeConfigForManagerTest(t *testing.T, path, dataDir, mode string) {
	t.Helper()
	raw := "config_version: 8\n" +
		"data_dir: " + dataDir + "\n" +
		"guardrail:\n" +
		"  mode: " + mode + "\n" +
		"observability: {}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func configContentHashForTest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// A hooks-only connector must never be reported as proxy-intercepted. This
// used to come from a hardcoded name list in connectorModeFor, and Kiro was
// missing from it: `defenseclaw-gateway status` showed "Data path: DefenseClaw
// proxy" and "Enforcement: llm proxy" for Kiro in the same output whose
// Guardrail subsystem reported "proxy_port: closed". The classification now
// comes from the connector's declared traffic mode, so the list cannot drift
// again.
func TestConnectorModeMatchesDeclaredTrafficMode(t *testing.T) {
	registry := sharedDefaultRegistry()
	for _, name := range registry.Names() {
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		wantProxy := proxyShouldBindForConnector(conn, nil)
		row := connectorModeFor(name, "action")
		intercept, _ := row["proxy_intercept"].(bool)
		if intercept != wantProxy {
			t.Errorf("%s: proxy_intercept=%v, want %v (declared traffic mode)", name, intercept, wantProxy)
		}
		mode, _ := row["mode"].(string)
		surface, _ := row["enforcement_surface"].(string)
		if wantProxy {
			if mode != "guardrail" || surface != "llm_proxy" {
				t.Errorf("%s: mode=%q surface=%q, want guardrail/llm_proxy", name, mode, surface)
			}
			continue
		}
		if mode != "observability" {
			t.Errorf("%s: mode=%q, want observability", name, mode)
		}
		if surface == "llm_proxy" {
			t.Errorf("%s: hooks-only connector reports enforcement_surface=llm_proxy", name)
		}
		// A hooks-only connector in action mode must advertise that its
		// hooks are what enforce, or the operator cannot tell whether
		// anything is actually blocking.
		row = connectorModeForConfig(nil, name)
		if _, ok := row["hook_enforcement"]; !ok {
			t.Errorf("%s: hook_enforcement is absent", name)
		}
	}
}

// Kiro specifically: it is an ordinary hook connector that also offers ACP.
// Both paths must read as hook enforcement, never as a proxy data path.
func TestKiroConnectorModeIsHooksOnly(t *testing.T) {
	row := connectorModeForConfig(nil, "kiro")
	for key, want := range map[string]interface{}{
		"connector":           "kiro",
		"mode":                "observability",
		"enforcement_surface": "agent_lifecycle_hooks",
		"proxy_intercept":     false,
	} {
		if got := row[key]; got != want {
			t.Errorf("kiro %s = %#v, want %#v", key, got, want)
		}
	}
	telemetry, _ := row["telemetry"].([]string)
	if len(telemetry) == 0 {
		t.Errorf("kiro telemetry = %#v, want at least hooks", row["telemetry"])
	}
}

func TestDiffConfigsRegistrySourcesAndAssetPolicyHotReload(t *testing.T) {
	// GAP-2422: the gateway never reads registry sources, so adding one must
	// not make every later reload fail. asset_policy (the operator block and
	// allow lists since config_version 9) is read live, so it reloads hot.
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.Registries.Sources = append(newCfg.Registries.Sources, config.RegistrySource{ID: "corp", Kind: "file"})
	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "registries") || slices.Contains(diff.RestartRequired, "registries") {
		t.Fatalf("changed=%v restart_required=%v, registries must hot reload", diff.Changed, diff.RestartRequired)
	}
	newCfg.AssetPolicy.Enabled = !oldCfg.AssetPolicy.Enabled
	diff = diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "asset_policy") || len(diff.RestartRequired) != 0 {
		t.Fatalf("changed=%v restart_required=%v, asset_policy must hot reload", diff.Changed, diff.RestartRequired)
	}
}

// TestConfigManagerAssetReloadAppliesWithoutConfigDiff pins the asset path
// of the one watcher: a referenced asset changing (or /policy/reload)
// rebuilds the generation even though config.yaml is unchanged, and an
// unchanged rebuild swaps nothing.
func TestConfigManagerAssetReloadAppliesWithoutConfigDiff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var diffs []ConfigDiff
	unchanged := false
	var rejected error
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
		diffs = append(diffs, diff)
		if rejected != nil {
			return rejected
		}
		if unchanged {
			return errGenerationUnchanged
		}
		return nil
	})
	if err := mgr.Reload(context.Background(), "settle"); err != nil {
		t.Fatalf("settle reload: %v", err)
	}
	diffs = nil
	if err := mgr.Reload(context.Background(), "test"); err != nil || len(diffs) != 0 {
		t.Fatalf("plain reload of an unchanged file = %v, applied %v", err, diffs)
	}
	if err := mgr.ReloadAssets(context.Background(), "test"); err != nil {
		t.Fatalf("asset reload: %v", err)
	}
	if len(diffs) != 1 || !slices.Equal(diffs[0].Changed, []string{configDiffAssets}) || len(diffs[0].RestartRequired) != 0 {
		t.Fatalf("asset reload diffs = %+v, want one hot %q diff", diffs, configDiffAssets)
	}
	gen := mgr.gen.Load()
	unchanged = true
	if err := mgr.ReloadAssets(context.Background(), "test"); err != nil || mgr.gen.Load() != gen {
		t.Fatalf("unchanged asset rebuild = %v, generation %d -> %d", err, gen, mgr.gen.Load())
	}
	// A pack that fails its digest check rejects the rebuild and leaves a
	// last_reload_error; restoring the pack rebuilds the same generation,
	// which must clear that error (GAP-0027), and a plain reload after the
	// repair does too (GAP-0131).
	t.Cleanup(func() { liveReloadError.Store("") })
	rejected = errors.New("custom pack digest mismatch")
	if err := mgr.ReloadAssets(context.Background(), "test"); err == nil {
		t.Fatal("rejected asset rebuild succeeded")
	}
	if !hasRejection() {
		t.Fatal("rejected asset rebuild left no last_reload_error")
	}
	rejected = nil
	if err := mgr.ReloadAssets(context.Background(), "test"); err != nil || hasRejection() {
		t.Fatalf("restored asset rebuild = %v, last_reload_error still set: %v", err, hasRejection())
	}
	rejected = errors.New("custom pack digest mismatch")
	if err := mgr.ReloadAssets(context.Background(), "test"); err == nil {
		t.Fatal("rejected asset rebuild succeeded")
	}
	rejected = nil
	if err := mgr.Reload(context.Background(), "test"); err != nil || mgr.rejected || hasRejection() {
		t.Fatalf("reload after the repair = %v, rejection still standing (manager %v)", err, mgr.rejected)
	}
}

// hasRejection reports a standing policy.last_reload_error.
func hasRejection() bool {
	msg, _ := liveReloadError.Load().(string)
	return msg != ""
}

// TestConfigManagerRestoredConfigSettlesTheRejection pins GAP-0241: a
// config.yaml the gateway refused and then restored to the running content
// rebuilds on the next reload and clears policy.last_reload_error, which
// otherwise stayed until a restart (no change was left to build).
func TestConfigManagerRestoredConfigSettlesTheRejection(t *testing.T) {
	t.Cleanup(clearGenerationBuildError)
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	var diffs []ConfigDiff
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
		diffs = append(diffs, diff)
		if slices.Equal(diff.Changed, []string{configDiffAssets}) {
			return errGenerationUnchanged
		}
		return nil
	})
	if err := mgr.Reload(context.Background(), "settle"); err != nil {
		t.Fatalf("settle reload: %v", err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("openshell: [dccert-block-marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "test"); err == nil {
		t.Fatal("reload of invalid YAML succeeded")
	}
	if msg, _ := liveReloadError.Load().(string); msg == "" {
		t.Fatal("the refused change is not reported")
	}
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	diffs = nil
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload of the restored file: %v", err)
	}
	if msg, _ := liveReloadError.Load().(string); msg != "" || len(diffs) != 1 {
		t.Fatalf("after the restore last_reload_error = %q, rebuilds %d; want it cleared by one rebuild", msg, len(diffs))
	}
	diffs = nil
	if err := mgr.Reload(context.Background(), "test"); err != nil || len(diffs) != 0 {
		t.Fatalf("a settled, unchanged reload = %v, rebuilds %d; want none", err, len(diffs))
	}
}

// A config_version 8 file whose in-memory migration fails is refused, not
// run as raw v8 without its data.json admission and audit.db block/allow
// policy (the reload keeps the previous generation).
func TestLoadRuntimeConfigCandidateRefusesAFailedV8Migration(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	dataJSON := filepath.Join(dir, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"actions": {},}`), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if cfg, err := loadRuntimeConfigCandidate(source, raw); err == nil || cfg != nil {
		t.Fatalf("loadRuntimeConfigCandidate = %v, %v; want the failed migration refused", cfg, err)
	}
}

// A Secure Client gateway reads .env only at start (GAP-0137, issue #1092).
func TestConfigManagerSecureClientReloadReadsNoDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	raw := []byte("config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Loading a Secure Client profile turns on strict hook contract
	// resolution for the whole process (Windows and macOS); later tests in
	// the same go test process expect it off.
	t.Cleanup(func() { connector.SetStrictHookContractResolution(false) })
	loads := 0
	config.RegisterDotEnvLoader(func(string) { loads++ })
	t.Cleanup(func() { config.RegisterDotEnvLoader(nil) })
	initial := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dir}
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			return nil
		})
	_ = mgr.Reload(context.Background(), "test")
	if loads != 0 {
		t.Fatalf("a Secure Client reload loaded .env %d time(s)", loads)
	}
}

// Secure Client keeps its reload classification (GAP-0141, GAP-0147, issue
// #1092): hook_fail_mode reloads hot; the levels, llm, watch, ai_discovery
// and admission (where the v8 action keys now land) need a restart; and the
// watcher follows no policy assets.
func TestDiffConfigsSecureClientKeepsItsReloadClassification(t *testing.T) {
	base := &config.Config{DeploymentMode: "managed_enterprise"}
	edit := func(change func(*config.Config)) ConfigDiff {
		next := cloneConfig(base)
		change(next)
		return diffConfigs(base, next)
	}
	if diff := edit(func(c *config.Config) { c.Guardrail.HookFailMode = "open" }); len(diff.RestartRequired) != 0 {
		t.Fatalf("hook_fail_mode needs a restart: %v", diff.RestartRequired)
	}
	for want, change := range map[string]func(*config.Config){
		"guardrail":    func(c *config.Config) { c.Guardrail.BlockAt = "HIGH" },
		"llm":          func(c *config.Config) { c.LLM.Model = "openai/gpt-4o" },
		"watch":        func(c *config.Config) { c.Watch.DebounceMs = 900 },
		"ai_discovery": func(c *config.Config) { c.AIDiscovery.Enabled = true },
		"admission": func(c *config.Config) {
			c.Admission.Skill.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}
		},
	} {
		if diff := edit(change); !slices.Contains(diff.RestartRequired, want) {
			t.Fatalf("%s edit restart set = %v, want %s", want, diff.RestartRequired, want)
		}
	}
	sidecar := &Sidecar{cfg: base, configMgr: &ConfigManager{}}
	sidecar.watchGenerationAssets()
	if sidecar.configMgr.assetDirs != nil || sidecar.configMgr.assetFiles != nil {
		t.Fatal("the Secure Client watcher follows policy assets")
	}
}

// An asset edited after bootstrap but before startup watches are attached
// must be rebuilt before the gateway reports readiness.
func TestConfigManagerStartupRebuildsAssetBeforeReady(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	pack := filepath.Join(dir, "pack")
	if err := os.Mkdir(pack, 0o700); err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(pack, "rule.rego")
	if err := os.WriteFile(asset, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeConfigForManagerTest(t, path, dir, "observe")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan string, 2)
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			contents, err := os.ReadFile(asset)
			if err == nil {
				applied <- string(contents)
			}
			return err
		})
	mgr.setStartupSource(path, raw)
	mgr.assetDirs = func() []string { return []string{pack} }
	mgr.afterWatchAdded = func() {
		if err := os.WriteFile(asset, []byte("new"), 0o600); err != nil {
			t.Error(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not report readiness")
	}
	select {
	case got := <-applied:
		if got != "new" {
			t.Fatalf("startup applied asset %q, want new", got)
		}
	default:
		t.Fatal("startup reported readiness without rebuilding the edited asset")
	}
	cancel()
	<-done
}

func TestConfigManagerRetriesPermissionErrorAfterRollbackWithoutAnotherWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	var denied atomic.Bool
	applied := make(chan struct{}, 1)
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			select {
			case applied <- struct{}{}:
			default:
			}
			return nil
		})
	mgr.permissionRetryInterval = 20 * time.Millisecond
	read := mgr.readSnapshot
	mgr.readSnapshot = func(path string) (configFileSnapshot, error) {
		if denied.Load() {
			return configFileSnapshot{}, os.ErrPermission
		}
		return read(path)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	select {
	case <-applied:
	default:
	}
	denied.Store(true)
	if err := mgr.Reload(ctx, "rollback"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("permission refusal = %v", err)
	}
	denied.Store(false)
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("permission recovery did not retry the config reload")
	}
	mgr.mu.Lock()
	retry := mgr.permissionRetry
	rejected := mgr.rejected
	mgr.mu.Unlock()
	if retry || rejected {
		t.Fatal("a recovered config is still marked rejected")
	}
	cancel()
	<-done
}

// The config directory already has an fsnotify watch, but it must also be
// classified as an asset directory when policy files live beside config.yaml.
func TestConfigManagerWatchesAssetsBesideConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan struct{}, 3)
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			applied <- struct{}{}
			return nil
		})
	mgr.setStartupSource(path, raw)
	mgr.assetDirs = func() []string { return []string{dir} }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not report readiness")
	}
	// Discard the startup rebuild; the new file must cause another apply.
	select {
	case <-applied:
	default:
		t.Fatal("startup did not build referenced assets")
	}
	if err := os.WriteFile(filepath.Join(dir, "new.rego"), []byte("package new"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-applied:
	case <-time.After(3 * time.Second):
		t.Fatal("asset beside config.yaml did not trigger reload")
	}
	cancel()
	<-done
}

// A rejected config_version 8 candidate does not change the scanner key the
// running generation reads: the inline key its in-memory migration moves to
// a variable is exported only when a reload accepts it.
func TestConfigManagerRejectedV8CandidateKeepsTheActiveScannerKey(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	write := func(mode, key string) []byte {
		raw := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: " + mode +
			"\nscanners:\n  skill_scanner:\n    use_virustotal: true\n    virustotal_api_key: " + key + "\nobservability: {}\n")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := write("observe", "vt-active-key")
	initial, err := loadRuntimeConfigCandidate(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != "" {
		t.Fatal("loading a candidate exported its inline key")
	}
	takeCandidateKeyExport(initial)()
	if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != "vt-active-key" {
		t.Fatal("the accepted configuration's key is not exported")
	}
	reject := true
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		if reject {
			return errors.New("candidate rejected")
		}
		return nil
	})
	write("action", "vt-rejected-key")
	if err := mgr.Reload(context.Background(), "test"); err == nil {
		t.Fatal("the reload was not rejected")
	}
	if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != "vt-active-key" {
		t.Fatal("a rejected candidate replaced the scanner key the running generation reads")
	}
	reject = false
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != "vt-rejected-key" {
		t.Fatal("the accepted candidate's rotated key is not exported")
	}
}
