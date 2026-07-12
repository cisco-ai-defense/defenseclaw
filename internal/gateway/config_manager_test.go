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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
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
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff, source configReloadSource) error {
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
	if !applied || mgr.gen.Load() != 1 || mgr.Current().ConfigVersion != 8 {
		t.Fatalf("applied/gen/version = %t/%d/%d", applied, mgr.gen.Load(), mgr.Current().ConfigVersion)
	}
	if got, want := version.Current().ContentHash, configContentHashForTest(nextRaw); got != want {
		t.Fatalf("successful reload content hash = %q, want %q", got, want)
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
	newCfg.OpenShell.Mode = "standalone"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "openshell") {
		t.Fatalf("changed = %v, missing openshell", diff.Changed)
	}
}

func TestDiffConfigsMarksApplicationProtectionChanged(t *testing.T) {
	oldCfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	newCfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	newCfg.ApplicationProtection.Enabled = !oldCfg.ApplicationProtection.Enabled

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "application_protection") {
		t.Fatalf("changed = %v, missing application_protection", diff.Changed)
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

func TestGuardrailAPIPatchCommitsDiskManagerSidecarAndProxyTogether(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	path := fixture.configPath
	raw := "config_version: 8\n" +
		"data_dir: " + fixture.dataDir + "\n" +
		"gateway:\n  token: transactional-token\n" +
		"guardrail:\n  enabled: true\n  mode: observe\n  scanner_mode: local\n" +
		"observability: {}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	oldCfg, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("load initial config: %v", err)
	}

	proxy := &GuardrailProxy{
		cfg:          &oldCfg.Guardrail,
		mode:         oldCfg.Guardrail.Mode,
		blockMessage: oldCfg.Guardrail.BlockMessage,
		inspector:    NewGuardrailInspector("local", nil, nil, ""),
	}
	sidecar := fixture.sidecar
	sidecar.publishConfig(oldCfg)
	sidecar.setGuardrailProxy(proxy)
	bound, err := sidecar.BootstrapObservabilityRuntime(t.Context(), path, []byte(raw))
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	mgr := newConfigManagerWithSnapshot(
		path, oldCfg, nil, nil, sidecar.observabilityV8ActivePlanDigest(), sidecar.applyConfigReloadSnapshot,
	)
	api := &APIServer{scannerCfg: cloneConfig(oldCfg)}
	api.SetConfigRuntime(mgr.Reload, sidecar.currentConfig)

	body, _ := json.Marshal(map[string]any{"mode": "action"})
	req := httptest.NewRequest(http.MethodPatch, "/v1/guardrail/config", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer transactional-token")
	w := httptest.NewRecorder()
	api.handleGuardrailConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	for label, got := range map[string]string{
		"manager": mgr.Current().Guardrail.Mode,
		"sidecar": sidecar.currentConfig().Guardrail.Mode,
	} {
		if got != "action" {
			t.Fatalf("%s mode = %q, want action", label, got)
		}
	}
	proxy.rtMu.RLock()
	proxyMode := proxy.mode
	proxy.rtMu.RUnlock()
	if proxyMode != "action" {
		t.Fatalf("proxy mode = %q, want action", proxyMode)
	}
	persisted, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("reload persisted config: %v", err)
	}
	if persisted.Guardrail.Mode != "action" {
		t.Fatalf("persisted mode = %q, want action", persisted.Guardrail.Mode)
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["live"] != true || response["mode"] != "action" {
		t.Fatalf("response = %#v, want live action", response)
	}
}

func TestReloadPredicatesRestartLLMConsumers(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{}
	oldCfg.LLM.Model = "openai/gpt-4o-mini"
	newCfg.LLM.Model = "openai/gpt-4.1-mini"

	if !guardrailNeedsRestart(oldCfg, newCfg) {
		t.Fatal("guardrailNeedsRestart returned false for llm change")
	}
	if !watcherNeedsRestart(oldCfg, newCfg) {
		t.Fatal("watcherNeedsRestart returned false for llm change")
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
