// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestConfigManagerHotBundleAuditWaitsForWriterAndEmitsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	configBytes := func(level, host string) []byte {
		return []byte("config_version: 8\ngateway:\n  config_reload:\n    mode: restart\nguardrail:\n  mode: action\n  block_at: " + level + "\n  host: " + host + "\nobservability: {}\n")
	}
	writeBundle := func(version uint64, id, summary string, raw []byte, afterWrite func()) <-chan error {
		result := make(chan error, 1)
		go func() {
			_, err := configwrite.Locked(context.Background(), path, configwrite.Options{
				Actor: "operator:manual-r3", LocalActor: "os:uid:0:root", Lifecycle: true,
				Reason: configwrite.BundleReason(id, version, summary),
				Bundle: configwrite.BundleRef{ID: id, Version: version, SignerKeyID: "mgmtp1-a"},
			}, func() (bool, error) {
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					return false, err
				}
				if afterWrite != nil {
					afterWrite()
				}
				return true, nil
			})
			result <- err
		}()
		return result
	}
	const firstID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T7"
	const hotID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	const restartID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T9"
	const assetID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8TA"
	initialRaw := configBytes("HIGH", "127.0.0.1")
	if err := <-writeBundle(1, firstID, "initial", initialRaw, nil); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.Enterprise.Profile = "standalone"
	_, logger := newNativeSkillRuntimeTestStore(t)
	capture := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(capture)
	applied := make(chan struct{}, 1)
	mgr := newConfigManagerWithSnapshot(path, initial, logger, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		select {
		case applied <- struct{}{}:
		default:
		}
		return nil
	})
	load := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
		candidate, err := load(source, raw)
		if err == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.Enterprise.Profile = "standalone"
		}
		return candidate, err
	}
	mgr.setStartupSource(path, initialRaw)
	mgr.appliedRaw = initialRaw

	// The lifecycle writes config.yaml before config.generation.json while
	// holding the lock. Force the watcher into that gap.
	written := make(chan struct{})
	release := make(chan struct{})
	hotRaw := configBytes("MEDIUM", "127.0.0.1")
	writer := writeBundle(2, hotID, "changed marker title", hotRaw, func() {
		close(written)
		<-release
	})
	<-written
	reloaded := make(chan error, 1)
	go func() { reloaded <- mgr.ReloadAssets(context.Background(), "api:policy_reload") }()
	select {
	case err := <-reloaded:
		if err == nil || !strings.Contains(err.Error(), "signed policy bundle") {
			t.Fatalf("reload before the bundle generation receipt = %v; want signed-bundle refusal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reload while the bundle writer is paused did not refuse")
	}
	select {
	case <-applied:
		t.Fatal("unreceipted bundle bytes became active")
	default:
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(context.Background(), "signed bundle generation ready"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-applied:
	default:
		t.Fatal("receipted bundle bytes were not applied")
	}
	if current := mgr.Current(); current.Guardrail.BlockAt != "MEDIUM" || mgr.gen.Load() != 1 {
		t.Fatalf("synchronous policy reload = generation %d, block_at %q", mgr.gen.Load(), current.Guardrail.BlockAt)
	}
	check := func(want int, id string, restart bool, changedPath string) {
		t.Helper()
		records := capture.snapshot()
		if len(records) != want {
			t.Fatalf("audit records = %d, want %d", len(records), want)
		}
		if want == 0 {
			return
		}
		record := records[want-1]
		if record.EventName() != observability.EventName(observability.TelemetryEventConfigChangeApplied) {
			t.Fatalf("event = %s", record.EventName())
		}
		encoded, err := record.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{
			`"defenseclaw.admin.operation":"bundle-apply"`,
			`"defenseclaw.admin.actor_ref":"os:uid:0:root"`,
			`"defenseclaw.admin.principal_ref":"operator:manual-r3"`,
			`"defenseclaw.policy.bundle.id":"` + id + `"`,
			`"defenseclaw.policy.bundle.version":` + strconv.Itoa(want+1),
		} {
			if !strings.Contains(string(encoded), field) {
				t.Fatalf("audit record lacks %s: %s", field, encoded)
			}
		}
		var envelope struct {
			Body map[string]json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(encoded, &envelope); err != nil {
			t.Fatal(err)
		}
		var afterJSON string
		if err := json.Unmarshal(envelope.Body["defenseclaw.admin.after_state"], &afterJSON); err != nil {
			t.Fatal(err)
		}
		var after map[string]any
		if err := json.Unmarshal([]byte(afterJSON), &after); err != nil {
			t.Fatal(err)
		}
		if after["generation_before"] != float64(want) || after["generation_after"] != float64(want+1) || after["restart"] != restart {
			t.Fatalf("bundle generation/restart = %v", after)
		}
		if after["policy_generation_before"] != float64(want-1) || after["policy_generation_after"] != float64(want) {
			t.Fatalf("runtime generation = %v", after)
		}
		var diffJSON string
		if err := json.Unmarshal(envelope.Body["defenseclaw.admin.diff"], &diffJSON); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(diffJSON, "\"path\":\""+changedPath+"\"") || strings.Contains(string(encoded), "\"MEDIUM\"") {
			t.Fatalf("audit diff lacks %s or exposes a policy value: %s", changedPath, encoded)
		}
	}
	check(1, hotID, false, "guardrail.block_at")
	if err := mgr.Reload(context.Background(), "unchanged bundle reapply"); err != nil {
		t.Fatal(err)
	}
	check(1, hotID, false, "guardrail.block_at")
	if err := <-writeBundle(3, restartID, "listener change", configBytes("MEDIUM", "0.0.0.0"), nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "restart-required bundle"); err != nil {
		t.Fatal(err)
	}
	check(2, restartID, true, "guardrail.host")
	// A policy asset can change under a new bundle without changing YAML.
	// The plain config watcher must leave that writer for the asset swap.
	assetRaw := configBytes("MEDIUM", "0.0.0.0")
	if err := <-writeBundle(4, assetID, "custom marker title", assetRaw, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background(), "unchanged YAML"); err != nil {
		t.Fatal(err)
	}
	check(3, assetID, false, configDiffAssets)
	if err := mgr.ReloadAssets(context.Background(), "asset event after the bundle was applied"); err == nil ||
		!strings.Contains(err.Error(), "signed policy bundle") {
		t.Fatalf("unsigned asset reload after the bundle was applied = %v; want signed-bundle refusal", err)
	}
	check(3, assetID, false, configDiffAssets)
	if err := logger.LogPolicyBundleReceipt("operator:manual-r3", audit.PolicyBundle{ID: hotID, Version: 2},
		audit.PolicyBundleReceipt{ReceiptID: hotID, State: audit.PolicyBundleConfirmed,
			ConfigGeneration: 2, EnforcingVersion: 2, Restart: false}); err != nil {
		t.Fatal(err)
	}
	records := capture.snapshot()
	if len(records) != 4 || records[3].EventName() != observability.EventName(observability.TelemetryEventConfigBundleReceipt) {
		t.Fatalf("receipt produced %d records, want one separate config.bundle.receipt", len(records))
	}
}

// A policy-only bundle can advance its signed generation without changing
// any parsed config field. The lifecycle's generation-file write must wake
// the running gateway, rebuild its policy, and emit the attributed audit row.
func TestConfigManagerHotPolicyOnlyBundleGenerationEventAudited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("config_version: 9\nguardrail:\n  mode: action\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(version uint64, id string) {
		t.Helper()
		if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{
			Actor: "operator:manual-r4", Lifecycle: true,
			Reason: configwrite.BundleReason(id, version, "policy asset changed"),
			Bundle: configwrite.BundleRef{ID: id, Version: version, SignerKeyID: "mgmtp1-a"},
		}, func() (bool, error) { return true, nil }); err != nil {
			t.Fatal(err)
		}
	}
	const firstID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T7"
	const hotID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	write(1, firstID)
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode = "managed_enterprise"
	initial.Enterprise.Profile = "standalone"
	_, logger := newNativeSkillRuntimeTestStore(t)
	capture := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(capture)
	applied := make(chan ConfigDiff, 1)
	mgr := newConfigManagerWithSnapshot(path, initial, logger, nil, "", func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
		applied <- diff
		return nil
	})
	load := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
		candidate, err := load(source, raw)
		if err == nil {
			candidate.DeploymentMode = "managed_enterprise"
			candidate.Enterprise.Profile = "standalone"
		}
		return candidate, err
	}
	mgr.setStartupSource(path, raw)
	mgr.appliedRaw = raw
	compiled, err := config.ParseCompileObservabilityV8(path, raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: initial.DataDir})
	if err != nil {
		t.Fatal(err)
	}
	mgr.bindInitialObservabilityV8Plan(compiled.Plan)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	write(2, hotID)
	select {
	case diff := <-applied:
		// The bundle must rebuild hot (no restart) on every platform. On Windows the
		// rebuilt config also lists the guardrail section (policy_dir) next to or
		// instead of the assets entry, so the exact asset-only classification is
		// only required elsewhere; the audited restart:false check below is strict
		// everywhere.
		if len(diff.RestartRequired) != 0 {
			t.Fatalf("hot policy bundle needs a restart: %+v", diff)
		}
		if runtime.GOOS != "windows" && (len(diff.Changed) != 1 || diff.Changed[0] != configDiffAssets) {
			t.Fatalf("hot policy asset diff = %+v", diff)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("generation-file event did not rebuild the hot bundle")
	}
	deadline := time.After(5 * time.Second)
	for len(capture.snapshot()) == 0 {
		select {
		case <-deadline:
			t.Fatal("hot bundle produced no config.change.applied")
		case <-time.After(10 * time.Millisecond):
		}
	}
	records := capture.snapshot()
	if len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventConfigChangeApplied) {
		t.Fatalf("hot bundle audit records = %d: %+v", len(records), records)
	}
	encoded, err := records[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"defenseclaw.admin.operation":"bundle-apply"`,
		`"defenseclaw.admin.principal_ref":"operator:manual-r4"`,
		`"defenseclaw.policy.bundle.id":"` + hotID + `"`,
		`"defenseclaw.policy.bundle.version":2`,
	} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("hot bundle audit lacks %s: %s", field, encoded)
		}
	}
	var envelope struct {
		Body map[string]json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	var afterJSON string
	if err := json.Unmarshal(envelope.Body["defenseclaw.admin.after_state"], &afterJSON); err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	if err := json.Unmarshal([]byte(afterJSON), &after); err != nil {
		t.Fatal(err)
	}
	if after["generation_before"] != float64(1) || after["generation_after"] != float64(2) || after["restart"] != false {
		t.Fatalf("hot bundle generation/restart = %v", after)
	}
	cancel()
	<-done
}
