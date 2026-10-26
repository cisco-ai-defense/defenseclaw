// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

func TestConfigManagerAttributesPendingListenerChangeOnce(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 9\ndata_dir: " + filepath.ToSlash(dir) + "\ngateway:\n  api_port: 19080\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	_, logger := newNativeSkillRuntimeTestStore(t)
	capture := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(capture)
	mgr := newConfigManagerWithSnapshot(path, initial, logger, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			return nil
		})
	mgr.appliedRaw = raw
	mgr.appliedGenerationKnown = true
	if err := mgr.Reload(t.Context(), "settle"); err != nil {
		t.Fatal(err)
	}
	after := bytes.ReplaceAll(raw, []byte("19080"), []byte("19081"))
	if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{Actor: "cli:operator", Reason: "defenseclaw config set"},
		func() (bool, error) { return true, os.WriteFile(path, after, 0o600) }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := mgr.Reload(t.Context(), "test"); err != nil {
			t.Fatal(err)
		}
	}
	if mgr.Current().Gateway.APIPort != 19080 {
		t.Fatal("pending listener was activated without a restart")
	}
	records := capture.snapshot()
	if len(records) != 1 {
		t.Fatalf("pending write produced %d audit records, want exactly one", len(records))
	}
	wire, err := json.Marshal(records[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cli:operator", "gateway.api_port", "config_generation", "restart_required"} {
		if !bytes.Contains(wire, []byte(want)) {
			t.Fatalf("pending audit omitted %s: %s", want, wire)
		}
	}
	// Cancelling the pending move also changes saved intent, even though
	// the resulting listener already matches the running gateway.
	if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{Actor: "cli:operator", Reason: "cancel listener move"},
		func() (bool, error) { return true, os.WriteFile(path, raw, 0o600) }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := mgr.Reload(t.Context(), "cancel"); err != nil {
			t.Fatal(err)
		}
	}
	if records := capture.snapshot(); len(records) != 2 {
		t.Fatalf("cancelling the pending write produced %d total audit records, want exactly two", len(records))
	}
}

// An unchanged startup asset reconcile (errGenerationUnchanged) and a later
// event for the same config.yaml bytes must not repeat the boot writer's
// config.change.applied; the next real write is still attributed once.
func TestConfigManagerUnchangedStartupDoesNotRepeatWriterAudit(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	for _, startupKnown := range []bool{true, false} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		raw := []byte("config_version: 9\ndata_dir: " + filepath.ToSlash(dir) + "\ngateway:\n  api_port: 19080\nobservability: {}\n")
		if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{Actor: "cli:operator", Reason: "defenseclaw setup"},
			func() (bool, error) { return true, os.WriteFile(path, raw, 0o600) }); err != nil {
			t.Fatal(err)
		}
		initial, err := config.LoadRuntimeV8File(path)
		if err != nil {
			t.Fatal(err)
		}
		_, logger := newNativeSkillRuntimeTestStore(t)
		capture := &captureJudgeRuntimeV8Emitter{}
		logger.SetRuntimeV8Emitter(capture)
		mgr := newConfigManagerWithSnapshot(path, initial, logger, nil, "",
			func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
				if len(diff.Changed) == 1 && diff.Changed[0] == configDiffAssets {
					return errGenerationUnchanged
				}
				return nil
			})
		compiled, err := config.ParseCompileObservabilityV8(path, raw,
			config.ObservabilityV8CompileOptions{DefaultDataDir: initial.DataDir})
		if err != nil {
			t.Fatal(err)
		}
		mgr.bindInitialObservabilityV8Plan(compiled.Plan)
		if startupKnown {
			mgr.setStartupSource(path, raw)
		}
		if err := mgr.ReloadAssets(t.Context(), "startup_reconcile"); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := mgr.Reload(t.Context(), "fsnotify"); err != nil {
				t.Fatal(err)
			}
		}
		if records := capture.snapshot(); len(records) != 0 {
			wire, _ := json.Marshal(records)
			t.Fatalf("startup known %v: unchanged config produced %d audit records, want none: %s", startupKnown, len(records), wire)
		}
		after := bytes.ReplaceAll(raw, []byte("19080"), []byte("19081"))
		if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{Actor: "cli:second", Reason: "defenseclaw config set"},
			func() (bool, error) { return true, os.WriteFile(path, after, 0o600) }); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := mgr.Reload(t.Context(), "fsnotify"); err != nil {
				t.Fatal(err)
			}
		}
		records := capture.snapshot()
		if len(records) != 1 {
			t.Fatalf("startup known %v: a new write produced %d audit records, want exactly one", startupKnown, len(records))
		}
		if wire, _ := json.Marshal(records[0]); !bytes.Contains(wire, []byte("cli:second")) {
			t.Fatalf("startup known %v: new write not attributed to its writer: %s", startupKnown, wire)
		}
	}
}

// A config set saved while the gateway was stopped, then a hand edit, then
// the start: the startup asset reconcile (errGenerationUnchanged) records
// the hand edit as the next generation and must also apply it, so the first
// write after the start is attributed to its writer instead of
// "generations N-M applied together" (GAP-0005, GAP-1338 class).
func TestConfigManagerStoppedSetThenHandEditThenStartAttributesTheNextWrite(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 9\ndata_dir: " + filepath.ToSlash(dir) + "\ngateway:\n  api_port: 19080\nobservability: {}\n")
	write := func(actor string, data []byte) {
		t.Helper()
		if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{Actor: actor, Reason: "defenseclaw config set"},
			func() (bool, error) { return true, os.WriteFile(path, data, 0o600) }); err != nil {
			t.Fatal(err)
		}
	}
	write("cli:operator", raw)
	// Stopped: config set saves a generation no gateway applies.
	stoppedSet := bytes.ReplaceAll(raw, []byte("19080"), []byte("19081"))
	write("cli:operator", stoppedSet)
	// Still stopped: a hand edit.
	handEdited := append([]byte("# edited by hand while stopped\n"), stoppedSet...)
	if err := os.WriteFile(path, handEdited, 0o600); err != nil {
		t.Fatal(err)
	}
	// Start.
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	_, logger := newNativeSkillRuntimeTestStore(t)
	capture := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(capture)
	mgr := newConfigManagerWithSnapshot(path, initial, logger, nil, "",
		func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
			if len(diff.Changed) == 1 && diff.Changed[0] == configDiffAssets {
				return errGenerationUnchanged
			}
			return nil
		})
	compiled, err := config.ParseCompileObservabilityV8(path, handEdited,
		config.ObservabilityV8CompileOptions{DefaultDataDir: initial.DataDir})
	if err != nil {
		t.Fatal(err)
	}
	mgr.bindInitialObservabilityV8Plan(compiled.Plan)
	mgr.setStartupSource(path, handEdited)
	if err := mgr.ReloadAssets(t.Context(), "startup_reconcile"); err != nil {
		t.Fatal(err)
	}
	// The first config set after the start.
	write("cli:after", bytes.ReplaceAll(handEdited, []byte("19081"), []byte("19082")))
	for i := 0; i < 2; i++ {
		if err := mgr.Reload(t.Context(), "fsnotify"); err != nil {
			t.Fatal(err)
		}
	}
	records := capture.snapshot()
	if len(records) == 0 {
		t.Fatal("the first write after the start produced no audit record")
	}
	for _, record := range records {
		wire, _ := json.Marshal(record)
		if bytes.Contains(wire, []byte("applied together")) {
			t.Fatalf("a write after a stopped set and hand edit is unattributed: %s", wire)
		}
	}
	last, _ := json.Marshal(records[len(records)-1])
	if !bytes.Contains(last, []byte("cli:after")) {
		t.Fatalf("the first write after the start is not attributed to its writer: %s", last)
	}
}
