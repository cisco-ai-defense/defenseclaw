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
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// A host a 1.0.0-1.0.2 upgrade migrated keeps the Cursor fail mode that
// migration rewrote to open, which managed hooks now honour. ensure restores
// closed once and says so; an open the administrator sets afterwards stays.
func TestEnsureRestoresMigratedCursorFailModeOnce(t *testing.T) {
	const key = "guardrail.connectors.cursor.hook_fail_mode"
	h := newTestHost(t, "linux")
	admin := strings.Replace(string(DefaultConfig(h.env.Layout)), "  mode: observe\n",
		"  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", 1)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte(admin), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	recordPath := h.env.P(config.MigrationRecordPath(h.env.Layout.ConfigPath))
	writeRecord := func(record config.MigrationRecord) {
		t.Helper()
		raw, _ := json.Marshal(record)
		if err := os.WriteFile(recordPath, raw, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	readRecord := func() config.MigrationRecord {
		t.Helper()
		var record config.MigrationRecord
		raw, err := os.ReadFile(recordPath)
		if err != nil || json.Unmarshal(raw, &record) != nil {
			t.Fatalf("read migration-v9.json: %v", err)
		}
		return record
	}

	// Without a record nothing changes.
	if r := h.run(Options{Action: ActionEnsure, Reason: "path"}); !r.Noop || !strings.Contains(h.read(h.env.Layout.ConfigPath), "hook_fail_mode: open") {
		t.Fatalf("ensure without a record: noop=%v changes=%+v", r.Noop, r.Changes)
	}

	// The record the 1.0.0-1.0.2 migration wrote for its rewrite.
	writeRecord(config.MigrationRecord{
		SchemaVersion: config.MigrationRecordSchemaVersion, FromVersion: 8, ToVersion: 9, Actor: "lifecycle",
		MigratedAt:   "2026-09-01T00:00:00Z",
		SourceSHA256: strings.Repeat("b", 64), ResultSHA256: sha256Bytes([]byte(h.read(h.env.Layout.ConfigPath))),
		Moved: []config.MigrationMove{{Source: "config", From: key, To: key, Value: "open"}},
	})
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	requireOK(t, r)
	if got := h.read(h.env.Layout.ConfigPath); !strings.Contains(got, "hook_fail_mode: closed") {
		t.Fatalf("the migrated open was not restored:\n%s", got)
	}
	if want := "restored " + key + " to closed: the 1.0.x v9 migration had rewritten it to open (not an admin choice)"; !strings.Contains(strings.Join(r.Changes, "\n"), want) {
		t.Fatalf("changes = %+v", r.Changes)
	}
	if record := readRecord(); len(record.Repaired) != 1 || record.Repaired[0].To != key ||
		record.ResultSHA256 != sha256Bytes([]byte(h.read(h.env.Layout.ConfigPath))) {
		t.Fatalf("record = %+v", record)
	}
	if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); !again.Noop {
		t.Fatalf("the repair does not settle: %+v", again.Changes)
	}

	// The administrator opens it after the repair: it stays open.
	editConfigInPlace(t, h, "hook_fail_mode: closed", "hook_fail_mode: open")
	requireOK(t, h.run(Options{Action: ActionEnsure, Reason: "path"}))
	if got := h.read(h.env.Layout.ConfigPath); !strings.Contains(got, "hook_fail_mode: open") {
		t.Fatalf("an administrator open set after the repair was undone:\n%s", got)
	}
}

// Re-review P1: a config a confirmed signed policy bundle installed is the
// administrator's signed choice, also when its bytes match an old v9
// migration result: ensure never repairs its explicit open.
func TestEnsureNeverRepairsABundleConfig(t *testing.T) {
	const key = "guardrail.connectors.cursor.hook_fail_mode"
	h := newTestHost(t, "linux")
	admin := strings.Replace(string(DefaultConfig(h.env.Layout)), "  mode: observe\n",
		"  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", 1)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte(admin), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	installed := h.read(h.env.Layout.ConfigPath)
	raw, _ := json.Marshal(config.MigrationRecord{
		SchemaVersion: config.MigrationRecordSchemaVersion, FromVersion: 8, ToVersion: 9, Actor: "lifecycle",
		MigratedAt:   "2026-09-01T00:00:00Z",
		SourceSHA256: strings.Repeat("b", 64), ResultSHA256: sha256Bytes([]byte(installed)),
		Moved: []config.MigrationMove{{Source: "config", From: key, To: key, Value: "open"}},
	})
	if err := os.WriteFile(h.env.P(config.MigrationRecordPath(h.env.Layout.ConfigPath)), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	generationPath := h.env.P(configwrite.GenerationPath(h.env.Layout.ConfigPath))
	state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	state.BundleID, state.BundleVersion, state.SignerKeyID = "acme-endpoints", 4, "k1"
	attributed, _ := json.Marshal(state)
	if err := os.WriteFile(generationPath, attributed, 0o640); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	requireOK(t, r)
	if got := h.read(h.env.Layout.ConfigPath); got != installed || strings.Contains(strings.Join(r.Changes, "\n"), "restored "+key) {
		t.Fatalf("a confirmed bundle's config was repaired: changes=%+v\n%s", r.Changes, got)
	}
}

// G-small loop 4, finding 2 (the Unix lifecycle of the same rule): a
// migration-v9.json that is there but cannot be read (not a regular file,
// past the input bound) or decoded is not "no record". ensure fails and
// names it, and the Cursor fail mode it may prove rewritten is left as it
// is, never reported as settled; once it is gone, ensure is a no-op again.
func TestEnsureRefusesAMigrationRecordItCannotRead(t *testing.T) {
	h := newTestHost(t, "linux")
	admin := strings.Replace(string(DefaultConfig(h.env.Layout)), "  mode: observe\n",
		"  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", 1)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte(admin), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	installed := h.read(h.env.Layout.ConfigPath)
	recordPath := h.env.P(config.MigrationRecordPath(h.env.Layout.ConfigPath))
	valid := filepath.Join(t.TempDir(), "valid-record.json")
	if err := os.WriteFile(valid, []byte(`{"schema_version":1,"from_version":8,"to_version":9}`), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		place func() error
	}{
		{"undecodable", func() error { return os.WriteFile(recordPath, []byte(`{"schema_version":`), 0o640) }},
		// G-small loop round 2: a record that decodes without the fields
		// every migration writes is not "no record".
		{"an empty object", func() error { return os.WriteFile(recordPath, []byte(`{}`), 0o640) }},
		{"null", func() error { return os.WriteFile(recordPath, []byte(`null`), 0o640) }},
		{"past the input bound", func() error {
			if err := os.WriteFile(recordPath, []byte(`{"schema_version":1}`), 0o640); err != nil {
				return err
			}
			return os.Truncate(recordPath, maxInputBytes+1)
		}},
		{"a directory", func() error { return os.Mkdir(recordPath, 0o750) }},
		{"a symlink", func() error { return os.Symlink(valid, recordPath) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.RemoveAll(recordPath); err != nil {
				t.Fatal(err)
			}
			if err := tc.place(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(recordPath) })
			r := h.run(Options{Action: ActionEnsure, Reason: "path"})
			if r.OK || r.Noop {
				t.Fatalf("ensure with an unreadable record: ok=%v noop=%v changes=%+v", r.OK, r.Noop, r.Changes)
			}
			named := false
			for _, e := range r.Errors {
				named = named || strings.Contains(e.Message, config.MigrationV9RecordFile)
			}
			if !named {
				t.Fatalf("errors %+v do not name %s", r.Errors, config.MigrationV9RecordFile)
			}
			if got := h.read(h.env.Layout.ConfigPath); got != installed {
				t.Fatalf("the config changed under an unreadable record:\n%s", got)
			}
		})
	}
	if err := os.RemoveAll(recordPath); err != nil {
		t.Fatal(err)
	}
	if r := h.run(Options{Action: ActionEnsure, Reason: "path"}); !r.OK || !r.Noop {
		t.Fatalf("ensure without a record: ok=%v noop=%v errors=%+v", r.OK, r.Noop, r.Errors)
	}
}
