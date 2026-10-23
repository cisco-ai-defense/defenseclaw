// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Only an unfinished committed uninstall is replayed, in the mode its
// tombstone recorded. A settled state-keeping uninstall keeps its tombstone
// for good; replaying it ran the purge it never asked for.
func TestStandaloneCommittedUninstallUnsettled(t *testing.T) {
	for _, tc := range []struct {
		name      string
		record    string
		root      bool
		journal   bool
		unsettled bool
		err       bool
	}{
		{name: "settled state-keeping uninstall", record: `{"installed":false,"uninstall_purge_requested":false}`},
		{name: "settled pre-1.0.4 tombstone", record: "\ufeff" + `{"installed":false}`},
		{name: "recorded purge not finished", record: `{"installed":false,"uninstall_purge_requested":true}`, unsettled: true},
		{name: "install root remains", record: `{"installed":false,"uninstall_purge_requested":false}`, root: true, unsettled: true},
		{name: "pre-1.0.4 teardown journal remains", record: `{"installed":false}`, journal: true, unsettled: true},
		{name: "teardown journal remains", record: `{"installed":false,"uninstall_purge_requested":false}`, journal: true, unsettled: true},
		{name: "string purge mode", record: `{"installed":false,"uninstall_purge_requested":"false"}`, err: true},
		{name: "null purge mode", record: `{"installed":false,"uninstall_purge_requested":null}`, err: true},
		{name: "invalid mode is refused before the folders", record: `{"installed":false,"uninstall_purge_requested":1}`, root: true, err: true},
		// The per-user purge (Setup PURGE=1) is part of the purge: its
		// tombstone is unsettled until that purge removed it, and a malformed
		// or orphaned per-user mode is refused.
		{name: "recorded per-user purge not finished", record: `{"installed":false,"uninstall_purge_requested":true,"uninstall_purge_user_state_requested":true}`, unsettled: true},
		{name: "recorded purge without the per-user purge", record: `{"installed":false,"uninstall_purge_requested":true,"uninstall_purge_user_state_requested":false}`, unsettled: true},
		{name: "string per-user purge mode", record: `{"installed":false,"uninstall_purge_requested":true,"uninstall_purge_user_state_requested":"true"}`, err: true},
		{name: "null per-user purge mode", record: `{"installed":false,"uninstall_purge_requested":true,"uninstall_purge_user_state_requested":null}`, err: true},
		{name: "per-user purge without its purge", record: `{"installed":false,"uninstall_purge_requested":false,"uninstall_purge_user_state_requested":true}`, err: true},
		{name: "per-user purge with no recorded purge", record: `{"installed":false,"uninstall_purge_user_state_requested":true}`, err: true},
		{name: "record turned installed", record: `{"installed":true}`, err: true},
		{name: "record without installed", record: `{}`, err: true},
		{name: "unparseable record", record: `{`, err: true},
		{name: "missing record", err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			layout := managed.StandaloneLayout{
				InstallRoot:  filepath.Join(base, "Program Files", "Cisco", "DefenseClaw"),
				LifecycleDir: filepath.Join(base, "ProgramData", "Cisco", "DefenseClaw", "install"),
			}
			if err := os.MkdirAll(layout.LifecycleDir, 0o700); err != nil {
				t.Fatal(err)
			}
			metadata := filepath.Join(layout.LifecycleDir, "deployment.json")
			if tc.record != "" {
				if err := os.WriteFile(metadata, []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.root {
				if err := os.MkdirAll(layout.InstallRoot, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.journal {
				if err := os.WriteFile(filepath.Join(layout.LifecycleDir, "managed-hooks-teardown-journal.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			unsettled, err := standaloneCommittedUninstallUnsettled(layout, metadata)
			if (err != nil) != tc.err || unsettled != tc.unsettled {
				t.Fatalf("unsettled=%t error=%v, want unsettled=%t error=%t", unsettled, err, tc.unsettled, tc.err)
			}
		})
	}
	if _, err := standaloneCommittedUninstallUnsettled(managed.StandaloneLayout{}, writeTombstone(t, `{"installed":false}`)); err == nil {
		t.Fatal("a layout without folders proved the uninstall settled")
	}
}

func writeTombstone(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
