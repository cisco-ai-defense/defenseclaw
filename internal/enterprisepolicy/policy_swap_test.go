// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adminStopHook = "\n[[hooks.Stop]]\n\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"/usr/local/bin/admin-stop\"\n"

// saveDuringSwap makes the hook that runs just before a shared policy file
// is compared and replaced save edit(current) to path, times times (-1:
// every time), as an administrator's editor or the managed-hook writer that
// saves after DefenseClaw read the file.
func saveDuringSwap(t *testing.T, path string, times int, edit func(string) string) *int {
	t.Helper()
	saved := new(int)
	previous := policyFileSwapHook
	t.Cleanup(func() { policyFileSwapHook = previous })
	policyFileSwapHook = func(at string) {
		if filepath.Clean(at) != filepath.Clean(path) || (times >= 0 && *saved >= times) {
			return
		}
		*saved++
		current, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		writeFile(t, path, edit(string(current)))
	}
	return saved
}

// GAP-0896 and GAP-0908: the machine-policy publisher and its removal read a
// shared vendor file (Codex requirements.toml, Cursor hooks.json), then wrote
// their earlier render through an unconditional rename or delete, losing an
// administrator's save made in between. Every such write is now a
// compare-and-swap of what was read, and the reconcile or removal renders
// again over the newer file, so the save is kept with DefenseClaw's entries.
func TestSharedPolicyWritesKeepAConcurrentAdministratorSave(t *testing.T) {
	type subject struct {
		name   string
		target Target
		path   func(*testing.T, Options) string
		admin  string
		edit   func(string) string
		mine   string
		theirs string
	}
	subjects := []subject{
		{name: "codex", target: codexTarget{}, path: codexPath, admin: adminCodexRequirements,
			edit: func(current string) string { return current + adminStopHook }, mine: "defenseclaw", theirs: "/usr/local/bin/admin-stop"},
		{name: "cursor", target: cursorTarget{}, path: cursorHooksPath, admin: adminCursorHooks,
			edit: func(current string) string {
				return strings.Replace(current, `"command": "/usr/local/bin/company-format"`, `"command": "/usr/local/bin/company-format"
      },
      {
        "command": "/usr/local/bin/admin-new"`, 1)
			}, mine: testHookBinary, theirs: "/usr/local/bin/admin-new"},
	}
	for _, s := range subjects {
		t.Run(s.name+"/a save during the publication", func(t *testing.T) {
			opts := testOptions(t)
			path := s.path(t, opts)
			writeFile(t, path, s.admin)
			saved := saveDuringSwap(t, path, 1, s.edit)
			if _, err := reconcileTarget(s.target, opts); err != nil {
				t.Fatal(err)
			}
			got := readFile(t, path)
			if *saved != 1 || !strings.Contains(got, s.theirs) || !strings.Contains(got, s.mine) {
				t.Fatalf("saves %d; the publication must keep the administrator's save and add DefenseClaw's entries:\n%s", *saved, got)
			}
			record, err := loadRecord(opts, s.target.Name())
			if err != nil || record == nil || record.PostimageSHA256 != sha256Hex([]byte(got)) {
				t.Fatalf("the ownership record %+v (%v) is not of the published file", record, err)
			}
			if _, err := removeTargetOwned(s.target, opts); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, path); !strings.Contains(got, s.theirs) || strings.Contains(got, s.mine) {
				t.Fatalf("removal after the rerendered publication:\n%s", got)
			}
		})
		t.Run(s.name+"/a save during the removal", func(t *testing.T) {
			opts := testOptions(t)
			path := s.path(t, opts)
			writeFile(t, path, s.admin)
			if _, err := reconcileTarget(s.target, opts); err != nil {
				t.Fatal(err)
			}
			saved := saveDuringSwap(t, path, 1, s.edit)
			if _, err := removeTargetOwned(s.target, opts); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, path); *saved != 1 || !strings.Contains(got, s.theirs) || strings.Contains(got, s.mine) {
				t.Fatalf("saves %d; the removal must keep the administrator's save and drop only DefenseClaw's entries:\n%s", *saved, got)
			}
		})
		t.Run(s.name+"/an administrator who keeps saving", func(t *testing.T) {
			opts := testOptions(t)
			path := s.path(t, opts)
			writeFile(t, path, s.admin)
			n := 0
			saveDuringSwap(t, path, -1, func(string) string {
				n++
				return s.edit(s.admin) + strings.Repeat("\n", n)
			})
			_, err := reconcileTarget(s.target, opts)
			if !errors.Is(err, errPolicyFileChanged) {
				t.Fatalf("reconcile = %v, want the conflict reported", err)
			}
			if got := readFile(t, path); got != s.edit(s.admin)+strings.Repeat("\n", n) || n != policyFileAttempts {
				t.Fatalf("after %d saves the file is not the administrator's last save:\n%s", n, got)
			}
		})
	}
}
