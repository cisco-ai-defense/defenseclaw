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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Follow-ups of GAP-1928 (review RV1928) through the lifecycle and the
// guardian check: GAP-1966, GAP-1967, GAP-1968.

// GAP-1966: a [hooks.<Event>] table between DefenseClaw's blocks leaves a
// file that re-renders to itself but no longer parses; the guardian missed
// it. A byte order mark added alone was missed the same way (RV1928 P4).
func TestGAP1966GuardianPutsBackACodexRequirementsThatNoLongerParses(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for name, mk := range map[string]func(string) string{
			"table collision between": func(want string) string {
				event := regexp.MustCompile(`\[\[hooks\.([A-Za-z]+)\]\]`).FindStringSubmatch(want)
				if event == nil {
					t.Fatalf("no hook event in:\n%s", want)
				}
				return strings.Replace(adminNote(want), "# administrator note\n", "[hooks."+event[1]+"]\n", 1)
			},
			"byte order mark added": func(want string) string { return "\ufeff" + want },
		} {
			t.Run(goos+"/"+name, func(t *testing.T) {
				c := newCodexHealHost(t, goos)
				c.write(t, mk(c.want))
				if got := c.env.TamperedFiles(); !reflect.DeepEqual(got, []string{codexRequirements}) {
					t.Fatalf("the guardian check found %v", got)
				}
				requireOK(t, c.run(Options{Action: ActionEnsure, Reason: "path"}))
				c.requireHealed(t, "ensure")
			})
		}
	}
}

// GAP-1967: ensure, repair and the guardian's restore replaced an
// administrator's edit with no copy, and the change line said only that
// DefenseClaw's entries were rewritten.
func TestGAP1967EnsureRepairAndGuardianRestoreKeepTheReplacedEdit(t *testing.T) {
	for name, tc := range map[string]struct {
		action, reason string
		edit           func(string) string
	}{
		"ensure":           {ActionEnsure, "", adminNote},
		"repair":           {ActionRepair, "", adminNote},
		"guardian restore": {ActionEnsure, "path", func(want string) string { return want + "# tampered\n" }},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCodexHealHost(t, "linux")
			edited := tc.edit(c.want)
			c.write(t, edited)
			result := c.run(Options{Action: tc.action, Reason: tc.reason})
			requireOK(t, result)
			c.requireHealed(t, tc.action)
			dir := filepath.Join(filepath.Dir(c.env.P(codexRequirements)), "defenseclaw-replaced")
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("copies in %s: %v %v", dir, entries, err)
			}
			saved := filepath.Join(dir, entries[0].Name())
			if got := c.read(strings.TrimPrefix(saved, c.env.Root)); got != edited {
				t.Fatalf("the copy is not the replaced file:\n%s", got)
			}
			changes := strings.Join(result.Changes, "\n")
			if !strings.Contains(changes, "restored the published codex machine policy") || !strings.Contains(changes, "the edited file is saved at "+saved) {
				t.Fatalf("the change line does not name the copy %s: %v", saved, result.Changes)
			}
		})
	}
}

// GAP-1968: a symbolic link put in place of requirements.toml made ensure
// and repair fail "is not a regular file", and the guardian then stopped
// listing it. The link is replaced, never followed.
func TestGAP1968EnsureAndRepairReplaceASymbolicLinkSwappedForCodexRequirements(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct{ action, reason string }{{ActionEnsure, "path"}, {ActionEnsure, ""}, {ActionRepair, ""}} {
			t.Run(goos+"/"+tc.action+tc.reason, func(t *testing.T) {
				c := newCodexHealHost(t, goos)
				path := c.env.P(codexRequirements)
				other := filepath.Join(t.TempDir(), "other.toml")
				linked := strings.Replace(adminNote(c.want), "# administrator note\n", "[features]\nhooks = false\n", 1)
				if err := os.WriteFile(other, []byte(linked), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
				if got := c.env.TamperedFiles(); !reflect.DeepEqual(got, []string{codexRequirements}) {
					t.Fatalf("the guardian check found %v", got)
				}
				result := c.run(Options{Action: tc.action, Reason: tc.reason})
				requireOK(t, result)
				if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
					t.Fatalf("the link was not replaced by a regular file: %v %v", info, err)
				}
				if data, _ := os.ReadFile(other); string(data) != linked {
					t.Fatalf("%s wrote through the link:\n%s", tc.action, data)
				}
				if !strings.Contains(strings.Join(result.Changes, "\n"), "which was a symbolic link to "+other) {
					t.Fatalf("the change line does not name the link: %v", result.Changes)
				}
				c.requireHealed(t, tc.action)
			})
		}
	}
}
