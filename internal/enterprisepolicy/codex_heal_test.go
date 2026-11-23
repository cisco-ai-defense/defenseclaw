// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"os"
	"strings"
	"testing"
)

// GAP-1928: a publish over a Codex requirements file edited since
// DefenseClaw wrote it put the edit into the file it then recorded, so a
// heal kept a tampered line and the lifecycle pinned it as trusted. Only a
// publish that adopts administrator edits takes the edited text now.
func TestGAP1928CodexPublishPutsBackThePublishedRequirements(t *testing.T) {
	opts := testOptions(t)
	path := codexPath(t, opts)
	writeFile(t, path, adminCodexRequirements)
	mustReconcile(t, codexTarget{}, opts)
	published := readFile(t, path)
	if CodexRequirementsDrifted(opts) {
		t.Fatal("a freshly published file reads as drifted")
	}
	for name, tampered := range map[string]string{
		"appended comment":      published + "# tampered\n",
		"administrator comment": "# tampered\n" + published,
		"changed value":         strings.Replace(published, `allowed_approval_policies = ["on-request"]`, `allowed_approval_policies = ["never"]`, 1),
		"changed managed value": strings.Replace(published, "allow_managed_hooks_only = true", "allow_managed_hooks_only = false", 1),
		"deleted":               "",
	} {
		t.Run(name, func(t *testing.T) {
			if tampered == published {
				t.Fatal("the tamper does not change the file")
			}
			if name == "deleted" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, path, tampered)
			}
			if !CodexRequirementsDrifted(opts) {
				t.Fatal("the drift check missed the change")
			}
			state := mustReconcile(t, codexTarget{}, opts)
			if !state.Changed || readFile(t, path) != published {
				t.Fatalf("publish did not put back the published file (changed=%v):\n%s", state.Changed, readFile(t, path))
			}
			if CodexRequirementsDrifted(opts) {
				t.Fatal("still drifted after the publish")
			}
		})
	}
	// The guardian restores damage to DefenseClaw's content, and leaves an
	// edit of the administrator's own text to verify and reconcile.
	for name, tc := range map[string]struct {
		data     string
		tampered bool
	}{
		"appended comment":      {published + "# tampered\n", true},
		"changed managed value": {strings.Replace(published, "allow_managed_hooks_only = true", "allow_managed_hooks_only = false", 1), true},
		"administrator comment": {adminNote(published), false},
		"published":             {published, false},
	} {
		writeFile(t, path, tc.data)
		if _, got := TamperedCodexRequirements(opts); got != tc.tampered {
			t.Errorf("%s: TamperedCodexRequirements = %v, want %v", name, got, tc.tampered)
		}
	}
	// Adopting keeps the administrator's edit and makes it the text later
	// heals put back.
	writeFile(t, path, adminNote(published))
	adopt := opts
	adopt.AdoptAdministratorEdits = true
	mustReconcile(t, codexTarget{}, adopt)
	accepted := readFile(t, path)
	if !strings.Contains(accepted, "# administrator note\n") {
		t.Fatalf("adopting dropped the administrator's edit:\n%s", accepted)
	}
	writeFile(t, path, accepted+"# tampered\n")
	mustReconcile(t, codexTarget{}, opts)
	if got := readFile(t, path); got != accepted {
		t.Fatalf("a heal after adopting did not put back the accepted file:\n%s", got)
	}
}

// adminNote adds a comment to the administrator's text of a published
// requirements file: after DefenseClaw's managed settings block, which
// comes first.
func adminNote(published string) string {
	end := codexHeadEnd + "\n"
	if !strings.Contains(published, end) {
		return "# administrator note\n" + published
	}
	return strings.Replace(published, end, end+"# administrator note\n", 1)
}
