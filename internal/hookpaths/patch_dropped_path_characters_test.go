// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
)

// droppedCharFixture is a working directory and a home of this host: the
// directives below name absolute paths, which a Windows host reads only with a
// drive letter.
func droppedCharFixture(t *testing.T) (cwd, home string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "work")
	return filepath.Join(home, "project"), home
}

// The hook client lists the file the apply_patch tool opens for a directive,
// which has no tab or carriage return in its name, for a patch tool call and
// for a shell command that feeds the envelope, so the protected-file checks
// of the user-side hook and of the gateway read the same name.
func TestApplyPatchTargetsListTheNameTheToolOpens(t *testing.T) {
	cwd, home := droppedCharFixture(t)
	want := filepath.Join(home, ".netrc")
	for _, spelled := range []string{".ne\ttrc", "\t.netrc", ".netrc\t", ".ne\rtrc"} {
		for _, directive := range []string{"Add File", "Update File", "Delete File"} {
			envelope := "*** Begin Patch\n*** " + directive + ": " + home + "/" + spelled + "\n*** End Patch"
			args, err := json.Marshal(map[string]string{"command": envelope})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := ApplyPatchLexicalTargets("apply_patch", args, cwd, home)
			if !ok || !slices.Contains(targets, want) {
				t.Errorf("tool %s %q: targets = %v ok = %v, want %s", directive, spelled, targets, ok, want)
			}
			command := "apply_patch <<'EOF'\n" + envelope + "\nEOF"
			targets, ok = ApplyPatchLexicalCommandTargets("shell", nil, command, cwd, home)
			if !ok || !slices.Contains(targets, want) {
				t.Errorf("shell %s %q: targets = %v ok = %v, want %s", directive, spelled, targets, ok, want)
			}
		}
	}
}

// The authorized-keys check reads the opened name too.
func TestApplyPatchNamesProtectedTargetReadsTheNameTheToolOpens(t *testing.T) {
	cwd, home := droppedCharFixture(t)
	for _, spelled := range []string{".ssh/authorized_keys", ".ssh/author\tized_keys", ".ssh/authorized_keys\t", "\t.ssh/authorized_keys", ".ssh/author\rized_keys"} {
		args, err := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + home + "/" + spelled + "\n+x\n*** End Patch"})
		if err != nil {
			t.Fatal(err)
		}
		if !ApplyPatchNamesProtectedTarget("apply_patch", args, cwd, home, nil) {
			t.Errorf("%q: not named as the protected authorized-keys file", spelled)
		}
	}
	args, err := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + home + "/.ssh/authorized_keys.bak\n+x\n*** End Patch"})
	if err != nil {
		t.Fatal(err)
	}
	if ApplyPatchNamesProtectedTarget("apply_patch", args, cwd, home, nil) {
		t.Error("a copy of the authorized-keys file is named as the protected file")
	}
}
