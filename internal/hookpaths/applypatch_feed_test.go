// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Classifier refix 1 (RV3-1): a patch fed from a staged file is judged by the
// directives in that file. The file is read only when nothing in the command
// can change it first; otherwise, or when it cannot be read, the targets stay
// unknown (TGT-0194).
func TestApplyPatchStagedFileTargets(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	envelope := func(body string) string { return "*** Begin Patch\n" + body + "*** End Patch\n" }
	for name, data := range map[string]string{
		"key.patch":   envelope("*** Update File: " + keys + "\n@@\n+k\n"),
		"ok.patch":    envelope("*** Update File: notes.txt\n@@\n+x\n"),
		"crlf.patch":  "*** Begin Patch\r\n*** Add File: " + keys + "\r\n+k\r\n*** End Patch\r\n",
		"plain.patch": "not a patch\n",
	} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	notes := filepath.Join(project, "notes.txt")
	inline := "printf '" + envelope("*** Update File: notes.txt\n@@\n+x\n") + "'"
	for _, tc := range []struct {
		command string
		want    string // a target that must be listed
	}{
		{"apply_patch < key.patch", keys},
		{"apply_patch <key.patch", keys},
		{"env apply_patch < key.patch", keys},
		{"cat key.patch | apply_patch", keys},
		{"cat 'key.patch' | apply_patch", keys},
		{"Get-Content key.patch | apply_patch", keys},
		{"Get-Content -Raw -Path \"key.patch\" | apply_patch", keys},
		{"gc key.patch | apply_patch", keys},
		{"apply_patch < " + filepath.ToSlash(filepath.Join(project, "key.patch")), keys},
		{"apply_patch < ~/proj/key.patch", keys},
		{"apply_patch < crlf.patch", keys},
		{inline + "\napply_patch < key.patch", keys},
		{inline + " | apply_patch < key.patch", keys},
		{inline + "; cat key.patch | apply_patch", keys},
		{"echo start && apply_patch < key.patch; echo done", keys},
		{"apply_patch < ok.patch", notes},
		{"cat ok.patch | apply_patch", notes},
	} {
		targets, ok := ApplyPatchWriteTargets("Bash", nil, tc.command, project, home)
		if !ok || !slices.Contains(targets, tc.want) {
			t.Errorf("ApplyPatchWriteTargets(%q) = %v, %t; want %s listed", tc.command, targets, ok, tc.want)
		}
	}
	// Unknown: the file cannot be read, holds no envelope, may change before
	// the feed, or the feed is not a static single file.
	for _, command := range []string{
		"apply_patch < missing.patch",
		"apply_patch < plain.patch",
		"cp key.patch ok.patch; apply_patch < ok.patch",
		"printf x > ok.patch; apply_patch < ok.patch",
		"apply_patch <<'P'\n" + envelope("*** Add File: ok.patch\n+x\n") + "P\napply_patch < ok.patch",
		`apply_patch < "$F"`,
		"apply_patch < $(echo ok.patch)",
		"cat *.patch | apply_patch",
		"cat ok.patch key.patch | apply_patch",
		`echo \'; cp key.patch ok.patch; echo \'; apply_patch < ok.patch`,
		"cd sub && apply_patch < ok.patch",
		"(apply_patch < ok.patch)",
		"FOO=1 apply_patch < ok.patch",
		"apply_patch < ok.patch 2>&1",
		"Get-Content env:PATCH | apply_patch",
		"Get-Content ok.patch:stream | apply_patch",
		`cat ok\.patch | apply_patch`,
		"cat ok.patch | tee ok.patch | apply_patch",
	} {
		if targets, ok := ApplyPatchWriteTargets("Bash", nil, command, project, home); ok {
			t.Errorf("ApplyPatchWriteTargets(%q) = %v, known; want unknown", command, targets)
		}
	}
}
