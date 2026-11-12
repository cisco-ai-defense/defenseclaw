// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestApplyPatchClientTargetsListTheRawSpellingOfAStepUpName: the hook client
// describes a patch header that steps up a directory by its raw spelling too,
// so the links before the step (the working directory is one) are walked as
// the operating system walks them and the gateway reads the answer by the same
// key. A name that cannot be walked, and a name without a step, keep their one
// clean target.
func TestApplyPatchClientTargetsListTheRawSpellingOfAStepUpName(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "proj")
	other := filepath.Join(root, "other")
	for _, dir := range []string{project, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(other, filepath.Join(project, "lnk")); err != nil {
		t.Fatal(err)
	}
	patch := func(name string) []byte {
		return []byte(`{"command":"apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: ` + name + `\n+x\n*** End Patch\nEOF\n"}`)
	}
	rows := []struct {
		name string
		cwd  string
		want []string
	}{
		{"lnk/../x.txt", project, []string{filepath.Join(project, "x.txt"), project + "/lnk/../x.txt"}},
		{"../x.txt", filepath.Join(project, "lnk"), []string{filepath.Join(project, "x.txt"), project + "/lnk/../x.txt"}},
		{"nodir/../x.txt", project, []string{filepath.Join(project, "x.txt")}},
		{"sub/x.txt", project, []string{filepath.Join(project, "sub", "x.txt")}},
	}
	for _, row := range rows {
		got, ok := ApplyPatchClientTargets("Bash", patch(row.name), "", row.cwd, root)
		if !ok || !slices.Equal(got, row.want) {
			t.Errorf("targets of %q from %s = %q, %t; want %q", row.name, row.cwd, got, ok, row.want)
		}
	}
}
