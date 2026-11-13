// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import "testing"

// LC-J9e: FolderName keeps a folder name RepoName would reduce to ASCII; an
// unusable one, and an unset one (OpenShell), give RepoName as before.
func TestStageFolderName(t *testing.T) {
	for _, c := range []struct{ folder, real, want string }{
		{"proj-ñ-日本", "/home/u/proj-ñ-日本", "proj-ñ-日本"},
		{"", "/home/u/proj-ñ-日本", RepoName("/home/u/proj-ñ-日本")},
		{"a/b", "/home/u/app", "app"},
		{"..", "/home/u/app", "app"},
		{"x\x07", "/home/u/app", "app"},
	} {
		if got := (StageOptions{FolderName: c.folder}).folderName(c.real); got != c.want {
			t.Errorf("folderName(%q, %q) = %q, want %q", c.folder, c.real, got, c.want)
		}
	}
	if RepoName("/home/u/proj-ñ-日本") != "proj" {
		t.Errorf("RepoName changed: %q", RepoName("/home/u/proj-ñ-日本"))
	}
}
