// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

func addFilePatch(target string) string {
	return "*** Begin Patch\n*** Add File: " + target + "\n+ordinary\n*** End Patch\n"
}

// TestApplyPatchAddFileStepUpFromMissingFolderIsOrdinary: a typed apply_patch
// Add File whose name steps up (..) after a folder that does not exist reads as
// the cleaned path inside the project, as it did before and as the heredoc
// spelling does. An ordinary target is allowed with no alert in the default
// pack; the same spellings that clean to a protected key file stay blocked.
func TestApplyPatchAddFileStepUpFromMissingFolderIsOrdinary(t *testing.T) {
	f := newAbsolutePatchFixture(t)
	for _, managed := range []bool{false, true} {
		checkMissingFolderStepUp(t, f, managed)
	}
}

func checkMissingFolderStepUp(t *testing.T, f absolutePatchFixture, managed bool) {
	t.Helper()
	for _, name := range []string{"sub/../notes.txt", "./sub/../notes.txt", "sub/../../proj/notes.txt", "src/../notes.txt"} {
		got, out := postApplyPatch(t, f, "codex", "default", managed, addFilePatch(name))
		if got != "allow" {
			t.Errorf("managed=%t Add File %q = %s, want allow: %.300s", managed, name, got, out)
		}
	}
	for _, name := range []string{"sub/../../.ssh/authorized_keys", "{H}/.ssh/authorized_keys"} {
		got, out := postApplyPatch(t, f, "codex", "default", managed, addFilePatch(f.path(name)))
		if got != "block" {
			t.Errorf("managed=%t Add File %q = %s, want block: %.300s", managed, name, got, out)
		}
	}
}
