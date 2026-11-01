// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// GAP-1099 (requested by instr-protect): the saved installer and its
// previous copy are active DefenseClaw state, so the state scan that judges
// a move or rename (ActionStateTargetMention) names them, as it names hooks
// and policies. A project look-alike is not state.
func TestActionStateTargetMentionNamesTheSavedInstaller(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, command := range []string{
		"mv ~/.defenseclaw/installer/install.sh /tmp/x",
		"mv /tmp/x ~/.defenseclaw/previous/installer/install.sh",
	} {
		if !ActionStateTargetMention(command, cwd, home) {
			t.Errorf("ActionStateTargetMention(%q) = false, want active state", command)
		}
	}
	if ActionStateTargetMention("mv .defenseclaw/installer/install.sh /tmp/x", cwd, home) {
		t.Error("a project look-alike is not active state")
	}
}
