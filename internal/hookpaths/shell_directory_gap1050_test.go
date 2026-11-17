// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-1050: after a directory change the walk cannot follow (a
// dynamic eval, source or cd), a run-time redirect target is unknown unless
// its last element is fixed text naming no authorized-keys or SSH control
// file.
func TestGAP1050FixedLastElementAfterUnknownDirectory(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, row := range []struct {
		command string
		unknown bool
	}{
		{"eval \"$X\"\nprintf k > \"$LOCK_DIR/pid\"", false},
		{"eval \"$X\"\nprintf k > \"$LOCK_DIR\"/pid", false},
		{"eval \"$X\"\nprintf k > $LOCK_DIR/owner.log", false},
		{"eval \"$X\"\nprintf k > \"$LOCK_DIR\"'/proc-start'", false},
		{"source \"$S\"\nprintf k > \"${D}/state_1\"", false},
		{"cd \"$D\"\nprintf k > \"$F/started\"", false},
		{"eval \"$X\"\nprintf k > \"$D/authorized_keys\"", true},
		{"eval \"$X\"\nprintf k > \"$D/authorized_keys2\"", true},
		{"eval \"$X\"\nprintf k > \"$D/AUTHORIZED_KEYS\"", true},
		{"eval \"$X\"\nprintf k > \"$D/authorized_keys. \"", true},
		{"eval \"$X\"\nprintf k > \"$D/administrators_authorized_keys\"", true},
		{"eval \"$X\"\nprintf k > \"$D/environment\"", true},
		{"eval \"$X\"\nprintf k > \"$D/rc\"", true},
		{"eval \"$X\"\nprintf k > \"$D/config\"", true},
		{"eval \"$X\"\nprintf k > \"$D/.\"", true},
		{"eval \"$X\"\nprintf k > \"$D/..\"", true},
		{"eval \"$X\"\nprintf k > \"$D/\"", true},
		{"eval \"$X\"\nprintf k > \"$D\"/a*", true},
		{"eval \"$X\"\nprintf k > \"$D\"/{a,b}", true},
		{"eval \"$X\"\nprintf k > \"$D/$F\"", true},
		{"eval \"$X\"\nprintf k > \"$D/x$(echo y)\"", true},
		{"eval \"$X\"\nprintf k > \"$D/AUTHOR~1\"", true},
		{"eval \"$X\"\nprintf k > \"$D/authorized_keys:s\"", true},
		{"eval \"$X\"\nprintf k > $D/authorized_\\keys", true},
		{"eval \"$X\"\nprintf k > \"$F\"", true},
		{"cd \"$D\"\nprintf k > \"$F\"", true},
		// A static relative authorized-keys name after the change, in the
		// case a case-insensitive file system opens and the Windows
		// spelling with a trailing dot.
		{"eval \"$X\"\nprintf k > authorized_keys", true},
		{"eval \"$X\"\nprintf k > Authorized_Keys", true},
		{"eval \"$X\"\nprintf k > authorized_keys.", true},
		{"eval \"$X\"\nprintf k > administrators_authorized_keys", true},
		{"eval \"$X\"\nprintf k > notes.txt", false},
	} {
		if _, unknown := ShellDirectoryWriteOperands(row.command, cwd, home, nil, false, false); unknown != row.unknown {
			t.Errorf("%q: unknown=%v, want %v", row.command, unknown, row.unknown)
		}
	}
}
