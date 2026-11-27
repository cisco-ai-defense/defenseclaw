// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func gap1553Spelling(t *testing.T, path string, conv func(*uint16, *uint16, uint32) (uint32, error)) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := conv(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("convert %s: %v", path, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// rel-1-0-10:GAP-1553: on the Windows no-answer path (bothLateScansOrdinary:
// the shared reader only), a Bash call that reaches the account's
// .ssh\authorized_keys by an 8.3 short name or a trailing dot is not
// ordinary (the call stays closed), as the long spelling is; a short name of
// an ordinary folder stays ordinary.
func TestGAP1553NoAnswerShortNamesStayClosed(t *testing.T) {
	home := gap1553Spelling(t, t.TempDir(), windows.GetLongPathName)
	ssh := filepath.Join(home, ".ssh")
	project := filepath.Join(home, "project")
	for _, dir := range []string{ssh, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(ssh, "authorized_keys")
	for _, file := range []string{key, filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sshShort := filepath.Base(gap1553Spelling(t, ssh, windows.GetShortPathName))
	keyShort := filepath.Base(gap1553Spelling(t, key, windows.GetShortPathName))
	projShort := filepath.Base(gap1553Spelling(t, project, windows.GetShortPathName))
	if sshShort == ".ssh" || keyShort == "authorized_keys" {
		t.Fatalf("the volume of %s has no 8.3 names (%s, %s): run on a volume that makes them", home, sshShort, keyShort)
	}
	payload := func(cwd, command string) []byte {
		raw, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
			"tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, row := range []struct {
		name, cwd, command string
		ordinary           bool
	}{
		{"short .ssh, append", home, "echo k >> " + sshShort + "/authorized_keys", false},
		{"short .ssh, read", home, "cat " + sshShort + "/authorized_keys", false},
		{"short authorized_keys from .ssh", ssh, "cat " + keyShort, false},
		{"trailing dot .ssh.", home, "cat .ssh./authorized_keys", false},
		{"long spelling", home, "cat .ssh/authorized_keys", false},
		{"short project folder", home, "cat " + projShort + "/notes.txt", true},
		{"project file", project, "cat notes.txt", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := lateScansOrdinary(home, "claudecode", "PreToolUse", payload(row.cwd, row.command), false); got != row.ordinary {
				t.Errorf("lateScansOrdinary(%q in %s) = %v, want %v", row.command, row.cwd, got, row.ordinary)
			}
		})
	}
}
