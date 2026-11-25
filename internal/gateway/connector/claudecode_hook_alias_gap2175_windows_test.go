// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// GAP-2175: enrolment, machine-policy verify, status and the guardian decide
// "this handler runs DefenseClaw's hook binary" with one rule
// (winpath.SameNamedFile): the binary by its own name or an 8.3 alias of it.
// pathidentity.Same alone also accepted a path through a junction or a hard
// link in a writable folder, whose owner can point it at another file after
// enrolment.
func TestGAP2175ClaudeEnrolmentAcceptsTheShortAliasOnly(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "DefenseClaw Program Files", "hooks", "e1132b0123456789")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(dir, "defenseclaw-hook.exe")
	other := filepath.Join(dir, "defenseclaw-other.exe")
	for _, path := range []string{hook, other} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	junction := filepath.Join(root, "linked")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, dir).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	viaJunction := filepath.Join(junction, filepath.Base(hook))
	hardLink := filepath.Join(root, "defenseclaw-hook.exe")
	if err := os.Link(hook, hardLink); err != nil {
		t.Fatal(err)
	}
	if !pathidentity.Same(viaJunction, hook) || !pathidentity.Same(hardLink, hook) {
		t.Fatal("fixture: the junction path and the hard link must open the hook binary's file")
	}

	opts := SetupOpts{HookExecutable: hook, ManagedEnterprise: true}
	handler := func(command string) map[string]interface{} {
		return map[string]interface{}{
			"type":    "command",
			"command": command,
			"args":    []interface{}{"hook", "--connector", "claudecode", "--enterprise-managed"},
		}
	}
	for _, tc := range []struct {
		name, command string
		enrolled      bool
	}{
		{"long path", hook, true},
		{"long path, other case", strings.ToUpper(hook), true},
		{"8.3 alias of the hook", gap2175Short(t, hook), true},
		{"8.3 alias of another executable", gap2175Short(t, other), false},
		{"path through a junction", viaJunction, false},
		{"hard link in another folder", hardLink, false},
	} {
		if got := claudeCodeHandlerTargetsCurrentRuntime(handler(tc.command), opts); got != tc.enrolled {
			t.Errorf("%s: claudeCodeHandlerTargetsCurrentRuntime(%s) = %v, want %v", tc.name, tc.command, got, tc.enrolled)
		}
	}
}

func gap2175Short(t *testing.T, path string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetShortPathName(%s): %v", path, err)
	}
	short := windows.UTF16ToString(buffer[:n])
	if !strings.Contains(short, "~") || strings.EqualFold(short, path) {
		t.Skipf("the volume of %s makes no 8.3 short names", path)
	}
	return short
}
