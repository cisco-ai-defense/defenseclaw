// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func gap2244GuardShort(t *testing.T, path string) string {
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

func gap2244GuardArgs(launcher string) []string {
	return []string{WrappedSubcommand, launcher, "hook", "--connector", "claudecode", "--enterprise-managed", "--event", "PreToolUse"}
}

// GAP-2244: the guarded wrapper of an HKLM matrix can name the launcher by
// its 8.3 alias. The guard must read that argv and start the hook, as it
// does for the long name; an alias of another file stays refused.
func TestGAP2244GuardReadsTheLauncherByItsShortName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "DefenseClaw Program Files", "bin", "hooks", "89aa96f0123456789")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, hookBinaryName)
	other := filepath.Join(dir, "defenseclaw-hook-other.exe")
	for _, path := range []string{launcher, other} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, spelling := range []string{
		launcher,
		filepath.Join(gap2244GuardShort(t, dir), hookBinaryName),
		gap2244GuardShort(t, launcher),
	} {
		got, hookArgs, event, wrapped, open, ok := ParseInvocationMode(gap2244GuardArgs(spelling))
		if !ok || got != spelling || len(hookArgs) != 4 || event != "PreToolUse" || !wrapped || open {
			t.Errorf("launcher %s: got %q %q %q wrapped=%t open=%t ok=%t", spelling, got, hookArgs, event, wrapped, open, ok)
		}
	}
	for name, spelling := range map[string]string{
		"alias of another file": gap2244GuardShort(t, other),
		"missing alias":         filepath.Join(dir, "DEFENS~9.EXE"),
		"relative alias":        "DEFENS~1.EXE",
		"directory alias":       gap2244GuardShort(t, dir),
	} {
		if _, _, _, _, _, ok := ParseInvocationMode(gap2244GuardArgs(spelling)); ok {
			t.Errorf("%s %s was read as the launcher", name, spelling)
		}
	}
}
