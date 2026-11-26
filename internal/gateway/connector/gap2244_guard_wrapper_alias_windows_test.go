// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// gap2244Image lays out a stand-in for an installed hook image folder with
// its launcher, its guard and one other executable. Long names get 8.3
// short names where the volume makes them.
func gap2244Image(t *testing.T) (dir, launcher, guard, other string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "DefenseClaw Program Files", "bin", "hooks", "89aa96f0123456789")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher = filepath.Join(dir, "defenseclaw-hook.exe")
	guard = filepath.Join(dir, windowsHookGuardBinaryName)
	other = filepath.Join(dir, "defenseclaw-hook-other.exe")
	for _, path := range []string{launcher, guard, other} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, launcher, guard, other
}

// gap2244Short is the 8.3 spelling of an existing path; it skips when the
// volume makes no short names.
func gap2244Short(t *testing.T, path string) string {
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

// gap2244Handler is the guarded cmd.exe handler Setup renders for event,
// with the guard and the launcher spelled as given.
func gap2244Handler(event, guard, launcher string) map[string]interface{} {
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	args := claudeManagedGuardWrapperArgs(guard, launcher, event, hookArgs)
	raw := make([]interface{}, len(args))
	for i, arg := range args {
		raw[i] = arg
	}
	return map[string]interface{}{"type": "command", "command": claudeCodeWindowsCommandProcessor(), "args": raw}
}

// GAP-2244: the guarded wrapper of an HKLM matrix that spells the launcher,
// the guard or both by 8.3 short names is the managed form, as the exec form
// by the same alias is.
func TestGAP2244ManagedGuardWrapperReadsTheInstalledFilesByTheirShortNames(t *testing.T) {
	dir, launcher, guard, _ := gap2244Image(t)
	shortDir := gap2244Short(t, dir)
	shortLauncher, shortGuard := gap2244Short(t, launcher), gap2244Short(t, guard)
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	for _, spelling := range []struct{ name, guard, launcher string }{
		{"long", guard, launcher},
		{"wa1 folder by alias", filepath.Join(shortDir, windowsHookGuardBinaryName), filepath.Join(shortDir, "defenseclaw-hook.exe")},
		{"wa2 every name by alias", shortGuard, shortLauncher},
		{"ws launcher by alias", guard, shortLauncher},
		{"guard by alias", shortGuard, launcher},
	} {
		for _, group := range claudeCodeAllHookGroups {
			got, gotArgs, ok := ClaudeCodeManagedGuardLauncher(gap2244Handler(group.eventType, spelling.guard, spelling.launcher))
			if !ok || got != spelling.launcher || !slices.Equal(gotArgs, hookArgs) {
				t.Fatalf("%s, %s: guard %s launcher %s not read as the managed form: %q %q %v",
					spelling.name, group.eventType, spelling.guard, spelling.launcher, got, gotArgs, ok)
			}
		}
	}
}

// GAP-2244 negative guard: a guard that is not the launcher folder's own
// guard file by its own names is not the managed form.
func TestGAP2244ManagedGuardWrapperRefusesAnyOtherGuard(t *testing.T) {
	dir, launcher, guard, other := gap2244Image(t)
	shortLauncher := gap2244Short(t, launcher)
	elsewhere := filepath.Join(filepath.Dir(dir), "elsewhere", windowsHookGuardBinaryName)
	if err := os.MkdirAll(filepath.Dir(elsewhere), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(elsewhere, []byte(windowsHookGuardBinaryName), 0o755); err != nil {
		t.Fatal(err)
	}
	hardLink := filepath.Join(filepath.Dir(dir), "linked", windowsHookGuardBinaryName)
	if err := os.MkdirAll(filepath.Dir(hardLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(guard, hardLink); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(filepath.Dir(dir), "junction")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, dir).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	for _, launcherSpelling := range []string{launcher, shortLauncher} {
		for name, badGuard := range map[string]string{
			"copy in another folder":          elsewhere,
			"copy in another folder by alias": gap2244Short(t, elsewhere),
			"other file in the folder":        other,
			"other file by alias":             gap2244Short(t, other),
			"hard link in another folder":     hardLink,
			"guard through a junction":        filepath.Join(junction, windowsHookGuardBinaryName),
			"missing guard":                   filepath.Join(dir, "DEFENS~9.EXE"),
		} {
			if got, _, ok := ClaudeCodeManagedGuardLauncher(gap2244Handler("PreToolUse", badGuard, launcherSpelling)); ok {
				t.Errorf("%s (%s) with launcher %s was read as the managed form (launcher %q)", name, badGuard, launcherSpelling, got)
			}
		}
	}
}
