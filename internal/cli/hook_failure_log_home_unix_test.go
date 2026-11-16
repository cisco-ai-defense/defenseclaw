// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// accountDatabaseHomeForTest is the home the account database gives this
// process's uid: getent on Linux, Open Directory (os/user, which does not read
// HOME there) on macOS.
func accountDatabaseHomeForTest(t *testing.T) string {
	t.Helper()
	uid := strconv.Itoa(os.Geteuid())
	if runtime.GOOS == "darwin" {
		account, err := user.LookupId(uid)
		if err != nil {
			t.Fatal(err)
		}
		return account.HomeDir
	}
	out, err := exec.Command("getent", "passwd", uid).Output()
	if err != nil {
		t.Skipf("getent passwd %s: %v", uid, err)
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) != 7 || fields[5] == "" {
		t.Fatalf("getent passwd %s: %q", uid, out)
	}
	return fields[5]
}

// An agent runtime can point HOME at another folder or unset it. A managed
// hook's failure rows still go to the home the account database gives the
// process's uid, on an active standalone runtime and on one that failed its
// checks.
func TestManagedUnixHookFailureLogIgnoresRedirectedHome(t *testing.T) {
	account := accountDatabaseHomeForTest(t)
	want := filepath.Join(account, config.DefaultDataDirName)
	redirected := t.TempDir()
	noSocket := func(string) (*managed.RuntimeDescriptor, error) {
		descriptor := testDescriptor()
		descriptor.HookSocket = ""
		return descriptor, nil
	}
	runtimes := map[string]func(string) (*managed.RuntimeDescriptor, error){
		"active": func(string) (*managed.RuntimeDescriptor, error) { return testDescriptor(), nil },
		"failed": noSocket,
	}
	for _, home := range []string{"redirected", "unset"} {
		for name, load := range runtimes {
			t.Run(home+" "+name, func(t *testing.T) {
				t.Setenv("HOME", redirected)
				if home == "unset" {
					if err := os.Unsetenv("HOME"); err != nil {
						t.Fatal(err)
					}
				}
				if got, err := managedHookUserProfileDir(); err != nil || got != filepath.Clean(account) {
					t.Fatalf("user profile = %q, %v; want the account database's %q (HOME %s)", got, err, account, home)
				}
				withStandaloneHookRuntime(t, "linux", load, noMarkers, "/nonexistent-secure-client")
				_ = prepareEnterpriseManagedHookRuntime("codex")
				opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
				if opts.FailureLogHome == nil {
					t.Fatal("managed hook options carry no failure log home")
				}
				if got := opts.FailureLogHome(); got != want || strings.HasPrefix(got, redirected) {
					t.Fatalf("failure log home = %q, want %q (HOME %s to %q)", got, want, home, redirected)
				}
			})
		}
	}
}
