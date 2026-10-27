// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// outageInstallLayout is one account whose hook runtime keeps its data in a
// data_dir set apart from the installer's folder.
type outageInstallLayout struct {
	base, data, account, installer, agentHome, other, state string
}

// oss-outage-open review (round g, loop round 1): install.sh and install.ps1
// hold .install.lock in their DEFENSECLAW_HOME, by default ~/.defenseclaw,
// while they replace a stopped gateway. With a data_dir set apart from it,
// the hooks of that data_dir looked for the lock in their own folder and in
// the HOME or DEFENSECLAW_HOME the agent passed them. A temporary HOME, or
// another DEFENSECLAW_HOME, hid the installer's lock, and the default tier
// let tool calls through unchecked during the upgrade. hook-outage-mode, the
// one step every per-user hook form takes before it lets an outage through,
// now closes while any folder an installer of this account may hold is
// locked, and the agent's environment can only add folders to that list.
func TestHookOutageFailModeNowClosesWhileAnyInstallerFolderIsLocked(t *testing.T) {
	lockDir := func(t *testing.T, root string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, ".install.lock"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name      string
		unixOnly  bool
		prepare   func(t *testing.T, l outageInstallLayout)
		env       func(l outageInstallLayout) map[string]string
		noAccount bool
		state     func(l outageInstallLayout) (string, bool)
		want      string
	}{
		{name: "no install holds any folder", want: "open"},
		{name: "the installer's default folder is locked and the agent's HOME is temporary",
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, l.installer) }, want: "closed"},
		{name: "the installer's default folder is locked and the agent names another DEFENSECLAW_HOME",
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, l.installer) },
			env:     func(l outageInstallLayout) map[string]string { return map[string]string{"DEFENSECLAW_HOME": l.other} },
			want:    "closed"},
		{name: "the runtime's own data folder is locked",
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, l.data) }, want: "closed"},
		{name: "the lock is a file",
			prepare: func(t *testing.T, l outageInstallLayout) {
				if err := os.WriteFile(filepath.Join(l.installer, ".install.lock"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}, want: "closed"},
		{name: "the lock is a dangling link", unixOnly: true,
			prepare: func(t *testing.T, l outageInstallLayout) {
				if err := os.Symlink(filepath.Join(l.base, "missing"), filepath.Join(l.installer, ".install.lock")); err != nil {
					t.Fatal(err)
				}
			}, want: "closed"},
		{name: "the installer's folder is a file",
			prepare: func(t *testing.T, l outageInstallLayout) {
				if err := os.RemoveAll(l.installer); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(l.installer, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}, want: "closed"},
		{name: "the installer's folder cannot be searched", unixOnly: true,
			prepare: func(t *testing.T, l outageInstallLayout) {
				if os.Geteuid() == 0 {
					t.Skip("root searches any folder")
				}
				if err := os.Chmod(l.installer, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(l.installer, 0o700) })
			}, want: "closed"},
		{name: "the account has no installer folder",
			prepare: func(t *testing.T, l outageInstallLayout) {
				if err := os.RemoveAll(l.installer); err != nil {
					t.Fatal(err)
				}
			}, want: "open"},
		{name: "the installer's folder is a link to an unlocked folder", unixOnly: true,
			prepare: func(t *testing.T, l outageInstallLayout) {
				if err := os.RemoveAll(l.installer); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(l.other, l.installer); err != nil {
					t.Fatal(err)
				}
			}, want: "open"},
		{name: "the DEFENSECLAW_HOME the hook inherits is locked",
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, l.other) },
			env:     func(l outageInstallLayout) map[string]string { return map[string]string{"DEFENSECLAW_HOME": l.other} },
			want:    "closed"},
		{name: "the HOME the hook inherits holds a locked .defenseclaw",
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, filepath.Join(l.agentHome, ".defenseclaw")) },
			want:    "closed"},
		{name: "a relative DEFENSECLAW_HOME names no installer folder",
			prepare: func(t *testing.T, l outageInstallLayout) {
				lockDir(t, filepath.Join(l.base, "relative-home"))
				t.Chdir(l.base)
			},
			env: func(outageInstallLayout) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": "relative-home"}
			},
			want: "open"},
		{name: "the installed state's data root is locked",
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, l.state) },
			state:   func(l outageInstallLayout) (string, bool) { return l.state, true },
			want:    "closed"},
		{name: "the installed state cannot be read",
			state: func(outageInstallLayout) (string, bool) { return "", true },
			want:  "closed"},
		{name: "the installed state's data root is not locked",
			state: func(l outageInstallLayout) (string, bool) { return l.state, true },
			want:  "open"},
		{name: "the account database does not list the account", noAccount: true, want: "open"},
		{name: "the account database does not list the account and the inherited HOME is locked", noAccount: true,
			prepare: func(t *testing.T, l outageInstallLayout) { lockDir(t, filepath.Join(l.agentHome, ".defenseclaw")) },
			want:    "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unixOnly && runtime.GOOS == "windows" {
				t.Skip("POSIX file modes and links")
			}
			base := t.TempDir()
			l := outageInstallLayout{
				base:      base,
				data:      filepath.Join(base, "custom-data"),
				account:   filepath.Join(base, "account"),
				agentHome: filepath.Join(base, "agent-tmp-home"),
				other:     filepath.Join(base, "other-home"),
				state:     filepath.Join(base, "installed-data-root"),
			}
			l.installer = filepath.Join(l.account, ".defenseclaw")
			for _, dir := range []string{l.data, l.installer, l.agentHome, l.other, l.state} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// The runtime's config lives in its custom data_dir, as the CLI
			// saves it (config_path_for_data_dir).
			writeOutageNowConfig(t, l.data, "data_dir: "+l.data+"\n"+outageNowDefaultConfig)
			isolateOutageHostMarkers(t)
			stubOutageInstallFolders(t, func() string {
				if tc.noAccount {
					return ""
				}
				return l.account
			}, func() (string, bool) {
				if tc.state == nil {
					return "", false
				}
				return tc.state(l)
			})
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("HOME", l.agentHome)
			t.Setenv("USERPROFILE", l.agentHome)
			if tc.env != nil {
				for key, value := range tc.env(l) {
					t.Setenv(key, value)
				}
			}
			if tc.prepare != nil {
				tc.prepare(t, l)
			}
			if got := hookOutageFailModeNow("opencode", filepath.Join(l.data, "hooks")); got != tc.want {
				t.Fatalf("hookOutageFailModeNow = %q, want %q", got, tc.want)
			}
		})
	}
}

// isolateOutageHostMarkers makes the build or test host's own machine
// markers (a managed Setup, Secure Client) absent, so the cases read the
// same on a managed lane host as on a build box.
func isolateOutageHostMarkers(t *testing.T) {
	t.Helper()
	oldDescriptor, oldWindows := managedHostDescriptorPath, managedHostWindowsStandalone
	oldSecureClient, oldUncertain := secureClientHost, managedHostWindowsMarkerUncertain
	missing := filepath.Join(t.TempDir(), "no-runtime-descriptor")
	managedHostDescriptorPath = func() string { return missing }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	secureClientHost = func() bool { return false }
	managedHostWindowsMarkerUncertain = func() bool { return false }
	t.Cleanup(func() {
		managedHostDescriptorPath, managedHostWindowsStandalone = oldDescriptor, oldWindows
		secureClientHost, managedHostWindowsMarkerUncertain = oldSecureClient, oldUncertain
	})
}

func stubOutageInstallFolders(t *testing.T, account func() string, state func() (string, bool)) {
	t.Helper()
	oldAccount, oldState := outageAccountHome, outageInstalledDataRoot
	outageAccountHome, outageInstalledDataRoot = account, state
	t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldState })
}

// The installer's default folder comes from the account database, not from
// the HOME or USERPROFILE the hook inherits from its agent.
func TestOutageAccountHomeIgnoresTheInheritedHome(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("HOME", fake)
	t.Setenv("USERPROFILE", fake)
	home := outageAccountHome()
	if home == "" {
		t.Skip("the account database does not list this account")
	}
	if !filepath.IsAbs(home) || pathidentity.Same(home, fake) {
		t.Fatalf("outageAccountHome() = %q, the inherited home %q", home, fake)
	}
}
