// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermespath

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0499: a service acting for a Windows account resolves the Hermes home
// the account's persistent environment selects, as a process the account
// starts would, and fails instead of falling back to the profile default
// when that home cannot be resolved.
func TestWindowsAccountHermesHomeFollowsThePersistentEnvironment(t *testing.T) {
	const profile = `C:\Users\alice`
	machineWide := map[string]string{"SystemDrive": "C:"}
	for _, tc := range []struct {
		name string
		env  windowsAccountEnvironment
		want string
		err  string
	}{
		{name: "default", want: profile + `\AppData\Local\hermes`},
		{
			name: "account variable",
			env:  windowsAccountEnvironment{user: []accountEnvValue{{name: "HERMES_HOME", value: `%USERPROFILE%\hermes-work`, expand: true}}},
			want: profile + `\hermes-work`,
		},
		{
			name: "machine variable",
			env:  windowsAccountEnvironment{machineWide: machineWide, machine: []accountEnvValue{{name: "Hermes_Home", value: `%SystemDrive%\hermes`, expand: true}}},
			want: `C:\hermes`,
		},
		{
			name: "account over machine",
			env: windowsAccountEnvironment{
				machine: []accountEnvValue{{name: "HERMES_HOME", value: `C:\machine\hermes`}},
				user:    []accountEnvValue{{name: "HERMES_HOME", value: `D:\alice\hermes`}},
			},
			want: `D:\alice\hermes`,
		},
		{
			name: "redirected sign-in Local AppData",
			env:  windowsAccountEnvironment{volatile: []accountEnvValue{{name: "LOCALAPPDATA", value: `D:\Redirected\alice\Local`}}},
			want: `D:\Redirected\alice\Local\hermes`,
		},
		{
			name: "unresolved reference",
			env:  windowsAccountEnvironment{user: []accountEnvValue{{name: "HERMES_HOME", value: `%NO_SUCH_VARIABLE%\hermes`, expand: true}}},
			err:  "does not expand",
		},
		{
			name: "literal reference",
			env:  windowsAccountEnvironment{user: []accountEnvValue{{name: "HERMES_HOME", value: `%USERPROFILE%\hermes`}}},
			err:  "does not expand",
		},
		{
			name: "relative",
			env:  windowsAccountEnvironment{user: []accountEnvValue{{name: "HERMES_HOME", value: `hermes`}}},
			err:  "not an absolute normalized path",
		},
		{
			name: "unresolved Local AppData",
			env:  windowsAccountEnvironment{user: []accountEnvValue{{name: "LOCALAPPDATA", value: `%NOPE%\Local`, expand: true}}},
			err:  "does not expand",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsAccountHermesHome(profile, tc.env)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("home = %q, %v; want an error containing %q, never the profile default", got, err, tc.err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("home = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := windowsAccountHermesHome(`Users\alice`, windowsAccountEnvironment{}); err == nil {
		t.Fatal("a relative profile directory must fail")
	}
}

func TestConfigPathForAccountUsesTheAccountHomeOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reads the account's registry hive; covered by the Windows tests")
	}
	t.Setenv("HERMES_HOME", t.TempDir())
	home := filepath.Join(t.TempDir(), "alice")
	got, err := ConfigPathForAccount(home)
	if err != nil || got != filepath.Join(home, ".hermes", "config.yaml") {
		t.Fatalf("ConfigPathForAccount = %q, %v; want the account's ~/.hermes, not the service's HERMES_HOME", got, err)
	}
	if _, err := ConfigPathForAccount("  "); err == nil {
		t.Fatal("an empty account home must fail")
	}
}
