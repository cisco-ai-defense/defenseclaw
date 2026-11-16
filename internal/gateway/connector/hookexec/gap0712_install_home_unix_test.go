// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// A supported custom install home can differ from the folder of the config
// file (DEFENSECLAW_CONFIG outside it, or a link to it). The hook finds the
// PID home from the record the gateway wrote at render time, not from the
// config path and not from its own environment.
func TestGAP0712PIDHomeComesFromItsOwnRecord(t *testing.T) {
	type layout struct {
		name string
		// record writes the install-home record; env sets DEFENSECLAW_HOME.
		record, env, symlinkConfig bool
		want                       bool
	}
	for _, tc := range []layout{
		{name: "external config file, record", record: true, want: true},
		{name: "external config link, record", record: true, symlinkConfig: true, want: true},
		{name: "hooks rendered before the record, environment names the home", env: true, want: true},
		{name: "neither record nor environment names the home", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			installHome := filepath.Join(account, "custom-install")
			configDir := filepath.Join(account, "config")
			store := filepath.Join(account, "moved-store")
			hooks := filepath.Join(store, "hooks")
			for _, dir := range []string{installHome, configDir, hooks} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(configDir, "config.yaml")
			actual := configPath
			if tc.symlinkConfig {
				actual = filepath.Join(installHome, "config.yaml")
			}
			if err := os.WriteFile(actual, []byte("config_version: 9\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.symlinkConfig {
				if err := os.Symlink(actual, configPath); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(hooks, ".config-record"), []byte(configPath+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.record {
				if err := os.WriteFile(filepath.Join(hooks, ".install-home-record"), []byte(installHome+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("DEFENSECLAW_HOME", "")
			if tc.env {
				t.Setenv("DEFENSECLAW_HOME", installHome)
			}
			oldHome, oldHolder, oldClass := perUserAccountHome, perUserPortHolder, perUserListenerClass
			t.Cleanup(func() {
				perUserAccountHome, perUserPortHolder, perUserListenerClass = oldHome, oldHolder, oldClass
			})
			perUserAccountHome = func() string { return account }
			perUserPortHolder = func(string, int) (daemon.PortHolder, error) {
				return daemon.PortHolder{PID: 1234, UID: 0}, nil
			}
			perUserListenerClass = func(_ string, _ int, home string, _ daemon.PortHolder, _ error, _ bool) daemon.PerUserListenerClass {
				if home == installHome {
					return daemon.PerUserListenerOwnGatewayRunAsRoot
				}
				return daemon.PerUserListenerForeign
			}
			opts := Options{Home: store, HookDir: hooks, APIAddr: "127.0.0.1:19100"}
			got := perUserRootGatewayReason(opts)
			if tc.want && !strings.Contains(got, "DEFENSECLAW_HOME='"+installHome+"'") {
				t.Fatalf("diagnosis = %q, want verified install home %q (candidates %q)", got, installHome, perUserRecordHomes(opts))
			}
			if !tc.want && got != "" {
				t.Fatalf("diagnosis = %q, want none when no layout names the PID home", got)
			}
		})
	}
}

// A record the account cannot trust (writable by others, or naming a folder
// others can write) is ignored, and a listener that does not verify as the
// gateway of this account never yields a root claim whatever the record names.
func TestGAP0712InstallHomeRecordIsNotTrustedBlindly(t *testing.T) {
	account := t.TempDir()
	installHome := filepath.Join(account, "custom-install")
	store := filepath.Join(account, "moved-store")
	hooks := filepath.Join(store, "hooks")
	for _, dir := range []string{installHome, hooks} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	record := filepath.Join(hooks, ".install-home-record")
	if err := os.WriteFile(record, []byte(installHome+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", "")
	oldHome, oldHolder, oldClass := perUserAccountHome, perUserPortHolder, perUserListenerClass
	t.Cleanup(func() {
		perUserAccountHome, perUserPortHolder, perUserListenerClass = oldHome, oldHolder, oldClass
	})
	perUserAccountHome = func() string { return account }
	perUserPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 1234, UID: 0}, nil
	}
	verified := true
	perUserListenerClass = func(_ string, _ int, home string, _ daemon.PortHolder, _ error, _ bool) daemon.PerUserListenerClass {
		if verified && home == installHome {
			return daemon.PerUserListenerOwnGatewayRunAsRoot
		}
		return daemon.PerUserListenerForeign
	}
	opts := Options{Home: store, HookDir: hooks, APIAddr: "127.0.0.1:19100"}
	if got := perUserRootGatewayReason(opts); !strings.Contains(got, installHome) {
		t.Fatalf("trusted record diagnosis = %q, want the install home", got)
	}
	verified = false
	if got := perUserRootGatewayReason(opts); got != "" {
		t.Fatalf("unverified listener diagnosis = %q, want no root claim", got)
	}
	verified = true
	if err := os.Chmod(record, 0o666); err != nil {
		t.Fatal(err)
	}
	if got := perUserRootGatewayReason(opts); got != "" {
		t.Fatalf("writable record diagnosis = %q, want none", got)
	}
	if err := os.Chmod(record, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(installHome, 0o777); err != nil {
		t.Fatal(err)
	}
	if got := perUserRootGatewayReason(opts); got != "" {
		t.Fatalf("shared install home diagnosis = %q, want none", got)
	}
}
