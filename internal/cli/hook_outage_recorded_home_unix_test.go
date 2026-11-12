// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-6 GAP-0307: an install with a custom DEFENSECLAW_HOME R keeps the
// account's config in R, not in ~/.defenseclaw. After `config set data_dir
// X`, X/hooks found no config (hookRuntimeConfigPath fell back to
// ~/.defenseclaw only) and R/hooks, whose config names X, were neither the
// account's folder nor config-less: every outage closed. The gateway now
// records the config it runs under beside the hooks it renders
// (.config-record), and that record, when this account owns it and nothing
// else can write it, names one of the account's own folders. The fresh and
// the stale hooks then follow R's config: default opens, strict, a saved
// closed and an install lock in R close; a record others can write, a link,
// a relative or missing target, or no record keep the old closed answer.
func TestHookOutageFailModeNowFollowsTheRecordedInstallHome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   string
		prepare  func(t *testing.T, r, x string)
		noRecord bool
		want     string
	}{
		{name: "default tier", config: outageNowDefaultConfig, want: "open"},
		{name: "strict tier", config: outageNowStrictConfig, want: "closed"},
		{name: "saved closed", config: outageNowDefaultConfig + "  hook_fail_mode: closed\n", want: "closed"},
		{name: "install holds the recorded home", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, _ string) { mkdirAll(t, filepath.Join(r, ".install.lock")) }},
		{name: "no record", config: outageNowDefaultConfig, noRecord: true, want: "closed"},
		// GAP-0309: the record is a pointer the account can rewrite, so the
		// account database's strict config is a floor.
		{name: "account database config is strict", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, _, _ string) {
				writeOutageNowConfig(t, filepath.Join(os.Getenv("HOME"), ".defenseclaw"), outageNowStrictConfig)
			}},
		{name: "account database config is default", config: outageNowDefaultConfig, want: "open",
			prepare: func(t *testing.T, _, _ string) {
				writeOutageNowConfig(t, filepath.Join(os.Getenv("HOME"), ".defenseclaw"), outageNowDefaultConfig)
			}},
		{name: "record writable by others", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, x string) {
				for _, dir := range []string{r, x} {
					chmod(t, filepath.Join(dir, "hooks", ".config-record"), 0o666)
				}
			}},
		{name: "record is a link", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, x string) {
				for _, dir := range []string{r, x} {
					rec := filepath.Join(dir, "hooks", ".config-record")
					raw, err := os.ReadFile(rec)
					if err != nil {
						t.Fatal(err)
					}
					real := filepath.Join(dir, "rec-real")
					if err := os.WriteFile(real, raw, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(rec); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(real, rec); err != nil {
						t.Fatal(err)
					}
				}
			}},
		{name: "hooks folder writable by others", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, x string) {
				chmod(t, filepath.Join(r, "hooks"), 0o777)
				chmod(t, filepath.Join(x, "hooks"), 0o777)
			}},
		{name: "recorded config folder writable by others", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, _ string) { chmod(t, r, 0o777) }},
		{name: "relative record", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, x string) {
				for _, dir := range []string{r, x} {
					writeRecord(t, dir, "home/config.yaml")
				}
			}},
		{name: "record names a missing file", config: outageNowDefaultConfig, want: "closed",
			prepare: func(t *testing.T, r, x string) {
				for _, dir := range []string{r, x} {
					writeRecord(t, dir, filepath.Join(r, "missing.yaml"))
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			r := filepath.Join(t.TempDir(), "dchome")
			x := filepath.Join(t.TempDir(), "dcdata")
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string { return account }
			outageInstalledDataRoot = func() (string, bool) { return "", false }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			// The agent's environment points at neither folder.
			t.Setenv("HOME", account)
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			for _, dir := range []string{filepath.Join(r, "hooks"), filepath.Join(x, "hooks")} {
				mkdirAll(t, dir)
			}
			writeOutageNowConfig(t, r, "data_dir: "+x+"\n"+tc.config)
			if !tc.noRecord {
				writeRecord(t, r, filepath.Join(r, "config.yaml"))
				writeRecord(t, x, filepath.Join(r, "config.yaml"))
			}
			if tc.prepare != nil {
				tc.prepare(t, r, x)
			}
			for _, hooks := range []string{filepath.Join(x, "hooks"), filepath.Join(r, "hooks")} {
				for _, connector := range []string{"claudecode", "codex"} {
					if got := hookOutageFailModeNow(connector, hooks); got != tc.want {
						t.Fatalf("hookOutageFailModeNow(%s, %s) = %q, want %q", connector, hooks, got, tc.want)
					}
				}
			}
		})
	}
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeRecord(t *testing.T, dataDir, target string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dataDir, "hooks", ".config-record"), []byte(target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Review 3 P2 (GAP-0309 on the moved-data_dir route), record shape R1: the
// account database's config is strict and names X, and X/hooks/.config-record
// is rewritten to Z/config.yaml, a default config naming Z. X/hooks then
// load Z's config, a moved folder's, and the floor must still close.
func TestHookOutageFailModeNowRewrittenRecordToAMovedFolderKeepsTheAccountFloor(t *testing.T) {
	for _, tc := range []struct {
		name, account, want string
	}{
		{name: "account strict", account: outageNowStrictConfig, want: "closed"},
		{name: "account saved closed", account: outageNowDefaultConfig + "  hook_fail_mode: closed\n", want: "closed"},
		{name: "account default", account: outageNowDefaultConfig, want: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			x := filepath.Join(t.TempDir(), "dcdata")
			z := filepath.Join(t.TempDir(), "other")
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string { return account }
			outageInstalledDataRoot = func() (string, bool) { return "", false }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			t.Setenv("HOME", account)
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			writeOutageNowConfig(t, filepath.Join(account, ".defenseclaw"), "data_dir: "+x+"\n"+tc.account)
			for _, dir := range []string{filepath.Join(x, "hooks"), filepath.Join(z, "hooks")} {
				mkdirAll(t, dir)
			}
			writeOutageNowConfig(t, z, "data_dir: "+z+"\n"+outageNowDefaultConfig)
			writeRecord(t, x, filepath.Join(z, "config.yaml"))
			if got := hookOutageFailModeNow("claudecode", filepath.Join(x, "hooks")); got != tc.want {
				t.Fatalf("hookOutageFailModeNow = %q, want %q", got, tc.want)
			}
		})
	}
}
