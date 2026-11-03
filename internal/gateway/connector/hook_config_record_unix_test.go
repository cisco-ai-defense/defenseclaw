// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-6 GAP-0307: the per-user render records the config file the
// gateway runs under (DEFENSECLAW_CONFIG, else DEFENSECLAW_HOME/config.yaml,
// else ~/.defenseclaw/config.yaml) beside the hooks, as an owner-only file.
// A relative value or a config that does not exist leaves the record as it
// was.
func TestPerUserRenderRecordsTheConfigItRunsUnder(t *testing.T) {
	read := func(t *testing.T, hookDir string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(hookDir, perUserConfigRecordName))
		if err != nil {
			return ""
		}
		info, err := os.Stat(filepath.Join(hookDir, perUserConfigRecordName))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("record mode %v (%v), want 0600", info.Mode().Perm(), err)
		}
		return string(raw)
	}
	t.Run("custom DEFENSECLAW_HOME", func(t *testing.T) {
		home := t.TempDir()
		install := filepath.Join(t.TempDir(), "dchome")
		data := filepath.Join(t.TempDir(), "dcdata")
		if err := os.MkdirAll(install, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(install, "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", home)
		t.Setenv("DEFENSECLAW_CONFIG", "")
		t.Setenv("DEFENSECLAW_HOME", install)
		if err := writePerUserGatewayHelperRecord(filepath.Join(data, "hooks")); err != nil {
			t.Fatal(err)
		}
		if got, want := read(t, filepath.Join(data, "hooks")), filepath.Join(install, "config.yaml")+"\n"; got != want {
			t.Fatalf("record = %q, want %q", got, want)
		}
		// A cold start whose DEFENSECLAW_HOME is the data folder (no
		// config.yaml there) keeps the record.
		t.Setenv("DEFENSECLAW_HOME", data)
		if err := writePerUserGatewayHelperRecord(filepath.Join(data, "hooks")); err != nil {
			t.Fatal(err)
		}
		if got, want := read(t, filepath.Join(data, "hooks")), filepath.Join(install, "config.yaml")+"\n"; got != want {
			t.Fatalf("record after a cold start = %q, want %q", got, want)
		}
		// A relative value names nothing.
		t.Setenv("DEFENSECLAW_HOME", "rel")
		if err := writePerUserGatewayHelperRecord(filepath.Join(data, "hooks")); err != nil {
			t.Fatal(err)
		}
		if got, want := read(t, filepath.Join(data, "hooks")), filepath.Join(install, "config.yaml")+"\n"; got != want {
			t.Fatalf("record after a relative home = %q, want %q", got, want)
		}
	})
	t.Run("DEFENSECLAW_CONFIG", func(t *testing.T) {
		home := t.TempDir()
		cfg := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(cfg, []byte("x: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", home)
		t.Setenv("DEFENSECLAW_HOME", "")
		t.Setenv("DEFENSECLAW_CONFIG", cfg)
		hooks := filepath.Join(home, ".defenseclaw", "hooks")
		if err := writePerUserGatewayHelperRecord(hooks); err != nil {
			t.Fatal(err)
		}
		if got := read(t, hooks); got != cfg+"\n" {
			t.Fatalf("record = %q, want %q", got, cfg)
		}
	})
	t.Run("no config yet", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("DEFENSECLAW_HOME", "")
		t.Setenv("DEFENSECLAW_CONFIG", "")
		hooks := filepath.Join(home, ".defenseclaw", "hooks")
		if err := writePerUserGatewayHelperRecord(hooks); err != nil {
			t.Fatal(err)
		}
		if got := read(t, hooks); got != "" {
			t.Fatalf("record = %q, want none", got)
		}
	})
}
