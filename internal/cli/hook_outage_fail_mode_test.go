// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A predecessor's open sidecar cannot reopen a new per-user hook binary.
func TestPerUserHookOutageFailModeIgnoresPredecessorEntry(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"open entry", `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`, "closed"},
		{"closed entry (strict tier)", `{"version":2,"fail_modes":{"codex":"closed"},"fail_mode_sources":{"codex":"config"}}`, "closed"},
		{"open entry without its source", `{"version":2,"fail_modes":{"codex":"open"}}`, "closed"},
		{"another connector open", `{"version":2,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"}}`, "closed"},
		{"unscoped legacy open", `{"version":2,"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`, "closed"},
		{"managed sidecar", `{"version":2,"managed_enterprise":true,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`, "closed"},
		{"version 1", `{"version":1,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`, "closed"},
		{"malformed", `{"version":2,"fail_modes":{"codex":"open"`, "closed"},
		{"fail modes not a map", `{"version":2,"fail_modes":"open","fail_mode_sources":{"codex":"config"}}`, "closed"},
		{"flat 0.8 record", "DEFENSECLAW_FAIL_MODE=open\n", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".hookcfg")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := perUserHookOutageFailMode(path, "codex"); got != tc.want {
				t.Fatalf("outage mode = %q, want %q", got, tc.want)
			}
		})
	}
	if got := perUserHookOutageFailMode(filepath.Join(t.TempDir(), "missing"), "codex"); got != "closed" {
		t.Fatalf("missing sidecar outage mode = %q, want closed", got)
	}
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		target := filepath.Join(dir, "real")
		if err := os.WriteFile(target, []byte(`{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, ".hookcfg")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if got := perUserHookOutageFailMode(link, "codex"); got != "closed" {
			t.Fatalf("linked sidecar outage mode = %q, want closed", got)
		}
	}
}
