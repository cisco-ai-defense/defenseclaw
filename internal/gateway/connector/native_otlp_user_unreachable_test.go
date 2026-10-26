// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2095: a config folder that is a link whose target is gone reads as
// absent (os.ErrNotExist), so the take-back must ask whether it can be
// reached before it treats "no config" as "no exporter".
func TestUserNativeOTLPConfigUnreachableNamesADanglingLink(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	home := t.TempDir()
	share := filepath.Join(t.TempDir(), "share")
	if err := os.MkdirAll(share, 0o700); err != nil {
		t.Fatal(err)
	}
	check := func() string {
		t.Helper()
		var got string
		if err := WithUserHomeDir(home, func() error {
			got = UserNativeOTLPConfigUnreachable("codex")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := check(); got != "" {
		t.Fatalf("no .codex: %q, want reachable", got)
	}
	link := filepath.Join(home, ".codex")
	if err := os.Symlink(share, link); err != nil {
		t.Fatal(err)
	}
	if got := check(); got != "" {
		t.Fatalf("linked .codex without a config: %q, want reachable", got)
	}
	if err := os.WriteFile(filepath.Join(share, "config.toml"), []byte("model = 'o4'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := check(); got != "" {
		t.Fatalf("linked .codex with a config: %q, want reachable", got)
	}
	if err := os.RemoveAll(share); err != nil {
		t.Fatal(err)
	}
	if got := check(); got != link {
		t.Fatalf("dangling .codex link: %q, want %q", got, link)
	}
	if got := UserNativeOTLPConfigUnreachable("hermes"); got != "" {
		t.Fatalf("hermes: %q", got)
	}
}
