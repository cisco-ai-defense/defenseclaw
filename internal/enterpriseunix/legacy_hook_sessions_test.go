// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The 1.0.2 gateway kept foreign-hook session records below the hook socket
// runtime folder. The 1.0.4 gateway uses its private data directory instead.
// An upgrade must retire the old records even if their root became writable
// by other users while the old release was installed.
func TestLinuxUpgradeInvalidatesLegacyHookSessionStore(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.2")}))
	root := h.env.P("/run/defenseclaw-hook/sessions")
	account := filepath.Join(root, "9a3343997276df92ed341e3f396555c4b3e30287")
	if err := os.MkdirAll(account, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"opencode-p-old.json", "opencode-s-old.json"} {
		if err := os.WriteFile(filepath.Join(account, name), []byte(`{"v":1}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	h.env.ProductVersion = "1.0.4"
	result := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.4")})
	requireOK(t, result)
	if got := h.mode("/run/defenseclaw-hook/sessions"); got != 0o711 {
		t.Fatalf("retired session root mode = %04o, want 0711", got)
	}
	if _, err := os.Stat(account); !os.IsNotExist(err) {
		t.Fatalf("retired account records remain: %v", err)
	}
	if !strings.Contains(messagesOf(result.Warnings, "legacy_hook_sessions_invalidated"), "old foreign-hook session records") {
		t.Fatalf("upgrade did not report invalidation: %+v", result.Warnings)
	}
}
