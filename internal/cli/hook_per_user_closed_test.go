// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPerUserNativeHookCannotBeOpenedByOldStateOrFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", "")
	if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "hooks", ".hookcfg"), []byte(`{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"", "open"} {
		if got := buildHookOptions("codex", "PreToolUse", "", flag).FailMode; got != "closed" {
			t.Errorf("flag %q: native hook fail mode = %q, want closed", flag, got)
		}
		if !hookPreRunFailsClosed(hookFailureContext{connector: "codex"}) {
			t.Errorf("flag %q: pre-run failure opened", flag)
		}
	}
}
