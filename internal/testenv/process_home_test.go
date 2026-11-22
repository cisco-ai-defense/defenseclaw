// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"testing"
)

func TestIsolateProcessHomeMovesHomeAndClearsTheAgentRoots(t *testing.T) {
	t.Setenv("HOME", "/real/home")
	t.Setenv("CLAUDE_CONFIG_DIR", "/real/claude")
	t.Setenv("CODEX_HOME", "/real/codex")
	restore, err := IsolateProcessHome()
	if err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")
	if home == "/real/home" || home == "" {
		t.Fatalf("HOME = %q", home)
	}
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		t.Fatalf("the process home does not exist: %v", err)
	}
	for _, name := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME"} {
		if _, ok := os.LookupEnv(name); ok {
			t.Errorf("%s is still set", name)
		}
	}
	restore()
	if got := os.Getenv("HOME"); got != "/real/home" {
		t.Errorf("HOME after restore = %q", got)
	}
	if got := os.Getenv("CLAUDE_CONFIG_DIR"); got != "/real/claude" {
		t.Errorf("CLAUDE_CONFIG_DIR after restore = %q", got)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("the process home was not removed: %v", err)
	}
}
