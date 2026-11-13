// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"testing"
)

// accountEnv are the variables through which the real account reaches a
// test: the DefenseClaw data directory and config, the hook fail-mode the
// shell hooks read, and the agents' own config roots. A developer shell, the
// dcenv of a shared host or a CI image can set any of them.
var accountEnv = []string{
	"DEFENSECLAW_HOME",
	"DEFENSECLAW_CONFIG",
	"DEFENSECLAW_FAIL_MODE",
	"DEFENSECLAW_HOOK_HOME",
	"CODEX_HOME",
	"CLAUDE_CONFIG_DIR",
	"HERMES_HOME",
}

// IsolateAccount gives the test an account of its own: a new empty home (SetHome
// moves every per-user root with it) and none of the accountEnv variables. A
// test that runs a connector Setup, reads the hook runtime's config or
// lists agent config folders would otherwise read the real ~/.defenseclaw,
// ~/.claude or ~/.codex of whoever runs it and pass or fail by the host
// (GAP-0137: no_config opened an outage on a host that had a config.yaml).
// It returns the home. A test that needs one of these variables sets it
// after the call.
func IsolateAccount(t testing.TB) string {
	t.Helper()
	home := t.TempDir()
	SetHome(t, home)
	for _, name := range accountEnv {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
	}
	return home
}
