// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// hookOutageFailModeNow answers from the config on disk at the time of the
// call, not from what the hooks recorded: a rule pack switched to strict
// after the gateway stopped closes the outage, and a config this release
// cannot load, a managed one or none closes it too.
func TestHookOutageFailModeNowReadsTheConfigOnDisk(t *testing.T) {
	const base = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"
	for _, tc := range []struct {
		name, config, connector, want string
	}{
		{"default pack", base, "codex", "open"},
		{"action mode, default pack", "config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n", "codex", "open"},
		{"permissive pack", base + "  rule_pack: permissive\n", "claudecode", "open"},
		{"strict pack", base + "  rule_pack: strict\n", "codex", "closed"},
		{"strict pack for this connector", base + "  connectors:\n    codex:\n      rule_pack: strict\n", "codex", "closed"},
		{"strict pack for another connector", base + "  connectors:\n    codex:\n      rule_pack: strict\n", "claudecode", "open"},
		{"upper-case connector name", base + "  rule_pack: strict\n", " CODEX ", "closed"},
		{"no connector", base, " ", "closed"},
		{"no config", "", "codex", "closed"},
		{"config this release cannot read", "config_version: 9\nguardrail: [\n", "codex", "closed"},
		{"an older config", "config_version: 7\nguardrail:\n  mode: observe\n", "codex", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", home)
			if tc.config != "" {
				if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(tc.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := hookOutageFailModeNow(tc.connector); got != tc.want {
				t.Fatalf("hookOutageFailModeNow(%q) = %q, want %q", tc.connector, got, tc.want)
			}
		})
	}
}
