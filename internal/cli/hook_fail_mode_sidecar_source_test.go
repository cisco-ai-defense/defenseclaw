// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// An upgrade leaves the previous release's hooks/.hookcfg until the new
// gateway renders it. 1.0.2 resolved an unset mode from the guardrail mode
// (open under observe), so a sidecar open without this release's
// fail_mode_sources entry is not an operator choice: the native hook fails
// closed on it unless the data directory's config.yaml sets open (the
// operator's guardrail fail-mode open, 0.8.x and 1.0.x alike). A mode this
// release recorded from the config is followed as written.
func TestNativeHookIgnoresAnEarlierReleasesSidecarOpen(t *testing.T) {
	const v102 = `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"claudecode":"open","codex":"open"}}`
	for _, test := range []struct {
		name, sidecar, config, connector, want string
	}{
		{name: "1.0.2 sidecar, config keys empty", sidecar: v102, config: "guardrail:\n  mode: observe\n", connector: "codex", want: "closed"},
		{name: "1.0.2 sidecar, no config", sidecar: v102, connector: "claudecode", want: "closed"},
		{name: "1.0.2 sidecar, operator open in the config", sidecar: v102, config: "guardrail:\n  mode: observe\n  hook_fail_mode: open\n", connector: "codex", want: "open"},
		{name: "1.0.2 sidecar, connector open in the config", sidecar: v102, config: "guardrail:\n  connectors:\n    claude-code:\n      hook_fail_mode: OPEN\n", connector: "claudecode", want: "open"},
		{name: "1.0.2 sidecar, config closed", sidecar: v102, config: "guardrail:\n  hook_fail_mode: closed\n", connector: "codex", want: "closed"},
		{name: "1.0.2 sidecar, automatic protection without its own mode", sidecar: v102, config: "guardrail:\n  hook_fail_mode: open\napplication_protection:\n  enabled: true\n", connector: "codex", want: "open"},
		{name: "1.0.2 sidecar, automatic protection closes it", sidecar: v102, config: "guardrail:\n  hook_fail_mode: open\napplication_protection:\n  enabled: true\n  guardrail:\n    hook_fail_mode: closed\n", connector: "codex", want: "closed"},
		{name: "1.0.2 sidecar, automatic protection opens it", sidecar: v102, config: "application_protection:\n  enabled: true\n  guardrail:\n    hook_fail_mode: open\n", connector: "codex", want: "open"},
		{name: "1.0.2 sidecar, config does not parse", sidecar: v102, config: "guardrail: [\n", connector: "codex", want: "closed"},
		{name: "0.8.x sidecar", sidecar: "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n", connector: "codex", want: "closed"},
		{name: "0.8.x sidecar, operator open in the config", sidecar: "DEFENSECLAW_FAIL_MODE=open\n", config: "guardrail:\n  hook_fail_mode: open\n", connector: "codex", want: "open"},
		{name: "unscoped legacy open", sidecar: `{"version":2,"legacy_fail_mode":"open"}`, connector: "codex", want: "closed"},
		{name: "1.0.4 sidecar open from the config", sidecar: `{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`, connector: "codex", want: "open"},
		{name: "1.0.4 source for a peer only", sidecar: `{"version":2,"fail_modes":{"codex":"open","claudecode":"closed"},"fail_mode_sources":{"claudecode":"config"}}`, connector: "codex", want: "closed"},
		{name: "1.0.4 sidecar closed", sidecar: `{"version":2,"fail_modes":{"codex":"closed"},"fail_mode_sources":{"codex":"config"}}`, config: "guardrail:\n  hook_fail_mode: open\n", connector: "codex", want: "closed"},
		// Cursor's sidecar open from an observe render is no operator choice;
		// an explicit open outside action mode is (r104 W3 G3-upg).
		{name: "cursor sidecar open, no config", sidecar: `{"version":2,"fail_modes":{"cursor":"open"}}`, connector: "cursor", want: "closed"},
		{name: "cursor sidecar open, observe config", sidecar: `{"version":2,"fail_modes":{"cursor":"open"}}`, config: "guardrail:\n  mode: observe\n", connector: "cursor", want: "closed"},
		{name: "cursor sidecar open, operator open", sidecar: `{"version":2,"fail_modes":{"cursor":"open"}}`, config: "guardrail:\n  hook_fail_mode: open\n", connector: "cursor", want: "open"},
		{name: "cursor sidecar open, operator open under action", sidecar: `{"version":2,"fail_modes":{"cursor":"open"}}`, config: "guardrail:\n  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", connector: "cursor", want: "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
			t.Setenv("DEFENSECLAW_FAIL_MODE", "")
			writeHookSidecarForTest(t, home, test.sidecar)
			if test.config != "" {
				if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := buildHookOptions(test.connector, "PreToolUse", "", "").FailMode; got != test.want {
				t.Fatalf("fail mode = %q, want %q", got, test.want)
			}
			if got := hookPreRunFailsClosed(hookFailureContext{connector: test.connector}); got != true {
				t.Fatalf("pre-run failure fails closed = %v, want %v", got, true)
			}
		})
	}
}

// The environment cannot point the check at another config to reopen a hook.
func TestNativeHookSidecarOpenIsNotConfirmedByDefenseclawConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
	writeHookSidecarForTest(t, home, `{"version":2,"fail_modes":{"codex":"open"}}`)
	other := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(other, []byte("guardrail:\n  hook_fail_mode: open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CONFIG", other)
	if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != "closed" {
		t.Fatalf("fail mode = %q, want closed", got)
	}
}
