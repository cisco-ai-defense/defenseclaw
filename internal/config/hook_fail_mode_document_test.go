// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The native hook and the installers' refresh read a config.yaml document's
// explicit fail modes without loading it (a 0.8.x one before 'defenseclaw
// migrate'). A Cursor open the operator wrote is kept outside action mode,
// whose Cursor hooks are closed; before r104 W3 G3-upg every Cursor value was
// ignored, so a 0.8.x explicit open was closed during the upgrade.
func TestConfiguredHookFailModeInDocumentReadsCursor(t *testing.T) {
	for _, test := range []struct{ name, doc, want string }{
		{"0.8.x cursor open in observe", "config_version: 7\nguardrail:\n  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "open"},
		{"global open, mode unset", "guardrail:\n  hook_fail_mode: open\n", "open"},
		{"cursor closed", "guardrail:\n  mode: observe\n  hook_fail_mode: open\n  connectors:\n    cursor:\n      hook_fail_mode: closed\n", "closed"},
		{"cursor open under action", "guardrail:\n  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "closed"},
		{"cursor action override", "guardrail:\n  mode: observe\n  hook_fail_mode: open\n  connectors:\n    cursor:\n      mode: action\n", "closed"},
		{"legacy enforce", "guardrail:\n  mode: enforce\n  hook_fail_mode: open\n", "closed"},
		{"unset", "guardrail:\n  mode: observe\n", ""},
		{"automatic protection with no mode of its own", "guardrail:\n  hook_fail_mode: open\napplication_protection:\n  enabled: true\n", "open"},
		{"automatic protection open under its action", "application_protection:\n  enabled: true\n  guardrail:\n    mode: action\n    hook_fail_mode: open\n", "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ConfiguredHookFailModeInDocument([]byte(test.doc), "cursor"); got != test.want {
				t.Fatalf("cursor fail mode = %q, want %q", got, test.want)
			}
		})
	}
	// Another connector's open does not depend on the guardrail mode.
	if got := ConfiguredHookFailModeInDocument([]byte("guardrail:\n  mode: action\n  hook_fail_mode: open\n"), "codex"); got != "open" {
		t.Fatalf("codex fail mode under action = %q, want open", got)
	}
}

// A 0.8.x or 1.0.x document with automatic protection on: its overlay sets
// the fail mode of a connector it covers, and a connector set up by hand
// keeps its own guardrail value (configuredHookFailModeForConnector, which
// 0.8.10 resolved the same way). Before r104 W3 G3-upg the document read
// returned "" whenever automatic protection was on, so the installers'
// refresh closed an operator's open during the upgrade. Each case agrees
// with the resolver on the decoded config.
func TestConfiguredHookFailModeInDocumentResolvesAutomaticProtection(t *testing.T) {
	const ap = "application_protection:\n  enabled: true\n"
	for _, test := range []struct{ name, doc, want string }{
		{"overlay open", "config_version: 7\nguardrail:\n  mode: observe\n" + ap + "  guardrail:\n    hook_fail_mode: open\n", "open"},
		{"connector overlay open", ap + "  connectors:\n    codex:\n      guardrail:\n        hook_fail_mode: open\n", "open"},
		{"connector overlay closes a global overlay open", ap + "  guardrail:\n    hook_fail_mode: open\n  connectors:\n    codex:\n      guardrail:\n        hook_fail_mode: closed\n", "closed"},
		{"overlay closes a guardrail open", "guardrail:\n  hook_fail_mode: open\n" + ap + "  guardrail:\n    hook_fail_mode: closed\n", "closed"},
		{"set up by hand: its own open wins", "guardrail:\n  connectors:\n    codex:\n      hook_fail_mode: open\n" + ap + "  guardrail:\n    hook_fail_mode: closed\n", "open"},
		{"set up by hand: the global open wins", "guardrail:\n  hook_fail_mode: open\n  connector: codex\n" + ap + "  guardrail:\n    hook_fail_mode: closed\n", "open"},
		{"set up by hand: no overlay", "claw:\n  mode: codex\n" + ap + "  guardrail:\n    hook_fail_mode: open\n", ""},
		{"another connector set up by hand", "guardrail:\n  connector: claudecode\n" + ap + "  guardrail:\n    hook_fail_mode: open\n", "open"},
		{"automatic protection off", "guardrail:\n  mode: observe\napplication_protection:\n  enabled: false\n  guardrail:\n    hook_fail_mode: open\n", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ConfiguredHookFailModeInDocument([]byte(test.doc), "codex"); got != test.want {
				t.Fatalf("codex fail mode = %q, want %q", got, test.want)
			}
			var decoded Config
			if err := yaml.Unmarshal([]byte(test.doc), &decoded); err != nil {
				t.Fatal(err)
			}
			if got := decoded.configuredHookFailModeForConnector("codex"); got != test.want {
				t.Fatalf("the config resolver says %q, the document read %q", got, test.want)
			}
		})
	}
}
