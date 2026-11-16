// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A restart-required change is reported as the setting it belongs to: never
// a map key below it (a connector, profile or group name), and only paths
// the managed classifier counts.
func TestRestartSettingPatterns(t *testing.T) {
	for _, tc := range []struct {
		before, after string
		want          []string
	}{
		{"guardrail:\n  hook_self_heal: true\n", "guardrail:\n  hook_self_heal: false\n", []string{"guardrail.hook_self_heal"}},
		{"gateway:\n  port: 1\n", "gateway:\n  port: 2\n", []string{"gateway"}},
		{"guardrail:\n  connectors:\n    codex:\n      enabled: false\n", "guardrail:\n  connectors:\n    codex:\n      enabled: true\n", []string{"guardrail.connectors.*.enabled"}},
		// An empty connector block has no leaf: the block itself changes.
		{"guardrail:\n  mode: observe\n", "guardrail:\n  mode: observe\n  connectors:\n    secret-agent-name: {}\n", []string{"guardrail.connectors.*"}},
		{"guardrail:\n  mode: observe\n", "guardrail:\n  mode: observe\n  connectors:\n    secret-agent-name:\n      enabled: true\n", []string{"guardrail.connectors.*.enabled"}},
		{"enterprise:\n  enrollment:\n    include_groups: [\"DOMAIN\\\\eng\"]\n", "enterprise:\n  enrollment:\n    include_groups: [\"DOMAIN\\\\ops\"]\n", []string{"enterprise.enrollment"}},
		{"enterprise:\n  profiles:\n    alice-team:\n      mode: observe\n", "enterprise:\n  profiles:\n    alice-team:\n      mode: action\n", []string{"enterprise.profiles"}},
		{"enterprise:\n  inspection:\n    local: true\n", "enterprise:\n  inspection:\n    local: false\n", nil},
		{"guardrail:\n  mode: observe\n", "guardrail:\n  mode: action\n", nil},
		{"fleet:\n  enabled: false\n", "fleet:\n  enabled: true\n", []string{"fleet.enabled"}},
	} {
		restart, err := ManagedConfigRestartRequired([]byte(tc.before), []byte(tc.after), ManagedDefaults{})
		if err != nil {
			t.Fatal(err)
		}
		if got := RestartSettingPatterns(restart); !slices.Equal(got, tc.want) {
			t.Fatalf("%q -> %q: restart %v gives %v, want %v", tc.before, tc.after, restart, got, tc.want)
		}
	}
}

// A whole block that appears is cut at its own depth; the list is sorted,
// unique and bounded, and a path the classifier does not count gives nothing.
func TestRestartSettingPatternsShape(t *testing.T) {
	if got := RestartSettingPatterns([]string{"guardrail", "gateway.port", "gateway.host", `guardrail.connectors["My Agent"].enabled`, "telemetry.sample"}); !slices.Equal(got, []string{"gateway", "guardrail", "guardrail.connectors.*.enabled"}) {
		t.Fatalf("patterns = %v", got)
	}
	var many []string
	for i := range MaxRestartSettingPatterns + 8 {
		many = append(many, fmt.Sprintf("enterprise.section_%c%c", 'a'+i/26, 'a'+i%26))
	}
	if got := RestartSettingPatterns(many); len(got) != MaxRestartSettingPatterns || !slices.IsSorted(got) {
		t.Fatalf("bounded patterns = %d %v", len(got), got)
	}
	if got := RestartSettingPatterns([]string{"enterprise.Section9"}); len(got) != 0 {
		t.Fatalf("a section outside the schema key shape is reported: %v", got)
	}
}

// A setting one config omits and the other spells out at the device's
// default is no change; any other value, an unparseable installed config
// and no defaults still count (F03).
func TestManagedConfigRestartRequiredResolvesOmittedDefaults(t *testing.T) {
	unix := ManagedDefaultsFor(managed.StandaloneLayout{GOOS: "linux", DataDir: "/var/lib/defenseclaw", APIAddr: "127.0.0.1:18970"})
	windows := ManagedDefaults{GOOS: "windows", DataDir: `C:\ProgramData\Cisco\DefenseClaw\runtime`, APIBind: "127.0.0.1", APIPort: 18970}
	const rest = "guardrail:\n  mode: observe\n"
	const listener = "gateway:\n  api_bind: 127.0.0.1\n  api_port: 18970\n"
	for _, tc := range []struct {
		name          string
		defaults      ManagedDefaults
		before, after string
		want          []string
	}{
		{"data_dir omitted", unix, "data_dir: /var/lib/defenseclaw\n" + rest, rest, nil},
		{"data_dir spelled out", unix, rest, "data_dir: /var/lib/defenseclaw/\n" + rest, nil},
		{"listener omitted", unix, listener + rest, rest, nil},
		{"empty api_bind", unix, listener + rest, "gateway:\n  api_bind: \"\"\n" + rest, nil},
		{"Windows data_dir spelling", windows, `data_dir: 'c:/programdata/cisco/defenseclaw/runtime\'` + "\n" + rest, rest, nil},
		{"other data_dir", unix, "data_dir: /srv/dc\n" + rest, rest, []string{"data_dir"}},
		{"other port", unix, listener + rest, "gateway:\n  api_port: 18971\n" + rest, []string{"gateway.api_port"}},
		{"other gateway key", unix, listener + rest, "gateway:\n  port: 1\n" + rest, []string{"gateway.port"}},
		{"no defaults", ManagedDefaults{}, "data_dir: /var/lib/defenseclaw\n" + rest, rest, []string{"data_dir"}},
		{"unparseable installed config", unix, "data_dir: [", "data_dir: /var/lib/defenseclaw\n" + rest, []string{"data_dir"}},
	} {
		got, err := ManagedConfigRestartRequired([]byte(tc.before), []byte(tc.after), tc.defaults)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Fatalf("%s: restart %v (%v), want %v", tc.name, got, err, tc.want)
		}
	}
}
