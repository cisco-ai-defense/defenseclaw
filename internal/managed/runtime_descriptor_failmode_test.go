// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strconv"
	"strings"
	"testing"
)

func failModeTestDescriptor() *RuntimeDescriptor {
	return &RuntimeDescriptor{
		SchemaVersion: RuntimeDescriptorSchemaVersion, Profile: ProfileStandalone,
		ServiceUser: "defenseclaw", ServiceUID: 995, ServiceGID: 985,
		APIAddr: StandaloneAPIAddr, MachinePolicyConnectors: []string{"codex"},
	}
}

// OpenHookConnectors round-trips sorted, is omitted when empty (a closed
// deployment's descriptor bytes are unchanged), and HookFailMode reads it:
// open only for a listed connector.
func TestRuntimeDescriptorOpenHookConnectors(t *testing.T) {
	closed, err := MarshalRuntimeDescriptor(failModeTestDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(closed), "open_hook_connectors") {
		t.Fatalf("a closed deployment's descriptor names open connectors:\n%s", closed)
	}
	d := failModeTestDescriptor()
	d.OpenHookConnectors = []string{"kiro", "codex"}
	data, err := MarshalRuntimeDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRuntimeDescriptor(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(parsed.OpenHookConnectors, ","); got != "codex,kiro" {
		t.Fatalf("open connectors = %q, want codex,kiro", got)
	}
	for connector, want := range map[string]string{"codex": "open", " Kiro ": "open", "claudecode": "closed"} {
		if got := parsed.HookFailMode(connector); got != want {
			t.Errorf("HookFailMode(%q) = %q, want %q", connector, got, want)
		}
	}
	if got := (*RuntimeDescriptor)(nil).HookFailMode("codex"); got != "closed" {
		t.Fatalf("nil descriptor fail mode = %q, want closed", got)
	}
	for _, bad := range [][]string{{"codex", "codex"}, {"Codex"}, {""}} {
		d := failModeTestDescriptor()
		d.OpenHookConnectors = bad
		if err := d.Validate(); err == nil {
			t.Errorf("open connectors %q validated", bad)
		}
	}
}

func TestRuntimeDescriptorPolicyViewPinsAreBoundToListedConnectors(t *testing.T) {
	d := failModeTestDescriptor()
	d.PolicyViewDigests = map[string]string{"codex": strings.Repeat("a", 64)}
	data, err := MarshalRuntimeDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRuntimeDescriptor(data)
	if err != nil || parsed.PolicyViewDigests["codex"] != d.PolicyViewDigests["codex"] {
		t.Fatalf("policy-view pin did not round-trip: %v, %+v", err, parsed)
	}
	for _, bad := range []map[string]string{
		{"codex": "not-a-digest"},
		{"codex": strings.Repeat("A", 64)},
		{"claudecode": strings.Repeat("a", 64)},
	} {
		d := failModeTestDescriptor()
		d.PolicyViewDigests = bad
		if err := d.Validate(); err == nil {
			t.Errorf("invalid policy-view pins %v validated", bad)
		}
	}
}

func TestRuntimeDescriptorPerAccountPinsRejectInvalidSources(t *testing.T) {
	good := PolicyViewFilePin{SHA256: strings.Repeat("a", 64), Size: 5, Mode: 0o600, Device: 1, Inode: 2, MTime: 3, CTime: 4}
	d := failModeTestDescriptor()
	d.PolicyViewUserSources = map[string]map[string]PolicyViewFilePin{"codex": {"alice": good}}
	data, err := MarshalRuntimeDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRuntimeDescriptor(data)
	if err != nil || parsed.PolicyViewUserSources["codex"]["alice"] != good {
		t.Fatalf("per-account pin did not round-trip: %v, %+v", err, parsed)
	}
	for _, bad := range []map[string]map[string]PolicyViewFilePin{
		{"codex": {"../alice": good}},
		{"codex": {"alice": {SHA256: strings.Repeat("a", 64)}}},
		{"claudecode": {"alice": good}},
		{"copilot": {"alice": good}},
	} {
		d := failModeTestDescriptor()
		d.PolicyViewUserSources = bad
		if err := d.Validate(); err == nil {
			t.Errorf("invalid per-account sources %+v validated", bad)
		}
	}
	large := failModeTestDescriptor()
	large.MachinePolicyConnectors = []string{"codex", "claudecode"}
	large.PolicyViewUserSources = map[string]map[string]PolicyViewFilePin{"codex": {}, "claudecode": {}}
	for i := range 128 {
		name := strings.Repeat("u", 200) + strconv.Itoa(i)
		large.PolicyViewUserSources["codex"][name] = good
		large.PolicyViewUserSources["claudecode"][name] = good
	}
	if _, err := MarshalRuntimeDescriptor(large); err == nil {
		t.Fatal("oversize per-account attestation descriptor was published")
	}
}
