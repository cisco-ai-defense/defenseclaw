// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// minimalPack is the smallest valid pack; tests append or replace keys.
const minimalPack = `version: 1
name: team
network: {mode: open}
approvals: {mode: triage}
workspace: {mode: mount}
harness: {yolo: true}
mcp: {import: true, host_ports: false}
hooks: {fail_mode: closed}
`

func mustParse(t *testing.T, doc string) *Pack {
	t.Helper()
	pack, err := Parse([]byte(doc), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return pack
}

func wantPackError(t *testing.T, err error, code, field string) *Error {
	t.Helper()
	var packErr *Error
	if !errors.As(err, &packErr) {
		t.Fatalf("error = %v (%T), want *packs.Error", err, err)
	}
	if packErr.Code != code || (field != "" && packErr.Field != field) {
		t.Fatalf("error = %+v, want code %q field %q", packErr, code, field)
	}
	return packErr
}

func TestBuiltinPacksLoad(t *testing.T) {
	want := map[string]struct {
		profile, approvals, workspace string
		yolo, mcpImport, hostPorts    bool
	}{
		"open":     {"open", ApprovalsTriage, "mount", true, true, true},
		"balanced": {"balanced", ApprovalsTriage, "mount", true, true, true},
		"strict":   {"strict", ApprovalsManual, "copy", false, false, false},
	}
	if got := BuiltinNames(); !reflect.DeepEqual(got, []string{"open", "balanced", "strict"}) {
		t.Fatalf("BuiltinNames() = %v", got)
	}
	digests := map[string]bool{}
	for _, name := range BuiltinNames() {
		t.Run(name, func(t *testing.T) {
			pack, err := Builtin(name)
			if err != nil {
				t.Fatalf("Builtin(%q): %v", name, err)
			}
			w := want[name]
			if pack.Name != name || !pack.Builtin || pack.Source != "builtin:"+name {
				t.Fatalf("identity = %q builtin=%v source=%q", pack.Name, pack.Builtin, pack.Source)
			}
			if pack.Profile() != w.profile || pack.Approvals.Mode != w.approvals || pack.Workspace.Mode != w.workspace {
				t.Fatalf("posture = profile %q approvals %q workspace %q", pack.Profile(), pack.Approvals.Mode, pack.Workspace.Mode)
			}
			if pack.Harness.Yolo != w.yolo || pack.MCP.Import != w.mcpImport || pack.MCP.HostPorts != w.hostPorts {
				t.Fatalf("switches = yolo %v import %v host_ports %v", pack.Harness.Yolo, pack.MCP.Import, pack.MCP.HostPorts)
			}
			if pack.Hooks.FailMode != FailModeClosed || !reflect.DeepEqual(pack.Egress.Feeds, []string{FeedBuiltin}) {
				t.Fatalf("hooks %q feeds %v", pack.Hooks.FailMode, pack.Egress.Feeds)
			}
			for _, mask := range []string{".env", "*.pem", ".aws/credentials"} {
				if !slices.Contains(pack.Workspace.Masks, mask) {
					t.Fatalf("masks %v lack %q", pack.Workspace.Masks, mask)
				}
			}
			for _, review := range []string{"package.json", ".envrc", ".github/workflows/**"} {
				if !slices.Contains(pack.Workspace.Review, review) {
					t.Fatalf("review %v lacks %q", pack.Workspace.Review, review)
				}
			}
			if !strings.HasPrefix(pack.Digest, "sha256:") || len(pack.Digest) != len("sha256:")+64 || digests[pack.Digest] {
				t.Fatalf("digest %q is not a unique sha256", pack.Digest)
			}
			digests[pack.Digest] = true
		})
	}
	balanced, _ := Builtin("balanced")
	for _, host := range []string{"registry.npmjs.org", "pypi.org", "github.com", "proxy.golang.org"} {
		if !slices.Contains(balanced.Egress.Allow, host) {
			t.Fatalf("balanced allowlist lacks %s", host)
		}
	}
	if _, err := Builtin("permissive"); err == nil {
		t.Fatal("Builtin(permissive) must fail")
	}
}

func TestParseRejectsDuplicateTopLevelKeys(t *testing.T) {
	_, err := Parse([]byte(minimalPack+"harness: {yolo: false}\n"), "test")
	wantPackError(t, err, "yaml_duplicate", "harness")
}

func TestParseNormalizesValues(t *testing.T) {
	doc := `version: 1
name: " team "
description: "  Team pack  "
network: {mode: allowlist}
approvals: {mode: auto}
egress:
  block: [Paste.Example., "*.Ngrok.io", paste.example]
  allow: ["[2001:db8::1]"]
  ports: [443, 443, 8443]
workspace:
  mode: copy
  masks: [" .env ", .env]
  review: [Makefile]
  max_upload_mb: 50
harness: {yolo: false, allowed: [claude-code, codex, claudecode]}
mcp: {import: false, host_ports: true, blocked_tools: ["github:delete_*", "github:delete_*"]}
hooks: {fail_mode: closed}
`
	pack := mustParse(t, doc)
	if pack.Name != "team" || pack.Description != "Team pack" {
		t.Fatalf("name %q description %q", pack.Name, pack.Description)
	}
	if pack.Profile() != "balanced" || pack.Approvals.Mode != ApprovalsAuto {
		t.Fatalf("profile %q approvals %q", pack.Profile(), pack.Approvals.Mode)
	}
	if !reflect.DeepEqual(pack.Egress.Block, []string{"paste.example", "*.ngrok.io"}) {
		t.Fatalf("block = %v", pack.Egress.Block)
	}
	if !reflect.DeepEqual(pack.Egress.Allow, []string{"[2001:db8::1]"}) {
		t.Fatalf("allow = %v", pack.Egress.Allow)
	}
	if !reflect.DeepEqual(pack.Egress.Ports, []int{443, 8443}) || pack.Egress.LargeUploadMB != 25 {
		t.Fatalf("ports %v large upload %d", pack.Egress.Ports, pack.Egress.LargeUploadMB)
	}
	if !reflect.DeepEqual(pack.Egress.Feeds, []string{FeedBuiltin}) {
		t.Fatalf("absent feeds must default to builtin, got %v", pack.Egress.Feeds)
	}
	if !reflect.DeepEqual(pack.Workspace.Masks, []string{".env"}) || pack.Workspace.MaxUploadMB != 50 {
		t.Fatalf("workspace = %+v", pack.Workspace)
	}
	if !reflect.DeepEqual(pack.Harness.Allowed, []string{"claudecode", "codex"}) {
		t.Fatalf("allowed harnesses = %v", pack.Harness.Allowed)
	}
	if !reflect.DeepEqual(pack.MCP.BlockedTools, []string{"github:delete_*"}) {
		t.Fatalf("blocked tools = %v", pack.MCP.BlockedTools)
	}

	defaults := mustParse(t, minimalPack)
	if !reflect.DeepEqual(defaults.Egress.Ports, []int{80, 443}) || defaults.Workspace.MaxUploadMB != 500 ||
		defaults.Egress.LargeUploadMB != 25 || defaults.Description != "" {
		t.Fatalf("defaults = %+v", defaults)
	}
	noFeeds := mustParse(t, strings.Replace(minimalPack, "network: {mode: open}", "network: {mode: open}\negress: {feeds: []}", 1))
	if len(noFeeds.Egress.Feeds) != 0 {
		t.Fatalf("explicit empty feeds must stay empty, got %v", noFeeds.Egress.Feeds)
	}
	deny := mustParse(t, strings.Replace(minimalPack, "network: {mode: open}", "network: {mode: deny}\negress: {ports: []}", 1))
	if deny.Profile() != "strict" || len(deny.Egress.Ports) != 0 {
		t.Fatalf("deny pack = profile %q ports %v", deny.Profile(), deny.Egress.Ports)
	}
}

func TestParseRejects(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(minimalPack, old, new, 1) }
	for _, tc := range []struct {
		name, doc, code, field string
	}{
		{"empty", "", "yaml_empty", ""},
		{"not yaml", "version: [1\n", "yaml_invalid", ""},
		{"two documents", minimalPack + "---\nversion: 1\n", "yaml_documents", ""},
		{"top-level list", "- 1\n", "yaml_type", ""},
		{"unknown key", minimalPack + "extra: true\n", "unknown_field", "extra"},
		{"unknown nested key", replace("hooks: {fail_mode: closed}", "hooks: {fail_mode: closed, mode: open}"), "unknown_field", "hooks.mode"},
		{"duplicate nested key", replace("harness: {yolo: true}", "harness: {yolo: true, yolo: false}"), "yaml_duplicate", "harness.yolo"},
		{"anchor", replace("harness: {yolo: true}", "harness: &h {yolo: true}"), "yaml_alias", "harness"},
		{"scalar anchor", replace("name: team", "name: &n team"), "yaml_alias", "name"},
		{"undefined alias", replace("harness: {yolo: true}", "harness: {yolo: *y}"), "yaml_invalid", ""},
		{"merge key", replace("harness: {yolo: true}", "harness: {<<: {yolo: true}}"), "yaml_alias", "harness.<<"},
		{"null value", replace("harness: {yolo: true}", "harness: {yolo: null}"), "yaml_type", "harness.yolo"},
		{"quoted bool", replace("harness: {yolo: true}", `harness: {yolo: "true"}`), "yaml_type", "harness.yolo"},
		{"integer name", replace("name: team", "name: 7"), "yaml_type", "name"},
		{"string port", replace("network: {mode: open}", "network: {mode: open}\negress: {ports: ['443']}"), "yaml_type", "egress.ports[0]"},
		{"scalar list", replace("network: {mode: open}", "network: {mode: open}\negress: {block: paste.example}"), "yaml_type", "egress.block"},
		{"non-string key", minimalPack + "1: x\n", "yaml_type", ""},
		{"missing version", replace("version: 1\n", ""), "missing_field", "version"},
		{"future version", replace("version: 1", "version: 2"), "unsupported_version", "version"},
		{"missing name", replace("name: team\n", ""), "missing_field", "name"},
		{"uppercase name", replace("name: team", "name: Team"), "invalid_value", "name"},
		{"missing network", replace("network: {mode: open}\n", ""), "missing_field", "network.mode"},
		{"unknown network", replace("mode: open}", "mode: wide}"), "invalid_value", "network.mode"},
		{"unknown approvals", replace("mode: triage}", "mode: never}"), "invalid_value", "approvals.mode"},
		{"unknown workspace", replace("mode: mount}", "mode: overlay}"), "invalid_value", "workspace.mode"},
		{"open fail mode", replace("fail_mode: closed", "fail_mode: open"), "invalid_value", "hooks.fail_mode"},
		{"missing yolo", replace("harness: {yolo: true}", "harness: {}"), "missing_field", "harness.yolo"},
		{"missing mcp import", replace("mcp: {import: true, host_ports: false}", "mcp: {host_ports: false}"), "missing_field", "mcp.import"},
		{"unknown feed", replace("network: {mode: open}", "network: {mode: open}\negress: {feeds: [custom]}"), "invalid_value", "egress.feeds[0]"},
		{"host glob with scheme", replace("network: {mode: open}", "network: {mode: open}\negress: {block: ['https://x.example']}"), "invalid_value", "egress.block[0]"},
		{"inner wildcard", replace("network: {mode: open}", "network: {mode: open}\negress: {allow: ['a.*.example']}"), "invalid_value", "egress.allow[0]"},
		{"allow every host", replace("network: {mode: open}", "network: {mode: allowlist}\negress: {allow: [pypi.org, '*']}"), "invalid_value", "egress.allow[1]"},
		{"allow a top-level domain", replace("network: {mode: open}", "network: {mode: open}\negress: {allow: ['*.COM']}"), "invalid_value", "egress.allow[0]"},
		{"allow a public suffix", replace("network: {mode: open}", "network: {mode: allowlist}\negress: {allow: ['*.co.uk']}"), "invalid_value", "egress.allow[0]"},
		{"port zero", replace("network: {mode: open}", "network: {mode: open}\negress: {ports: [0]}"), "invalid_value", "egress.ports[0]"},
		{"no ports while open", replace("network: {mode: open}", "network: {mode: open}\negress: {ports: []}"), "invalid_value", "egress.ports"},
		{"negative large upload", replace("network: {mode: open}", "network: {mode: open}\negress: {large_upload_mb: -1}"), "invalid_value", "egress.large_upload_mb"},
		{"zero upload cap", replace("workspace: {mode: mount}", "workspace: {mode: mount, max_upload_mb: 0}"), "invalid_value", "workspace.max_upload_mb"},
		{"absolute mask", replace("workspace: {mode: mount}", "workspace: {mode: mount, masks: [/etc/passwd]}"), "invalid_value", "workspace.masks[0]"},
		{"home mask", replace("workspace: {mode: mount}", "workspace: {mode: mount, masks: ['~/.ssh/*']}"), "invalid_value", "workspace.masks[0]"},
		{"escaping review", replace("workspace: {mode: mount}", "workspace: {mode: mount, review: ['../x']}"), "invalid_value", "workspace.review[0]"},
		{"backslash mask", replace("workspace: {mode: mount}", `workspace: {mode: mount, masks: ['a\b']}`), "invalid_value", "workspace.masks[0]"},
		{"drive letter mask", replace("workspace: {mode: mount}", "workspace: {mode: mount, masks: ['C:/x']}"), "invalid_value", "workspace.masks[0]"},
		{"empty mask", replace("workspace: {mode: mount}", "workspace: {mode: mount, masks: ['  ']}"), "invalid_value", "workspace.masks[0]"},
		{"bad harness", replace("harness: {yolo: true}", "harness: {yolo: true, allowed: ['claude code']}"), "invalid_value", "harness.allowed[0]"},
		{"bad blocked tool", replace("mcp: {import: true, host_ports: false}", "mcp: {import: true, host_ports: false, blocked_tools: ['rm -rf']}"), "invalid_value", "mcp.blocked_tools[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc), "test")
			wantPackError(t, err, tc.code, tc.field)
		})
	}
}

func TestIsBroadAllowGlob(t *testing.T) {
	for glob, want := range map[string]bool{
		"*": true, " * ": true, "*.com": true, "*.CO.UK.": true, "*.io": true,
		"*.example.com": false, "*.github.io": false, "*.corp": false, "*.internal": false,
		"com": false, "example.com": false, "203.0.113.7": false, "[2001:db8::1]": false,
	} {
		if got := IsBroadAllowGlob(glob); got != want {
			t.Errorf("IsBroadAllowGlob(%q) = %v, want %v", glob, got, want)
		}
	}
	// Block lists may still name every host.
	pack := mustParse(t, strings.Replace(minimalPack, "network: {mode: open}", "network: {mode: open}\negress: {block: ['*', '*.com']}", 1))
	if !reflect.DeepEqual(pack.Egress.Block, []string{"*", "*.com"}) {
		t.Fatalf("block = %v", pack.Egress.Block)
	}
}

func TestParseLimits(t *testing.T) {
	big := minimalPack + "description: " + strings.Repeat("x", MaxPackBytes) + "\n"
	_, err := Parse([]byte(big), "test")
	wantPackError(t, err, "too_large", "")

	_, err = Parse([]byte(minimalPack+"description: "+strings.Repeat("x", maxDescription+1)+"\n"), "test")
	wantPackError(t, err, "invalid_value", "description")

	ports := make([]string, maxPorts+1)
	for i := range ports {
		ports[i] = strconv.Itoa(1000 + i)
	}
	doc := strings.Replace(minimalPack, "network: {mode: open}",
		"network: {mode: open}\negress: {ports: ["+strings.Join(ports, ", ")+"]}", 1)
	_, err = Parse([]byte(doc), "test")
	wantPackError(t, err, "invalid_value", "egress.ports")

	masks := make([]string, maxListEntries+1)
	for i := range masks {
		masks[i] = "f" + strconv.Itoa(i)
	}
	doc = strings.Replace(minimalPack, "workspace: {mode: mount}",
		"workspace: {mode: mount, masks: ["+strings.Join(masks, ", ")+"]}", 1)
	_, err = Parse([]byte(doc), "test")
	wantPackError(t, err, "invalid_value", "workspace.masks")
}

func TestErrorMessages(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(minimalPack, "mode: mount}", "mode: overlay}", 1)), "/etc/packs/team/pack.yaml")
	want := `sandbox pack /etc/packs/team/pack.yaml: workspace.mode: "overlay" must be one of mount, copy`
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	_, err = Parse([]byte(minimalPack+"extra: 1\n"), "test")
	if err == nil || !strings.Contains(err.Error(), "line 9: unknown key") {
		t.Fatalf("error = %v, want the line number", err)
	}
	var nilErr *Error
	if nilErr.Error() != "sandbox pack error" {
		t.Fatal("nil *Error must still format")
	}
}

func TestMarshalRoundTrips(t *testing.T) {
	for _, name := range BuiltinNames() {
		pack, err := Builtin(name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := pack.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%s): %v", name, err)
		}
		again, err := Parse(data, "roundtrip")
		if err != nil {
			t.Fatalf("Parse(Marshal(%s)): %v\n%s", name, err, data)
		}
		again.Builtin, again.Source, again.Digest = pack.Builtin, pack.Source, pack.Digest
		if !reflect.DeepEqual(pack, again) {
			t.Fatalf("round trip of %s changed the pack:\n%+v\n%+v", name, pack, again)
		}
	}
}
