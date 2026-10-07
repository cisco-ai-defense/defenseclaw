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

//go:build !windows

package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A pack that extends another sets only what it changes: the parent fills
// in the rest, lists add to the parent's, scalars and the port list replace.
func TestExtendsMergesTheParent(t *testing.T) {
	root := t.TempDir()
	child := `version: 1
name: team
extends: balanced
egress:
  allow: [artifacts.example.com]
  ports: [443]
workspace:
  masks: ["secrets/**"]
harness: {yolo: false}
`
	dir := writePack(t, root, "team", child)
	pack, err := Load("team", root)
	if err != nil {
		t.Fatal(err)
	}
	balanced, _ := Builtin("balanced")
	if pack.Network.Mode != NetworkAllowlist || pack.Approvals.Mode != ApprovalsTriage || pack.Harness.Yolo ||
		!pack.MCP.Import || pack.Hooks.OnTamper != OnTamperStop || !reflect.DeepEqual(pack.Egress.Ports, []int{443}) {
		t.Fatalf("merged pack = %+v", pack)
	}
	if len(pack.Egress.Allow) != len(balanced.Egress.Allow)+1 || !containsString(pack.Egress.Allow, "artifacts.example.com") ||
		!containsAll(pack.Egress.Allow, balanced.Egress.Allow) {
		t.Fatalf("allow = %v", pack.Egress.Allow)
	}
	if !containsAll(pack.Workspace.Masks, balanced.Workspace.Masks) || !containsString(pack.Workspace.Masks, "secrets/**") ||
		!reflect.DeepEqual(pack.Workspace.Review, balanced.Workspace.Review) {
		t.Fatalf("workspace = %+v", pack.Workspace)
	}
	if pack.Description != "" || pack.Extends != "balanced" || len(pack.Chain) != 1 || pack.Chain[0].Name != "balanced" ||
		!pack.Chain[0].Builtin || pack.Chain[0].Digest != balanced.Digest {
		t.Fatalf("description %q extends %q chain %+v", pack.Description, pack.Extends, pack.Chain)
	}
	// The digest covers the parent's digest and the file's own bytes.
	sum := sha256.Sum256([]byte(balanced.Digest + "\n" + child))
	if want := "sha256:" + hex.EncodeToString(sum[:]); pack.Digest != want {
		t.Fatalf("digest %s, want %s", pack.Digest, want)
	}
	if again, err := Validate(filepath.Join(dir, PackFileName), root); err != nil || again.Digest != pack.Digest {
		t.Fatalf("Validate = %v, %v", again, err)
	}

	// A custom parent: its chain follows, and harness.allowed is replaced.
	writePack(t, root, "base", `version: 1
name: base
extends: strict
harness: {allowed: [codex, claudecode]}
mcp: {blocked_tools: ["fs.write"]}
`)
	writePack(t, root, "leaf", `version: 1
name: leaf
extends: base
harness: {allowed: [codex]}
mcp: {blocked_tools: ["net.*"]}
`)
	leaf, err := Load("leaf", root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leaf.Harness.Allowed, []string{"codex"}) || !reflect.DeepEqual(leaf.MCP.BlockedTools, []string{"fs.write", "net.*"}) ||
		leaf.Network.Mode != NetworkDeny || len(leaf.Chain) != 2 || leaf.Chain[0].Name != "base" || leaf.Chain[1].Name != "strict" {
		t.Fatalf("leaf = %+v chain %+v", leaf, leaf.Chain)
	}
	list, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e.Name == "leaf" && (e.Err != nil || e.Extends != "base") {
			t.Fatalf("list entry %+v", e)
		}
	}
}

func TestExtendsRefusals(t *testing.T) {
	root := t.TempDir()
	extends := func(name, parent string) string {
		return "version: 1\nname: " + name + "\nextends: " + parent + "\n"
	}
	writePack(t, root, "loop-a", extends("loop-a", "loop-b"))
	writePack(t, root, "loop-b", extends("loop-b", "loop-a"))
	writePack(t, root, "self", extends("self", "self"))
	writePack(t, root, "orphan", extends("orphan", "missing"))
	writePack(t, root, "pathy", extends("pathy", "/etc/defenseclaw/pack.yaml"))
	// d1 → d2 → d3 → d4 → d5 → open: five ancestors, one too many.
	for i := 1; i <= 5; i++ {
		parent := "open"
		if i < 5 {
			parent = "d" + string(rune('1'+i))
		}
		writePack(t, root, "d"+string(rune('0'+i)), extends("d"+string(rune('0'+i)), parent))
	}
	for _, tc := range []struct{ ref, code string }{
		{"loop-a", "extends_cycle"},
		{"self", "extends_cycle"},
		{"orphan", "not_found"},
		{"pathy", "invalid_value"},
		{"d1", "extends_depth"},
	} {
		_, err := Load(tc.ref, root)
		wantPackError(t, err, tc.code, "extends")
	}
	// Four ancestors are fine.
	if _, err := Load("d2", root); err != nil {
		t.Fatalf("four ancestors: %v", err)
	}
	// Parse and a file loaded without a pack directory find no custom parent;
	// a built-in parent needs none.
	_, err := Parse([]byte(extends("x", "open")), "test")
	wantPackError(t, err, "extends_unsupported", "extends")
	_, err = Validate(filepath.Join(root, "orphan"), "")
	wantPackError(t, err, "not_found", "extends")
	if _, err := Validate(filepath.Join(root, "d5"), ""); err != nil {
		t.Fatalf("a built-in parent: %v", err)
	}
	// The merged pack is validated as a whole: a deny parent's empty port
	// list does not carry over to a child that turns the proxy on.
	writePack(t, root, "denyish", "version: 1\nname: denyish\nnetwork: {mode: deny}\napprovals: {mode: manual}\nworkspace: {mode: copy}\n"+
		"harness: {yolo: false}\nmcp: {import: false, host_ports: false}\nhooks: {fail_mode: closed}\negress: {ports: []}\n")
	writePack(t, root, "opened", extends("opened", "denyish")+"network: {mode: allowlist}\n")
	_, err = Load("opened", root)
	wantPackError(t, err, "invalid_value", "egress.ports")
}

// Inherited built-in allow entries stay DefenseClaw's curated ones; the
// pack's own entries are the operator's, which allow_unblock: false drops.
func TestExtendsResolveCuratedAllow(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "team", "version: 1\nname: team\nextends: balanced\negress: {allow: [artifacts.example.com]}\n")
	eff, violations := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "team", root }), Flags{})
	wantViolations(t, violations)
	if containsString(eff.curatedAllow, "artifacts.example.com") || !containsString(eff.curatedAllow, "registry.npmjs.org") ||
		!containsString(eff.Egress.Allow, "artifacts.example.com") {
		t.Fatalf("curated %v allow %v", eff.curatedAllow, eff.Egress.Allow)
	}
	opts, err := eff.EgressOptions(nil)
	if err != nil || len(opts.Allowlists) != 1 || !reflect.DeepEqual(opts.Allow, []string{"artifacts.example.com"}) {
		t.Fatalf("egress options allow %v allowlists %d: %v", opts.Allow, len(opts.Allowlists), err)
	}
	eff, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.PackDir, o.Admin.AllowUnblock = "team", root, boolPtr(false)
	}), Flags{})
	v := onlyViolation(t, violations)
	if v.Key != "egress.allow" || v.Attempted != "artifacts.example.com" || containsString(eff.Egress.Allow, "artifacts.example.com") ||
		!containsString(eff.Egress.Allow, "registry.npmjs.org") {
		t.Fatalf("violation %+v allow %v", v, eff.Egress.Allow)
	}
}

// The custom packs a pack extends are policy sources (never shared with a
// mounted sandbox), and a trusted pack's custom parents must be trusted too.
func TestExtendsPolicySourcesAndTrust(t *testing.T) {
	root := t.TempDir()
	baseDir := writePack(t, root, "base", "version: 1\nname: base\nextends: strict\n")
	teamDir := writePack(t, root, "team", "version: 1\nname: team\nextends: base\n")
	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "team", root }), Flags{})
	sources := eff.PolicySources()
	if !containsString(sources, filepath.Join(baseDir, PackFileName)) || !containsString(sources, filepath.Join(teamDir, PackFileName)) {
		t.Fatalf("PolicySources() = %v", sources)
	}

	previous := validateTrustedFile
	t.Cleanup(func() { validateTrustedFile = previous })
	var checked []string
	validateTrustedFile = func(path, _ string) error {
		checked = append(checked, path)
		if strings.HasPrefix(path, baseDir) {
			return os.ErrPermission
		}
		return nil
	}
	_, err := LoadTrusted("team", root)
	wantPackError(t, err, "untrusted", "")
	if len(checked) != 2 {
		t.Fatalf("checked %v", checked)
	}
}
