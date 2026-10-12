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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func mustRepoPolicy(t *testing.T, doc string) *RepoPolicy {
	t.Helper()
	rp, err := ParseRepoPolicy([]byte(doc), "/p/"+RepoPolicyPath)
	if err != nil {
		t.Fatalf("ParseRepoPolicy: %v", err)
	}
	return rp
}

// A repository policy narrows the run's posture, and only where it is
// stricter: its values are floors and ceilings, not replacements.
func TestRepoPolicyTightens(t *testing.T) {
	for _, tc := range []struct {
		name, pack, doc string
		want            string // wantPosture keys
		tightened       []string
		settings        map[string]string // key -> requested value the repo replaced
	}{
		{"network floor", "open", "version: 1\nnetwork: {mode: allowlist}\n",
			"profile=balanced network=allowlist approvals=triage", []string{"network.mode"},
			map[string]string{"network.mode": "open", "profile": "open"}},
		{"deny and manual", "open", "version: 1\nnetwork: {mode: deny}\napprovals: {mode: manual}\n",
			"profile=strict network=deny approvals=manual", []string{"network.mode"}, nil},
		{"floors already met", "strict", "version: 1\nnetwork: {mode: allowlist}\napprovals: {mode: triage}\nworkspace: {mode: copy}\nhooks: {on_silence: stop}\n",
			"profile=strict approvals=manual mode=copy on_silence=stop", nil, nil},
		{"egress", "open", "version: 1\negress: {block: [files.example.net], ports: [443, 8443], large_upload_mb: 5, block_large_uploads: true}\n",
			"ports=443 block=files.example.net", []string{"egress.block", "egress.ports", "egress.large_upload_mb", "egress.block_large_uploads"},
			map[string]string{"egress.ports": "80, 443", "egress.large_upload_mb": "25", "egress.block_large_uploads": "false"}},
		{"workspace", "open", "version: 1\nworkspace: {mode: copy, masks: [\"config/*.secret\"], review: [scripts/**]}\n",
			"mode=copy", []string{"workspace.mode", "workspace.masks", "workspace.review"}, map[string]string{"workdir.mode": "mount"}},
		{"harness, mcp, hooks", "open", "version: 1\nharness: {yolo: false}\nmcp: {import: false, blocked_tools: [\"fs.*\"]}\nhooks: {on_tamper: stop}\n",
			"yolo=false import=false on_tamper=stop", []string{"harness.yolo", "mcp.import", "mcp.blocked_tools", "hooks.on_tamper"},
			map[string]string{"yolo": "true", "mcp.import": "true", "hooks.on_tamper": "alert"}},
		{"hook silence and process tree", "open", "version: 1\nhooks: {on_silence: stop}\nobserve: {process_tree: true}\n",
			"on_silence=stop process_tree=true", []string{"observe.process_tree", "hooks.on_silence"},
			map[string]string{"observe.process_tree": "false", "hooks.on_silence": "alert"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := mustRepoPolicy(t, tc.doc)
			eff, violations := mustResolve(t, testConfig(nil), Flags{Pack: tc.pack, RepoPolicy: rp})
			wantViolations(t, violations)
			wantPosture(t, eff, tc.want)
			if !reflect.DeepEqual(eff.RepoTightened, tc.tightened) || eff.RepoPolicy != rp {
				t.Fatalf("tightened %v, want %v", eff.RepoTightened, tc.tightened)
			}
			for key, requested := range tc.settings {
				s, _ := eff.Setting(key)
				if s.Source != SourceRepo || s.Origin != RepoPolicyConstraint && !strings.Contains(s.Origin, "profile") || s.Requested != requested {
					t.Fatalf("setting %s = %+v, want source repo, requested %q", key, s, requested)
				}
			}
		})
	}

	// The lists it adds to keep everything else, name it in their
	// provenance, and its block entries refuse an unblock with its name.
	rp := mustRepoPolicy(t, "version: 1\negress: {block: [files.example.net]}\nworkspace: {masks: [\"config/*.secret\"], review: [scripts/**]}\n")
	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Egress.Block = []string{"other.example.org"} }),
		Flags{RepoPolicy: rp})
	if !containsAll(eff.Egress.Block, []string{"other.example.org", "files.example.net"}) ||
		!containsString(eff.Workspace.Masks, ".env") || !containsString(eff.Workspace.Masks, "config/*.secret") ||
		!containsString(eff.Workspace.Review, "scripts/**") || !containsString(eff.Workspace.Review, RepoPolicyPath) {
		t.Fatalf("lists: block %v masks %v review %v", eff.Egress.Block, eff.Workspace.Masks, eff.Workspace.Review)
	}
	wantSetting(t, eff, "egress.block", listValue(eff.Egress.Block), SourceRepo, "pack open + openshell.egress.block + "+RepoPolicyConstraint)
	if dec := eff.DecideEgress("files.example.net", 443); dec.Allowed || dec.Rule != RuleBlock {
		t.Fatalf("decision = %+v", dec)
	}
	var v *Violation
	if err := eff.Allow(Action{Kind: ActionUnblock, Host: "files.example.net"}); !errors.As(err, &v) || v.Constraint != RepoPolicyConstraint {
		t.Fatalf("unblock = %v", err)
	}
	// The administrator's clamps still apply on top.
	eff, _ = mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Admin.MinProfile = "strict" }),
		Flags{RepoPolicy: mustRepoPolicy(t, "version: 1\nnetwork: {mode: allowlist}\n")})
	wantSetting(t, eff, "profile", "strict", SourceAdmin, "openshell.admin.min_profile")
}

// Anything that would loosen the policy refuses the run, one fatal
// violation per key; a valid tightening next to it changes nothing about
// that.
func TestRepoPolicyRefusesLoosening(t *testing.T) {
	for _, tc := range []struct{ doc, key string }{
		{"network: {mode: open}", "network.mode"},
		{"approvals: {mode: auto}", "approvals.mode"},
		{"egress: {allow: [exfil.example.com]}", "egress.allow"},
		{"egress: {large_upload_mb: 0}", "egress.large_upload_mb"},
		{"egress: {block_large_uploads: false}", "egress.block_large_uploads"},
		{"workspace: {mode: mount}", "workspace.mode"},
		{"workspace: {unmask: [.env]}", "workspace.unmask"},
		{"harness: {yolo: true}", "harness.yolo"},
		{"mcp: {import: true}", "mcp.import"},
		{"hooks: {on_tamper: alert}", "hooks.on_tamper"},
		{"hooks: {on_silence: alert}", "hooks.on_silence"},
		{"observe: {process_tree: false}", "observe.process_tree"},
	} {
		rp := mustRepoPolicy(t, "version: 1\n"+tc.doc+"\n")
		_, violations := mustResolve(t, testConfig(nil), Flags{RepoPolicy: rp})
		v := onlyViolation(t, violations)
		if v.Key != tc.key || !v.Fatal || v.Source != SourceRepo || v.Constraint != RepoPolicyConstraint || v.Admin() ||
			!strings.Contains(v.Message, RepoPolicyPath) || !strings.Contains(v.Detail, "can only tighten") {
			t.Fatalf("%s: violation %+v", tc.doc, v)
		}
	}
	rp := mustRepoPolicy(t, "version: 1\nnetwork: {mode: open}\nharness: {yolo: true}\negress: {allow: [a.example.com, b.example.com], block: [c.example.com]}\n")
	_, violations := mustResolve(t, testConfig(nil), Flags{RepoPolicy: rp})
	if len(violations) != 3 || FirstFatal(violations) == nil {
		t.Fatalf("violations = %+v", violations)
	}
	// A list of ports the policy does not open leaves the run no egress.
	_, violations = mustResolve(t, testConfig(nil), Flags{RepoPolicy: mustRepoPolicy(t, "version: 1\negress: {ports: [8443]}\n")})
	if v := onlyViolation(t, violations); v.Key != "egress.ports" || !v.Fatal {
		t.Fatalf("violation %+v", v)
	}
	// Under deny the ports only bound approvals, so none left is fine.
	_, violations = mustResolve(t, testConfig(nil), Flags{Pack: "strict", RepoPolicy: mustRepoPolicy(t, "version: 1\negress: {ports: [8443]}\n")})
	wantViolations(t, violations)
}

// The repository policy is untrusted input: strict, bounded, no links, no
// includes, and nothing it says reaches the terminal unescaped.
// GAP-0245: yaml.v3 names a parser error's line one short (an unclosed
// '[' on line 5 read "line 4"); the error names the line a reader counts.
func TestRepoPolicyNamesTheSyntaxErrorLine(t *testing.T) {
	for doc, want := range map[string]string{
		"version: 1\nnetwork:\n  mode: deny\negress:\n  block: [a.example.com\n": "line 5: did not find expected ',' or ']'",
		"version: 1\nnetwork:\nworkspace: {masks: [x]\n":                         "line 3: did not find expected ',' or '}'",
	} {
		_, err := ParseRepoPolicy([]byte(doc), "repo")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
}

func TestRepoPolicyHostileInput(t *testing.T) {
	for _, tc := range []struct{ name, doc, code string }{
		{"no version", "network: {mode: deny}\n", "missing_field"},
		{"future version", "version: 2\n", "unsupported_version"},
		{"include", "version: 1\ninclude: ../../other.yaml\n", "unknown_field"},
		{"extends", "version: 1\nextends: open\n", "unknown_field"},
		{"a pack key it cannot set", "version: 1\negress: {feeds: []}\n", "unknown_field"},
		{"anchor", "version: 1\negress: {block: &b [a.example.com]}\nworkspace: {masks: *b}\n", "yaml_alias"},
		{"merge key", "version: 1\nnetwork:\n  <<: {mode: deny}\n", "yaml_alias"},
		{"duplicate key", "version: 1\nversion: 1\n", "yaml_duplicate"},
		{"quoted bool", "version: 1\nharness: {yolo: \"false\"}\n", "yaml_type"},
		{"two documents", "version: 1\n---\nversion: 1\n", "yaml_documents"},
		{"block everything", "version: 1\negress: {block: [\"*\"]}\n", "invalid_value"},
		{"mask outside the project", "version: 1\nworkspace: {masks: [../secrets]}\n", "invalid_value"},
		{"no ports", "version: 1\negress: {ports: []}\n", "invalid_value"},
		{"bad port", "version: 1\negress: {ports: [70000]}\n", "invalid_value"},
		{"too large", "version: 1\n# " + strings.Repeat("x", MaxRepoPolicyBytes) + "\n", "too_large"},
		{"escape in a key", "version: 1\n\"\x1b[2Jegress\": {}\n", "yaml_invalid"},
		{"bidi override in a key", "version: 1\n\"\u202eegress\": {}\n", "unknown_field"},
	} {
		_, err := ParseRepoPolicy([]byte(tc.doc), "repo")
		pe := wantPackError(t, err, tc.code, "")
		if !strings.HasPrefix(err.Error(), "repository policy repo") {
			t.Fatalf("%s: %v does not name the repository policy", tc.name, err)
		}
		if strings.ContainsAny(err.Error(), "\x1b\x07\r\u202e") {
			t.Fatalf("%s: the error carries a control character: %q", tc.name, err.Error())
		}
		if tc.code == "unknown_field" && !strings.Contains(pe.Reason, "a repository policy may set") {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}

	project := t.TempDir()
	if rp, err := LoadRepoPolicy(project); rp != nil || err != nil {
		t.Fatalf("no policy: %v %v", rp, err)
	}
	if _, err := LoadRepoPolicy("relative/project"); err == nil {
		t.Fatal("a relative project was read")
	}
	dir := filepath.Join(project, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dir, "sandbox.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRepoPolicy(project)
	wantPackError(t, err, "not_regular", "")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	// Links are refused, the folder and the file alike.
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "sandbox.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, dir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err = LoadRepoPolicy(project)
	wantPackError(t, err, "symlink", "")
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "sandbox.yaml"), filepath.Join(project, RepoPolicyPath)); err != nil {
		t.Fatal(err)
	}
	_, err = LoadRepoPolicy(project)
	wantPackError(t, err, "symlink", "")
	if err := os.Remove(filepath.Join(project, RepoPolicyPath)); err != nil {
		t.Fatal(err)
	}
	doc := "version: 1\nnetwork: {mode: allowlist}\n"
	if err := os.WriteFile(filepath.Join(project, RepoPolicyPath), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	rp, err := LoadRepoPolicy(project)
	if err != nil || rp.NetworkMode != NetworkAllowlist || string(rp.Content) != doc || rp.Source != filepath.Join(project, RepoPolicyPath) ||
		!strings.HasPrefix(rp.Digest, "sha256:") {
		t.Fatalf("LoadRepoPolicy = %+v, %v", rp, err)
	}
}

// A run in a subfolder of a repository does not get the repository policy
// at its root: ParentRepoPolicy finds that file for the warning, never
// above the repository's top (the folder holding .git).
func TestParentRepoPolicy(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	sub, nested := filepath.Join(repo, "svc", "api"), filepath.Join(repo, "vendor", "lib")
	for _, d := range []string{filepath.Join(repo, ".git"), filepath.Join(repo, ".defenseclaw"), sub, filepath.Join(nested, ".git"),
		filepath.Join(root, ".defenseclaw")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(repo, RepoPolicyPath), filepath.Join(root, RepoPolicyPath)} {
		if err := os.WriteFile(f, []byte("version: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for project, want := range map[string]string{
		sub:                          filepath.Join(repo, RepoPolicyPath),
		repo:                         "", // its own, which LoadRepoPolicy reads
		nested:                       "", // another repository (a submodule) without one
		filepath.Join(nested, "src"): "",
		"relative/svc":               "",
	} {
		if got := ParentRepoPolicy(project); got != want {
			t.Errorf("ParentRepoPolicy(%s) = %q, want %q", project, got, want)
		}
	}
}
