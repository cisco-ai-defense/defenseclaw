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

//go:build unix

package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

const remoteProject = "/sandbox/work/myapp"

// copyInActor starts a copy of a fresh project in an actor whose file
// system is a temporary directory.
func copyInActor(t *testing.T) (*operator, sandboxFS, *StartResult) {
	t.Helper()
	if runtimeUnsupported() {
		t.Skip("copy mode is Linux and macOS only")
	}
	o := newOperator(t)
	o.initRepo()
	write(t, o.project, ".env", "API_KEY=do-not-copy-this-value\n", 0o600)
	write(t, o.project, "deploy/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", 0o600)
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	res, err := Start(context.Background(), StartOptions{Transport: sb, Project: o.project, Name: "c1", DataDir: o.data, Home: o.home})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return o, sb, res
}

func runtimeUnsupported() bool {
	_, err := osw.Stage(context.Background(), osw.StageOptions{})
	return errors.Is(err, osw.ErrUnsupportedPlatform)
}

func TestStartCopiesTheProjectAndHoldsSecretsBack(t *testing.T) {
	o, sb, res := copyInActor(t)
	if res.RemoteDir != remoteProject || res.Kind != osw.CopyGit || res.UploadedAt == nil || res.VerifiedAt == nil {
		t.Fatalf("record %+v", res.CopyRecord)
	}
	if got := read(t, sb.local(remoteProject), "src/app.go"); got != "package main\n" {
		t.Fatalf("app.go = %q", got)
	}
	if _, err := os.Stat(sb.local(remoteProject + "/.git/HEAD")); err != nil {
		t.Fatalf("the copy is not a repository: %v", err)
	}
	// The secrets stay on this machine: not as files, not in the history.
	for _, secret := range []string{".env", "deploy/id_rsa"} {
		if b, err := os.ReadFile(filepath.Join(sb.local(remoteProject), secret)); err == nil && strings.Contains(string(b), "do-not-copy") {
			t.Fatalf("%s reached the actor", secret)
		}
	}
	line := res.KeptBackLine()
	if !strings.HasPrefix(line, "kept back: ") || !strings.Contains(line, ".env") || !strings.Contains(line, "id_rsa") || !strings.Contains(line, "(2 files)") {
		t.Fatalf("line = %q", line)
	}
	if _, err := osw.LoadCopy(o.data, "c1"); err != nil {
		t.Fatalf("record not saved: %v", err)
	}
}

func TestStartTakesTheRemoteRootAndNeedsATransport(t *testing.T) {
	o := newOperator(t)
	o.initRepo()
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	res, err := Start(context.Background(), StartOptions{Transport: sb, Project: o.project, Name: "c2", DataDir: o.data, Home: o.home, RemoteRoot: "/sandbox/elsewhere"})
	if err != nil || res.RemoteDir != "/sandbox/elsewhere/myapp" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := Start(context.Background(), StartOptions{Project: o.project, Name: "c3", DataDir: o.data, Home: o.home}); err == nil {
		t.Fatal("no transport accepted")
	}
}

func TestStartRefusesAProjectOverTheLimit(t *testing.T) {
	o := newOperator(t)
	o.initRepo()
	write(t, o.project, "data/big.bin", strings.Repeat("0123456789abcdef", 3<<16), 0o644) // 3 MiB
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	_, err := Start(context.Background(), StartOptions{Transport: sb, Project: o.project, Name: "big", DataDir: o.data, Home: o.home, MaxBytes: 1 << 20})
	var large *TooLargeError
	if !errors.As(err, &large) || !errors.Is(err, osw.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"This folder is ", " MB, over the 1 MB limit.", "--clone REPO_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q lacks %q", err, want)
		}
	}
	if _, err := osw.LoadCopy(o.data, "big"); err == nil {
		t.Fatal("a refused copy left a record")
	}
}

func TestStartReportsAnActorThatCannotBeReached(t *testing.T) {
	o := newOperator(t)
	o.initRepo()
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	a.srv.Close()
	_, err := Start(context.Background(), StartOptions{Transport: sb, Project: o.project, Name: "gone", DataDir: o.data, Home: o.home})
	if err == nil || !strings.HasPrefix(err.Error(), "upload the project to the actor: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestPullReviewListsFlaggedFilesFirstAndApplyLandsThem(t *testing.T) {
	o, sb, _ := copyInActor(t)
	ctx := context.Background()
	agent := sb.local(remoteProject)
	write(t, agent, "README.md", "agent version\n", 0o644)
	write(t, agent, "src/new.go", "package main\n\nfunc New() {}\n", 0o644)
	write(t, agent, ".github/workflows/ci.yml", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n", 0o644)
	write(t, agent, "scripts/run.sh", "#!/bin/sh\necho hi\n", 0o755)
	write(t, agent, ".bashrc", "alias ls=true\n", 0o644)
	write(t, agent, ".env", "API_KEY=agent-made-this\n", 0o600) // held back: not brought back

	rv, err := Pull(ctx, PullOptions{Exec: sb, DataDir: o.data, Name: "c1"})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if rv.Empty || rv.Result == nil || rv.Summary == "" || len(rv.Diff) == 0 || !strings.Contains(string(rv.Diff), "+agent version") {
		t.Fatalf("review %+v", rv)
	}
	byPath := map[string]File{}
	var firstPlain = -1
	for i, f := range rv.Changed {
		byPath[f.Path] = f
		if len(f.Flags) == 0 && firstPlain < 0 {
			firstPlain = i
		}
	}
	for _, p := range []string{".github/workflows/ci.yml", "scripts/run.sh", ".bashrc"} {
		if len(byPath[p].Flags) == 0 {
			t.Errorf("%s not flagged: %+v", p, rv.Changed)
		}
	}
	if ci := strings.Join(byPath[".github/workflows/ci.yml"].Flags, ";"); !strings.Contains(ci, "CI") {
		t.Errorf("ci flags %q", ci)
	}
	if len(byPath["README.md"].Flags) != 0 || len(byPath["src/new.go"].Flags) != 0 {
		t.Errorf("ordinary changes flagged: %+v %+v", byPath["README.md"], byPath["src/new.go"])
	}
	if rv.Flagged < 3 || firstPlain != rv.Flagged {
		t.Errorf("flagged = %d, first plain at %d: %+v", rv.Flagged, firstPlain, rv.Changed)
	}
	if byPath["README.md"].Status != "modified" || byPath["src/new.go"].Status != "added" {
		t.Errorf("statuses %+v %+v", byPath["README.md"], byPath["src/new.go"])
	}
	if _, ok := byPath[".env"]; ok || len(rv.Dropped) == 0 {
		t.Errorf("the held-back .env came back: %+v dropped %v", byPath[".env"], rv.Dropped)
	}
	if !rv.Sensitive || !strings.Contains(rv.Text, "need a look before you bring them back") || !strings.Contains(rv.Text, "Other changes:") {
		t.Errorf("text = %q", rv.Text)
	}

	// A patch runs nothing: no yes needed. Nothing else is touched.
	patch := filepath.Join(o.root, "work.patch")
	ap, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModePatch, PatchPath: patch})
	if err != nil || ap.PatchPath != patch || !strings.Contains(ap.Text, "wrote ") {
		t.Fatalf("patch: %+v %v", ap, err)
	}
	if b, _ := os.ReadFile(patch); !strings.Contains(string(b), "agent version") {
		t.Fatalf("patch = %q", b)
	}
	if read(t, o.project, "README.md") != "hello\n" {
		t.Fatal("a patch changed the project")
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModePatch, PatchPath: patch}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("an existing patch file was overwritten: %v", err)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModePatch}); err == nil {
		t.Fatal("patch mode without a file")
	}

	// A branch leaves the checkout alone; asking again finds it up to date.
	br, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeBranch, Branch: "agent/c1"})
	if err != nil || br.Branch != "agent/c1" || br.UpToDate {
		t.Fatalf("branch: %+v %v", br, err)
	}
	if o.git(o.project, "show", "agent/c1:README.md") != "agent version" || read(t, o.project, "README.md") != "hello\n" {
		t.Fatal("the branch does not hold the work, or the checkout moved")
	}
	if again, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeBranch, Branch: "agent/c1"}); err != nil || !again.UpToDate {
		t.Fatalf("second branch: %+v %v", again, err)
	}

	// Into the working tree, code that can run needs a yes.
	_, err = Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeApply})
	var sens *SensitiveError
	if !errors.As(err, &sens) || !errors.Is(err, osw.ErrSensitiveChanges) || !contains(sens.Files, ".github/workflows/ci.yml") {
		t.Fatalf("apply without a yes: %v", err)
	}
	if read(t, o.project, "README.md") != "hello\n" {
		t.Fatal("a refused apply changed the project")
	}
	ap2, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeApply, AcceptSensitive: true})
	if err != nil || ap2.FellBack || !contains(ap2.Written, "README.md") || !contains(ap2.Written, "src/new.go") || ap2.PreApplyRef == "" {
		t.Fatalf("apply: %+v %v", ap2, err)
	}
	if read(t, o.project, "README.md") != "agent version\n" || read(t, o.project, "src/new.go") == "" {
		t.Fatal("the work is not in the project")
	}
	if got := read(t, o.project, ".env"); got != "API_KEY=do-not-copy-this-value\n" {
		t.Fatalf("the project's own .env was overwritten: %q", got)
	}
	if !strings.Contains(ap2.Text, "applied ") {
		t.Fatalf("text = %q", ap2.Text)
	}
}

func TestPullOfNothingAndApplyOfNothing(t *testing.T) {
	o, sb, _ := copyInActor(t)
	rv, err := Pull(context.Background(), PullOptions{Exec: sb, DataDir: o.data, Name: "c1"})
	if err != nil || !rv.Empty || len(rv.Changed) != 0 || rv.Flagged != 0 || len(rv.Diff) != 0 || !strings.Contains(rv.Text, "nothing to bring back") {
		t.Fatalf("%+v %v", rv, err)
	}
	if _, err := Apply(context.Background(), ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeApply}); !errors.Is(err, osw.ErrNoChanges) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Apply(context.Background(), ApplyOptions{DataDir: o.data, Name: "c1", Mode: "merge"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := Pull(context.Background(), PullOptions{DataDir: o.data, Name: "c1"}); err == nil {
		t.Fatal("pull without a transport")
	}
	if _, err := Pull(context.Background(), PullOptions{Exec: sb, DataDir: o.data, Name: "never-started"}); err == nil {
		t.Fatal("pull of an unknown copy")
	}
}

func TestApplyBranchRefusesAnExistingBranch(t *testing.T) {
	o, sb, _ := copyInActor(t)
	write(t, sb.local(remoteProject), "README.md", "v1\n", 0o644)
	if _, err := Pull(context.Background(), PullOptions{Exec: sb, DataDir: o.data, Name: "c1"}); err != nil {
		t.Fatal(err)
	}
	o.git(o.project, "branch", "taken")
	_, err := Apply(context.Background(), ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeBranch, Branch: "taken"})
	if err == nil || !strings.Contains(err.Error(), "branch taken already exists") {
		t.Fatalf("err = %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// A synthetic pull: the order and the reasons do not depend on a sandbox.
func TestReviewOrderAndReasons(t *testing.T) {
	res := &osw.PullResult{
		Changes: []osw.TreeChange{
			{Path: "a_plain.go", Status: "M", Added: 3, Deleted: 1},
			{Path: "z_big.txt", Status: "A", Added: 4000},
			{Path: "logo.png", Status: "A", Binary: true},
			{Path: "link", Status: "A", NewMode: "120000"},
			{Path: "pkg/.npmrc", Status: "M", Added: 1},
			{Path: "gone.txt", Status: "D", Deleted: 5},
			{Path: "hook.sh", Status: "M", Added: 2},
		},
		Review: osw.ReviewReport{
			FilesChanged: 7, Insertions: 4010, Deletions: 6,
			Flags: []osw.Flag{
				{Path: "hook.sh", Label: "hook.sh", Kind: osw.RiskExecutable, Severity: osw.SeverityHigh, Detail: "executable"},
				{Path: "hook.sh", Label: "hook.sh", Kind: osw.RiskAutoExec, Severity: osw.SeverityCritical},
			},
			Findings: []osw.ScanFinding{{Path: "z_big.txt", Scanner: "clawshield-secrets", Severity: "CRITICAL", Title: "token"}},
		},
	}
	rv := buildReview(res)
	rv.Text = rv.render("c")
	var order []string
	for _, f := range rv.Changed {
		order = append(order, f.Path)
	}
	// Flagged first, most serious first (the auto-exec flag and the secret
	// finding tie, by path), then the lesser flags, then the plain changes.
	if got := strings.Join(order, ","); got != "hook.sh,z_big.txt,link,logo.png,pkg/.npmrc,a_plain.go,gone.txt" {
		t.Fatalf("order %v", order)
	}
	if rv.Flagged != 5 {
		t.Fatalf("flagged %d", rv.Flagged)
	}
	reasons := map[string]string{}
	for _, f := range rv.Changed {
		reasons[f.Path] = strings.Join(f.Flags, "; ")
	}
	for path, want := range map[string]string{
		"z_big.txt":  "contains what looks like a secret",
		"logo.png":   "binary file",
		"link":       "symlink",
		"pkg/.npmrc": "hidden file",
		"hook.sh":    "runs by itself",
	} {
		if !strings.Contains(reasons[path], want) {
			t.Errorf("%s: %q lacks %q", path, reasons[path], want)
		}
	}
	if !strings.Contains(reasons["z_big.txt"], "large change (4000 lines)") {
		t.Errorf("z_big.txt: %q", reasons["z_big.txt"])
	}
	if reasons["a_plain.go"] != "" || reasons["gone.txt"] != "" {
		t.Errorf("plain files flagged: %q %q", reasons["a_plain.go"], reasons["gone.txt"])
	}
	if !strings.Contains(rv.Text, "5 files need a look") {
		t.Errorf("text = %q", rv.Text)
	}
}
