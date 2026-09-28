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

package sandboxcli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// A conflicted `pull --apply` exits 4 and says how to merge (manual test
// L2: status 0 and no hint).
func TestPullApplyConflictExitsWithItsOwnStatus(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("m2-b")
	sb.WorkdirMode, sb.Workdir = "copy", "/sandbox/work/proj"
	ta.daemon.add(sb)
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyMerge, Conflicts: []string{"README.md"}, Branch: "dc/m2-b",
		PatchPath: "/data/sandboxes/m2-b/copy/m2-b.patch"}
	err := ta.Pull(context.Background(), PullOptions{Name: "m2-b", Apply: true})
	wantExit(t, err, ExitPullConflict)
	out := ta.output()
	for _, want := range []string{"the 3-way apply conflicted in README.md; your working tree is unchanged", "the changes are on branch dc/m2-b instead",
		"merge them when you are ready: git merge dc/m2-b"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// A git too old to merge in place falls back the same way.
	ta.out.Reset()
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyMerge, Branch: "dc/m2-b", Warnings: []string{"git 2.34.1 cannot merge without touching the working tree (git 2.38+ can)"}}
	wantExit(t, ta.Pull(context.Background(), PullOptions{Name: "m2-b", Apply: true}), ExitPullConflict)
	if out := ta.output(); strings.Contains(out, "applied 1 change") || !strings.Contains(out, "could not be applied to your working tree") {
		t.Fatalf("output:\n%s", out)
	}
	// A branch or patch that exists says how to go on, without the
	// workspace package's prefix.
	ta.copy.applied, ta.copy.applyErr = nil, errors.New("workspace: branch dc/m2-b already exists")
	err = ta.Pull(context.Background(), PullOptions{Name: "m2-b", Branch: true})
	if err == nil || err.Error() != "bring back m2-b's changes: branch dc/m2-b already exists; pass --branch-name NAME for another branch, or --force to move this one" {
		t.Fatalf("Pull --branch = %v", err)
	}
	ta.copy.applyErr = errors.New("workspace: /tmp/x.patch already exists")
	err = ta.Pull(context.Background(), PullOptions{Name: "m2-b", PatchOut: "/tmp/x.patch"})
	if err == nil || !strings.HasSuffix(err.Error(), "/tmp/x.patch already exists; pass another --patch-out FILE, or --force to overwrite this one") {
		t.Fatalf("Pull --patch-out = %v", err)
	}
}

// The session summary and the review count commits and branch moves, and
// the undo preview lists the HEAD reset and the stop before it asks
// (manual test L3).
func TestCommitsShowInTheSummaryAndTheUndoPreview(t *testing.T) {
	ta := newTestApp(t, "y\n")
	before, after := strings.Repeat("a", 40), strings.Repeat("b", 40)
	ta.daemon.review = sandboxapi.ReviewResponse{Summary: "0 files changed (+0 −0)",
		Report: &workspace.ReviewReport{HeadBefore: before, HeadAfter: after, BranchBefore: "main", BranchAfter: "main"}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	if !strings.Contains(out, "0 files changed (+0 −0) · HEAD moved on main (aaaaaaa → bbbbbbb)") || !strings.Contains(out, "Keep changes?") {
		t.Fatalf("a session that only committed:\n%s", out)
	}
	ta.out.Reset()
	if err := ta.Review(context.Background(), ReviewOptions{Name: "dc-claude-proj-1a2b"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "HEAD moved on main (aaaaaaa → bbbbbbb)") {
		t.Fatalf("review:\n%s", ta.output())
	}

	ta = newTestApp(t, "")
	ta.daemon.add(sampleSandbox("box"))
	ta.daemon.undo = sandboxapi.UndoResponse{Result: &workspace.UndoResult{Project: "/home/u/proj", Preview: true, HeadBefore: before, HeadAfter: after,
		BranchBefore: "main", BranchAfter: "main", RefChanges: []workspace.RefChange{{Ref: "refs/heads/fix", After: after}},
		Changes: []workspace.TreeChange{{Path: "main.go", Status: "M"}}}}
	if err := ta.Undo(context.Background(), UndoOptions{Name: "box", Preview: true}); err != nil {
		t.Fatal(err)
	}
	out = ta.output()
	for _, want := range []string{"revert  main.go", "reset HEAD (main) from bbbbbbb back to aaaaaaa", "restore 1 branch or tag: fix",
		"stop box first (its harness session ends)"} {
		if !strings.Contains(out, want) {
			t.Errorf("undo preview lacks %q:\n%s", want, out)
		}
	}
	if len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/undo")) != 1 {
		t.Fatal("a preview restored something")
	}
}

// One line per action, reasons merged per file, whole pack errors, the
// right plural, the Model line on connect, a URL where a host belongs, the
// setup steps it skipped (manual test L10).
func TestMessagePolish(t *testing.T) {
	t.Run("approve and unblock print one line", func(t *testing.T) {
		ta := newTestApp(t, "")
		ta.daemon.approvals = []sandboxapi.Approval{{ID: "ap-1", Sandbox: "box", Host: "pkg.example", Status: sandboxapi.ApprovalPending}}
		if err := ta.Decide(context.Background(), DecideOptions{Sandbox: "box", ID: "ap-1", Approve: true}); err != nil {
			t.Fatal(err)
		}
		if err := ta.Unblock(context.Background(), UnblockOptions{Host: "webhook.site", Sandbox: "box"}); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(ta.output(), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("output:\n%s", ta.output())
		}
	})
	t.Run("review merges a file's reasons", func(t *testing.T) {
		flags := []workspace.Flag{
			{Path: "Makefile", Label: "Makefile", Severity: workspace.SeverityHigh, Detail: "make runs this"},
			{Path: "package.json", Label: "package.json#scripts.postinstall", Severity: workspace.SeverityHigh, Detail: "runs on npm install"},
			{Path: "Makefile", Label: "Makefile", Severity: workspace.SeverityMedium, Detail: "made executable"},
			{Path: "package.json", Label: "package.json", Severity: workspace.SeverityMedium, Detail: "package.json changed"},
		}
		got := mergeFlags(flags)
		if len(got) != 2 || got[0].name != "Makefile" || strings.Join(got[0].details, "; ") != "make runs this; made executable" ||
			got[1].name != "package.json" || got[1].severity != workspace.SeverityHigh ||
			strings.Join(got[1].details, "; ") != "scripts.postinstall: runs on npm install; package.json changed" {
			t.Fatalf("merged = %+v", got)
		}
		if line := riskLine(&workspace.ReviewReport{Flags: flags}); line != "⚠ Changed files that can run code on your machine: Makefile, package.json  → review before running" {
			t.Fatalf("risk line = %q", line)
		}
	})
	t.Run("list counts one call", func(t *testing.T) {
		sb := sampleSandbox("box")
		sb.Hooks.ToolCalls, sb.Hooks.ToolBlocked = 1, 0
		if got := hooksText(sb); got != "1 call" {
			t.Fatalf("hooksText = %q", got)
		}
	})
	t.Run("connect keeps the Model line", func(t *testing.T) {
		ta := newTestApp(t, "")
		sb := sampleSandbox("box")
		sb.Launch.CredentialProfile = profiles.AnthropicID
		ta.daemon.add(sb)
		if err := ta.Connect(context.Background(), ConnectOptions{Name: "box"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ta.output(), "Model     ANTHROPIC_API_KEY → api.anthropic.com only (the sandbox sees a placeholder)") {
			t.Fatalf("connect banner:\n%s", ta.output())
		}
	})
	t.Run("a credential takes a host", func(t *testing.T) {
		ta := newTestApp(t, "")
		ta.env["STRIPE_API_KEY"] = "x"
		_, err := ta.ParseCredential("STRIPE_API_KEY=https://api.stripe.com")
		if err == nil || !strings.Contains(err.Error(), "name a host, not a URL") {
			t.Fatalf("ParseCredential = %v", err)
		}
	})
	t.Run("the no-terminal hint names a flag that exists", func(t *testing.T) {
		if strings.Contains(ErrNoTerminal.Error(), "--non-interactive") || !strings.Contains(ErrNoTerminal.Error(), "pass --yes") {
			t.Fatalf("ErrNoTerminal = %q", ErrNoTerminal)
		}
	})
}
