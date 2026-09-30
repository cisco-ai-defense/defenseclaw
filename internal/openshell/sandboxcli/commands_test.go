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

package sandboxcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
)

func TestListAndStatus(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("b-box"))
	ta.daemon.add(sampleSandbox("a-box"))
	ta.ok(t, ta.List(bg, OutputText))
	out := ta.output()
	has(t, out, "NAME", "4 calls, 1 blocked", "1h01m")
	if strings.Index(out, "a-box") > strings.Index(out, "b-box") {
		t.Fatalf("list is not sorted:\n%s", out)
	}
	ta.ok(t, ta.fresh().List(bg, OutputJSON))
	var list struct{ Sandboxes []sandboxapi.Sandbox }
	if err := json.Unmarshal(ta.out.Bytes(), &list); err != nil || len(list.Sandboxes) != 2 || list.Sandboxes[0].Name != "a-box" {
		t.Fatalf("list json = %s, %v", ta.out.String(), err)
	}
	ta.out.Reset()
	ta.daemon.status.Admin = sandboxapi.AdminStatus{Configured: true, Authority: "advisory", Detail: "openshell.admin is advisory: you own config.yaml"}
	ta.ok(t, ta.Status(bg, "", OutputText))
	has(t, ta.output(), "Sandboxes       on", "openshell 0.1.1", "Organization    openshell.admin is advisory: you own config.yaml")
	ta.ok(t, ta.fresh().Status(bg, "a-box", OutputText))
	has(t, ta.output(), "skip-permissions on", "managed tier", "9 requests, 4 tool calls, 1 blocked",
		"3 destinations contacted, 1 blocked, 2.0 KiB up, 1.0 MiB down")
	ta.ok(t, ta.fresh().Status(bg, "a-box", OutputJSON))
	var sb sandboxapi.Sandbox
	if err := json.Unmarshal(ta.out.Bytes(), &sb); err != nil || sb.Name != "a-box" {
		t.Fatalf("status json: %v", err)
	}
	if err := ta.Status(bg, "missing", OutputText); err == nil {
		t.Fatal("status of a missing sandbox succeeded")
	}
}

// What the hooks did shows in the list's HOOKS column and in status: the
// right plural, tamper, hooks that do not reach DefenseClaw and hook calls
// that failed closed (manual R2-5, R2-30, L10).
func TestListAndStatusShowTheHooks(t *testing.T) {
	at := time.Date(2026, 9, 28, 4, 57, 1, 0, time.Local)
	for _, c := range []struct {
		name   string
		edit   func(*sandboxapi.HookCoverage)
		list   string
		status []string
	}{
		{"one call", func(h *sandboxapi.HookCoverage) { h.HookRequests, h.ToolCalls, h.ToolBlocked = 5, 1, 0 }, " 1 call ",
			[]string{"Hook traffic  5 requests, 1 tool call, 0 blocked"}},
		{"tamper", func(h *sandboxapi.HookCoverage) { h.Tampered, h.LastTamperAt = 1, at }, "tamper!",
			[]string{"Tamper        1 tool call ran without a DefenseClaw verdict, last 04:57:01"}},
		{"unreachable", func(h *sandboxapi.HookCoverage) {
			h.Unreachable, h.UnreachableSince, h.UnreachableReason, h.IngressRefused = true, at, "OpenShell refused the hooks' connections", 4
		}, "unreachable!", []string{"4 refused by OpenShell", "NOT REACHING DefenseClaw since",
			"⚠ " + hooksWarningText("OpenShell refused the hooks' connections")}},
		{"failed calls", func(h *sandboxapi.HookCoverage) {
			h.HookFailed, h.LastHookFailure, h.LastHookFailureAt = 2, "HTTP 429 Too Many Requests", at
		}, "4 calls, 1 blocked, 2 failed", []string{"Hook traffic  9 requests, 4 tool calls, 1 blocked, 2 failed (fail closed)",
			"Hook error    DefenseClaw answered HTTP 429 Too Many Requests at 04:57:01 (the hook failed closed)"}},
		// The verdicts per hook event, the most frequent first (#956).
		{"events", func(h *sandboxapi.HookCoverage) {
			h.Events = map[string]int64{"Stop": 2, "PostToolUse": 11, "SessionStart": 2, "PreToolUse": 12, "UserPromptSubmit": 3}
			h.OtherEvents = 1
		}, "4 calls, 1 blocked", []string{
			"Hook events   PreToolUse 12 · PostToolUse 11 · UserPromptSubmit 3 · SessionStart 2 · Stop 2 · other events 1\n"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			sb := sampleSandbox("box")
			c.edit(&sb.Hooks)
			ta.daemon.add(sb)
			ta.ok(t, ta.List(bg, OutputText))
			has(t, ta.output(), c.list)
			ta.ok(t, ta.fresh().Status(bg, "box", OutputText))
			has(t, ta.output(), c.status...)
			if sb.Hooks.Events == nil {
				lacks(t, ta.output(), "Hook events")
			}
			ta.ok(t, ta.fresh().Status(bg, "box", OutputJSON))
			var got sandboxapi.Sandbox
			if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil || !maps.Equal(got.Hooks.Events, sb.Hooks.Events) ||
				got.Hooks.OtherEvents != sb.Hooks.OtherEvents {
				t.Fatalf("status json hooks = %+v (%v), want events %v and %d other", got.Hooks, err, sb.Hooks.Events, sb.Hooks.OtherEvents)
			}
		})
	}
}

func TestActivityRendering(t *testing.T) {
	ta := newTestApp(t, "")
	at := time.Date(2026, 9, 27, 12, 1, 2, 0, time.Local)
	ta.daemon.events = []sandboxapi.ActivityEvent{
		{Seq: 1, Time: at, Kind: sandboxapi.ActivityEgressAllowed, Sandbox: "box", Host: "registry.npmjs.org", Port: 443},
		{Seq: 2, Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: "box", Host: "webhook.site", Category: "exfil destination", Unblockable: true},
		{Seq: 3, Time: at, Kind: sandboxapi.ActivityToolBlocked, Sandbox: "box", Tool: "Bash", Reason: "E2E marker"},
		{Seq: 4, Time: at, Kind: sandboxapi.ActivityApprovalRequested, Sandbox: "box", ApprovalID: "ap-1", Host: "10.0.0.5", Port: 5432},
		{Seq: 5, Time: at, Kind: sandboxapi.ActivityFinding, Sandbox: "box", Reason: sandboxapi.ReasonNestedRepo, Message: "⚠ quarantined a new git repository at x/.git"},
		{Seq: 6, Time: at, Kind: sandboxapi.ActivityFinding, Sandbox: "box", Reason: sandboxapi.ReasonHooksUnreachable,
			Message: "⚠ " + hooksWarningText("OpenShell refused the hooks' connections")},
		{Seq: 7, Time: at, Kind: sandboxapi.ActivityFinding, Sandbox: "box", Reason: sandboxapi.ReasonHooksRestored, Message: "DefenseClaw hooks reach the daemon again"},
		{Seq: 8, Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: "box", Host: "evil.example.net", Source: sandboxapi.SourceOpenShell,
			Reason: "transparent_tcp_policy_denied", Replayed: true},
		{Seq: 9, Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: "box", Host: "example.org", Category: "not_allowlisted", Reason: "some_new_token"},
		// The daemon's reason does not name the destination: the line does.
		{Seq: 10, Time: at, Kind: sandboxapi.ActivityApprovalRequested, Sandbox: "box", ApprovalID: "ap-2", Host: "api.example.com", Port: 443,
			Message: "approvals are manual for the strict profile"},
		{Seq: 11, Time: at, Kind: sandboxapi.ActivityHookFailed, Sandbox: "box", Reason: "HTTP 429 Too Many Requests",
			Message: "✗ 3 hook calls failed (last: HTTP 429 Too Many Requests), so the harness's actions were blocked (hooks fail closed)"},
		{Seq: 12, Time: at, Kind: sandboxapi.ActivityHookFailed, Sandbox: "box", Reason: "HTTP 403 Forbidden"},
		// The large-upload block names the threshold the upload crossed.
		{Seq: 13, Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: "box", Host: "files.example.net", Category: sandboxapi.CategoryLargeUpload,
			Reason: "This sandbox tried to send more than 10 MiB to a destination it had not contacted before.", Unblockable: true},
		{Seq: 14, Time: at, Kind: sandboxapi.ActivityEgressLargeUpload, Sandbox: "box", Host: "drop.example.net", BytesUp: 30 << 20},
	}
	ta.ok(t, ta.Activity(bg, ActivityOptions{Sandbox: "box"}))
	lines := strings.Split(strings.TrimSpace(ta.output()), "\n")
	want := []string{
		"12:01:02 ✓ registry.npmjs.org",
		"12:01:02 ✗ webhook.site (exfil destination)  → unblock: defenseclaw sandbox unblock webhook.site --sandbox box",
		"12:01:02 ✗ tool Bash blocked: E2E marker",
		"12:01:02 ? ask ap-1: 10.0.0.5:5432  → defenseclaw sandbox approve box ap-1",
		"12:01:02 ⚠ quarantined a new git repository at x/.git",
		"12:01:02 ✗ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked (OpenShell refused the hooks' connections). Run: defenseclaw sandbox doctor",
		"12:01:02 ✓ DefenseClaw hooks reach the daemon again",
		"12:01:02 ✗ evil.example.net (no OpenShell rule allows it) (while DefenseClaw was down)",
		"12:01:02 ✗ example.org (not on the allowlist)",
		"12:01:02 ? ask ap-2: api.example.com:443 (approvals are manual for the strict profile)  → defenseclaw sandbox approve box ap-2",
		"12:01:02 ✗ 3 hook calls failed (last: HTTP 429 Too Many Requests), so the harness's actions were blocked (hooks fail closed)",
		"12:01:02 ✗ a hook call failed (HTTP 403 Forbidden), so the harness's action was blocked",
		"12:01:02 ✗ files.example.net (large upload blocked: this sandbox tried to send more than 10 MiB to a destination it had not contacted before)" +
			"  → unblock: defenseclaw sandbox unblock files.example.net --sandbox box",
		"12:01:02 ⚠ large upload to drop.example.net (30.0 MiB)",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("activity =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	ta.ok(t, ta.fresh().Activity(bg, ActivityOptions{Output: OutputJSON}))
	var got struct{ Events []sandboxapi.ActivityEvent }
	if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil || len(got.Events) != len(want) {
		t.Fatalf("activity json: %v %s", err, ta.output())
	}
	// The whole feed, followed, names each line's sandbox.
	ta.ok(t, ta.fresh().Activity(bg, ActivityOptions{Follow: true}))
	if n := strings.Count(ta.output(), "\n"); n != len(want) {
		t.Fatalf("followed %d events:\n%s", n, ta.output())
	}
	has(t, ta.output(), "12:01:02 box ? ask ap-2: api.example.com:443 (approvals are manual for the strict profile)  → defenseclaw sandbox approve box ap-2")
}

func TestApprovalsAndDecisions(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.approvals = []sandboxapi.Approval{{ID: "ap-1", Sandbox: "box", Kind: "host_port", Host: "127.0.0.1", Port: 5432, Risky: true,
		Reason: "a door into your machine", Status: sandboxapi.ApprovalPending}}
	ta.ok(t, ta.Approvals(bg, ApprovalsOptions{}))
	has(t, ta.output(), "ap-1", "127.0.0.1:5432", "risky")
	// An ask for several ports shows every one approving opens.
	ta.out.Reset()
	ta.daemon.approvals[0].Endpoints = []sandboxapi.ApprovalEndpoint{{Host: "127.0.0.1", Port: 5432}, {Host: "127.0.0.1", Port: 6379}}
	ta.ok(t, ta.Approvals(bg, ApprovalsOptions{}))
	has(t, ta.output(), "127.0.0.1:5432,6379")
	ta.ok(t, ta.fresh().Approvals(bg, ApprovalsOptions{Output: OutputJSON}))
	var list struct{ Approvals []sandboxapi.Approval }
	if err := json.Unmarshal(ta.out.Bytes(), &list); err != nil || len(list.Approvals) != 1 {
		t.Fatalf("approvals json: %v", err)
	}
	wantErr(t, ta.Decide(bg, DecideOptions{Sandbox: "other", ID: "ap-1", Approve: true}), "has no pending ask")
	ta.ok(t, ta.fresh().Decide(bg, DecideOptions{Sandbox: "box", ID: "ap-1", Approve: true, Always: true}))
	calls := ta.daemon.callsTo("POST", sandboxapi.PathApprovals+"/ap-1")
	if len(calls) != 1 || !strings.Contains(string(calls[0].Body), `"decision":"approve"`) || !strings.Contains(string(calls[0].Body), `"always":true`) {
		t.Fatalf("decide calls = %+v", calls)
	}
	// One line per decision (manual test L10).
	has(t, ta.output(), "approved ap-1", "next quiet moment", "kept for future sandboxes")
	if n := strings.Count(ta.output(), "\n"); n != 1 {
		t.Fatalf("decide printed %d lines:\n%s", n, ta.output())
	}
	ta.ok(t, ta.Decide(bg, DecideOptions{Sandbox: "box", ID: "ap-1"}))
	if calls := ta.daemon.callsTo("POST", sandboxapi.PathApprovals+"/ap-1"); !strings.Contains(string(calls[1].Body), `"decision":"reject"`) {
		t.Fatalf("reject body = %s", calls[1].Body)
	}
}

func TestUnblock(t *testing.T) {
	ta := newTestApp(t, "")
	if err := ta.Unblock(bg, UnblockOptions{Host: "webhook.site"}); err == nil {
		t.Fatal("an unscoped unblock was accepted")
	}
	if err := ta.Unblock(bg, UnblockOptions{Host: "webhook.site", Sandbox: "box", Always: true}); err == nil {
		t.Fatal("--sandbox with --always was accepted")
	}
	ta.ok(t, ta.Unblock(bg, UnblockOptions{Host: "webhook.site", Sandbox: "box"}))
	ta.ok(t, ta.Unblock(bg, UnblockOptions{Host: "paste.example", Always: true}))
	has(t, ta.output(), "unblocked webhook.site in box", "unblocked paste.example for every sandbox")
	if n := strings.Count(ta.output(), "\n"); n != 2 {
		t.Fatalf("output (one line each):\n%s", ta.output())
	}
	ta.daemon.errors["POST "+sandboxapi.PathEgressUnblock] = &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "egress.unblock", Admin: true}}
	err := ta.Unblock(bg, UnblockOptions{Host: "x.example", Sandbox: "box"})
	if err == nil || err.Error() != "blocked by your organization's DefenseClaw policy: egress.unblock" {
		t.Fatalf("admin unblock = %v", err)
	}
}

// Undo previews, asks and restores; it names what it cannot restore (and
// the bytecode cache it removes), the commits and branch moves it resets,
// and with -o json stdout holds one document while the preview, the prompt
// and the progress go to stderr.
func TestUndo(t *testing.T) {
	deps := workspace.IgnoredChange{Path: "node_modules/", Modified: 1, Executables: []string{"node_modules/.bin/tool"}, ExecutableCount: 1,
		Dependencies: true, Remedy: "delete it and reinstall the packages (for example `npm ci`)"}
	cache := workspace.IgnoredChange{Path: "calc/__pycache__/", Added: 1, Modified: 1, Removed: true, Remedy: "delete it; Python rebuilds it"}
	restoredDeps, overCap, vendor := deps, deps, deps
	restoredDeps.Restored, overCap.OverCap, vendor.Path = true, true, "vendor/"
	undoIgnoredOn := func(ta *testApp) {
		ta.Cfg.OpenShell.Workdir.UndoIgnored = config.OpenShellUndoIgnoredConfig{Enabled: true, MaxMB: 64}
	}
	readme := []workspace.TreeChange{{Path: "README.md", Status: "M"}}
	before, after := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for _, c := range []struct {
		name, input string
		opts        UndoOptions
		undo        *workspace.UndoResult
		undos       int
		stopped     bool // -o json: stdout is the restore's response
		setup       func(*testApp)
		want, not   []string
	}{
		{name: "restore", input: "y\n", undos: 2, want: []string{"revert  README.md", "restored: 1 file restored"}},
		{name: "only what undo cannot restore", undo: &workspace.UndoResult{Preview: true, Ignored: []workspace.IgnoredChange{deps}}, undos: 1,
			want: []string{"undo cannot restore node_modules/ (1 file added or changed during the session, including .bin/tool): " +
				"delete it and reinstall the packages (for example `npm ci`)", "nothing else to undo"},
			not: []string{"✓ nothing to undo"}},
		{name: "a bytecode cache is removed", input: "y\n", undo: &workspace.UndoResult{Changes: readme, Ignored: []workspace.IgnoredChange{cache, deps}},
			undos: 2, want: []string{"remove  2 files the session wrote to calc/__pycache__/ (a Python bytecode cache)",
				"undo cannot restore node_modules/", "restored: 1 file restored, except node_modules/ (see above)"},
			not: []string{"undo cannot restore calc/__pycache__/"}},
		// Off, a dependency directory undo cannot restore names the key that
		// makes the next undo point keep a copy of it (#944).
		{name: "the key that keeps a copy", undo: &workspace.UndoResult{Preview: true, Ignored: []workspace.IgnoredChange{deps}}, undos: 1,
			want: []string{"openshell.workdir.undo_ignored.enabled: true in ", "config.yaml makes each undo point keep a copy of " +
				"node_modules, .venv, venv (up to 500 MB), so undo restores them; it applies from the next session's start"}},
		{name: "a directory the key does not name", setup: undoIgnoredOn,
			undo: &workspace.UndoResult{Preview: true, Ignored: []workspace.IgnoredChange{vendor}}, undos: 1,
			want: []string{"add vendor to openshell.workdir.undo_ignored.dirs in "}, not: []string{"undo_ignored.enabled: true"}},
		{name: "a kept copy is restored", input: "y\n", undo: &workspace.UndoResult{Changes: readme, Ignored: []workspace.IgnoredChange{restoredDeps}},
			undos: 2, want: []string{"restore node_modules/ from the copy the undo point keeps (1 file added or changed during the session)",
				"restored: 1 file restored (node_modules/ too, from the copy the undo point keeps)"},
			not: []string{"undo cannot restore", "undo_ignored"}},
		{name: "a copy past the cap", setup: undoIgnoredOn, undo: &workspace.UndoResult{Preview: true, Ignored: []workspace.IgnoredChange{overCap}}, undos: 1,
			want: []string{"undo cannot restore node_modules/ (1 file added or changed during the session, including .bin/tool): " +
				"delete it and reinstall the packages (for example `npm ci`) (its copy would pass openshell.workdir.undo_ignored.max_mb, 64 MB)"},
			not: []string{"makes each undo point keep a copy"}},
		{name: "commits", opts: UndoOptions{Preview: true}, undos: 1,
			undo: &workspace.UndoResult{Preview: true, HeadBefore: before, HeadAfter: after, BranchBefore: "main", BranchAfter: "main",
				RefChanges: []workspace.RefChange{{Ref: "refs/heads/fix", After: after}}, Changes: []workspace.TreeChange{{Path: "main.go", Status: "M"}}},
			want: []string{"revert  main.go", "reset HEAD (main) from bbbbbbb back to aaaaaaa", "restore 1 branch or tag: fix",
				"stop box first (its harness session ends)"}},
		{name: "json restore", input: "y\n", opts: UndoOptions{Output: OutputJSON}, undos: 2, stopped: true,
			want: []string{"revert  README.md", "stop box first (its harness session ends)", "Stop box and restore "}},
		{name: "json declined", input: "n\n", opts: UndoOptions{Output: OutputJSON}, undos: 1, want: []string{"revert  README.md", "nothing changed"}},
		{name: "json nothing to undo", opts: UndoOptions{Output: OutputJSON}, undo: &workspace.UndoResult{Preview: true}, undos: 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, c.input)
			ta.daemon.add(sampleSandbox("box"))
			if c.setup != nil {
				c.setup(ta)
			}
			if c.undo != nil {
				r := *c.undo
				r.Project = ta.project
				ta.daemon.undo = sandboxapi.UndoResponse{Result: &r}
			}
			o := c.opts
			o.Name = "box"
			ta.ok(t, ta.Undo(bg, o))
			b := ta.bodies("POST", "box/undo")
			if len(b) != c.undos || !strings.Contains(b[0], `"preview":true`) || (c.undos == 2 && !strings.Contains(b[1], `"stop":true`)) {
				t.Fatalf("undo calls = %q, want %d", b, c.undos)
			}
			out := ta.output()
			if o.Output == OutputJSON {
				var res sandboxapi.UndoResponse
				if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Result == nil || res.Stopped != c.stopped {
					t.Fatalf("stdout is not one undo response (%v):\n%s", err, out)
				}
				if ta.IO.Out != io.Writer(ta.out) {
					t.Fatal("stdout was not restored after the command")
				}
				out = ta.err.String()
			}
			has(t, out, c.want...)
			lacks(t, out, c.not...)
		})
	}
	// No terminal and no --yes: the preview is shown, nothing restored, and
	// the hint names a flag that exists.
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.daemon.add(sampleSandbox("box"))
	err := ta.Undo(bg, UndoOptions{Name: "box"})
	if !errors.Is(err, ErrNoTerminal) || !strings.Contains(err.Error(), "pass --yes") || strings.Contains(err.Error(), "--non-interactive") {
		t.Fatalf("undo without a terminal = %v", err)
	}
	ta.wantCalls(t, 1, "POST", "box/undo")
}

func TestReviewAndDelete(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("box"))
	ta.daemon.review = sandboxapi.ReviewResponse{Summary: "8 files changed (+212 −37)",
		RiskLine: "⚠ Changed files that can run code on your machine: package.json#scripts.postinstall  → review before running",
		Report: &workspace.ReviewReport{FilesChanged: 8, HeadBefore: strings.Repeat("a", 40), HeadAfter: strings.Repeat("b", 40),
			BranchBefore: "main", BranchAfter: "main",
			Flags: []workspace.Flag{{Path: "package.json", Label: "package.json#scripts.postinstall", Severity: workspace.SeverityHigh, Detail: "runs on npm install"}},
			Findings: []workspace.ScanFinding{{Path: "config/dev.env", Scanner: "clawshield-secrets", RuleID: "aws-key",
				Severity: "critical", Title: "AWS access key", Location: "config/dev.env:3"}}}}
	ta.ok(t, ta.Review(bg, ReviewOptions{Name: "box", Diff: true}))
	has(t, ta.output(), "box: 8 files changed (+212 −37)", "HIGH     package.json — scripts.postinstall: runs on npm install", "+changed",
		"  CRITICAL config/dev.env:3 — clawshield-secrets: AWS access key", "HEAD moved on main (aaaaaaa → bbbbbbb)")
	lacks(t, ta.output(), "{Path:")
	ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}, Yes: true, KeepSnapshot: true}))
	if b := ta.bodies("DELETE", "box"); len(b) != 1 || !strings.Contains(b[0], `"keep_snapshot":true`) {
		t.Fatalf("delete calls = %q", b)
	}
}

// `review` of a copy-mode sandbox (every sandbox on the MicroVM driver)
// previews what `pull` would bring back and applies nothing, naming the
// pull that does; the daemon's review, of mounted projects only, is not
// asked. With -o json stdout holds the pull's result.
func TestReviewPreviewsACopysPull(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.ok(t, ta.Review(bg, ReviewOptions{Name: "copybox", Diff: true}))
	has(t, ta.output(), "starting copybox to read its work", "copybox: 1 file changed (+4 −1)", "  M main.go",
		"--diff: the changes of a copy come back as a patch; `defenseclaw sandbox pull copybox --patch-out FILE` writes one",
		"nothing was applied; bring it back with `defenseclaw sandbox pull copybox --apply` (or --branch or --patch-out FILE)", "stopped copybox again")
	if !slices.Equal(ta.copy.steps, []string{"pull copybox"}) || ta.calls("POST", "copybox/review") != 0 {
		t.Fatalf("copy steps %v, daemon reviews %d; want a pull and nothing applied", ta.copy.steps, ta.calls("POST", "copybox/review"))
	}
	if r := ta.bodies("POST", "copybox/workspace"); len(r) != 0 {
		t.Fatalf("a preview reported %q", r)
	}
	// A plain folder has no branch.
	ta = newTestApp(t, "", copySandbox("plainbox"))
	ta.copy.pull = &workspace.PullResult{Name: "plainbox", Kind: workspace.CopyPlain,
		Changes: []workspace.TreeChange{{Path: "notes.md", Status: "M", Added: 1}}, Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 1}}
	ta.ok(t, ta.Review(bg, ReviewOptions{Name: "plainbox"}))
	has(t, ta.output(), "bring it back with `defenseclaw sandbox pull plainbox --apply` (or --patch-out FILE)")
	lacks(t, ta.output(), "--branch", "--diff")
	// -o json: one document, the pull's.
	ta = newTestApp(t, "", copySandbox("copybox"))
	ta.ok(t, ta.Review(bg, ReviewOptions{Name: "copybox", Diff: true, Output: OutputJSON}))
	var res workspace.PullResult
	if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Name != "copybox" || len(res.Changes) != 1 {
		t.Fatalf("stdout is not the pull's result (%v):\n%s", err, ta.out.String())
	}
	if len(ta.copy.apply) != 0 {
		t.Fatalf("a review applied %+v", ta.copy.apply)
	}
}

// The review merges each file's reasons into one line (manual test L10).
func TestReviewMergesAFilesReasons(t *testing.T) {
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
}

// Deleting a copy-mode sandbox discards the work it holds that was never
// pulled back: `delete` says so and defaults to no, --yes says it did, and
// teardown names it before it asks.
func TestDeleteNamesUnpulledCopyWork(t *testing.T) {
	ta := newTestApp(t, "\n")
	sb := copySandbox("fix-tests")
	sb.Phase = "ready"
	ta.daemon.add(sb)
	ta.copy.pending = map[string]workspace.CopyWork{"fix-tests": workspace.CopyWorkUnpulled}
	ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"fix-tests"}}))
	has(t, ta.output(), "Sandbox fix-tests holds work that was never pulled back; `defenseclaw sandbox pull fix-tests --apply|--branch|--patch-out FILE` "+
		"brings it back. Delete it and discard that work? [y/N]")
	if ta.calls("DELETE", "fix-tests") != 0 {
		t.Fatal("the default deleted the work")
	}
	// A stopped sandbox is judged by its last pull; --yes deletes and says so.
	ta = newTestApp(t, "", copySandbox("docs"))
	ta.copy.pendingStopped = map[string]workspace.CopyWork{"docs": workspace.CopyWorkUnapplied}
	ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"docs"}, Yes: true}))
	has(t, ta.output(), "sandbox docs holds a pull that was never applied", "deleting it discards that work (--yes)")
	ta.wantCalls(t, 1, "DELETE", "docs")
	// A mount-mode sandbox has nothing of the kind.
	ta = newTestApp(t, "y\n", sampleSandbox("live"))
	ta.copy.pending = map[string]workspace.CopyWork{"live": workspace.CopyWorkUnpulled}
	ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"live"}}))
	lacks(t, ta.output(), "never pulled")
	// Its undo point goes with it unless kept; a copy has none to name.
	has(t, ta.output(), "Delete sandbox live (its providers, credentials and, unless --keep-snapshot, its undo point)? [y/N]")
	// Teardown lists it in its plan (a dry run changes nothing).
	ta = newTestApp(t, "", copySandbox("fix-tests"))
	ta.copy.pendingStopped = map[string]workspace.CopyWork{"fix-tests": workspace.CopyWorkUnknown}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{DryRun: true}))
	has(t, ta.output(), "sandbox fix-tests may hold work that was never pulled back (it is not running, so it was not checked)", "teardown deletes it")
}

// TestExecStopsItsCommandWhenTheClientEnds pins that a `sandbox exec`
// client that is ended stops its command in the sandbox, which OpenShell
// leaves running: the command carries a session mark, and the reaper
// targets exactly that session.
func TestExecStopsItsCommandWhenTheClientEnds(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("box"))
	ta.IO.TTY = false
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	ta.stream.answer = func(argv []string) (int, string) {
		if _, cmd := execSession(sandboxCommand(argv)); len(cmd) > 0 && cmd[0] == "sleep" {
			cancel() // the client is told to end while the command runs
			return -1, ""
		}
		return 0, ""
	}
	if err := ta.Exec(ctx, ExecOptions{Name: "box", Command: []string{"sleep", "600"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("exec = %v, want the cancellation", err)
	}
	if len(ta.stream.runs) != 2 {
		t.Fatalf("runs = %q, want the command and the reaper", ta.stream.runs)
	}
	session, cmd := execSession(sandboxCommand(ta.stream.runs[0]))
	if len(session) != 32 || !slices.Equal(cmd, []string{"sleep", "600"}) {
		t.Fatalf("the command runs under no session shell: %q", ta.stream.runs[0])
	}
	if reap := sandboxCommand(ta.stream.runs[1]); len(reap) != 5 || reap[0] != "/bin/sh" || reap[2] != reapScript || reap[4] != session {
		t.Fatalf("reaper = %q, want session %s", reap, session)
	}
	// A command that ends on its own is not reaped.
	ta.stream.runs = nil
	ta.ok(t, ta.Exec(bg, ExecOptions{Name: "box", Command: []string{"true"}}))
	if len(ta.stream.runs) != 1 {
		t.Fatalf("runs = %q, want the command only", ta.stream.runs)
	}
}

// TestReapScriptStopsTheSession runs the reaper on this machine (Linux,
// where /proc lists processes): it stops the session shell of its session
// and every process below it, and leaves another session's alone. The
// session shell exits with its command's status.
func TestReapScriptStopsTheSession(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc on this platform")
	}
	mine, other := strings.Repeat("a", 32), strings.Repeat("b", 32)
	dir := t.TempDir()
	start := func(session string) *exec.Cmd {
		// The command's own child writes its pid, to be found again.
		argv := execSessionArgv(session, []string{"/bin/sh", "-c", `sleep 600 & echo $! >"$0"; wait`, filepath.Join(dir, session)})
		cmd := exec.Command(argv[0], argv[1:]...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		return cmd
	}
	child := func(session string) int {
		t.Helper()
		for i := 0; i < 50; i++ {
			if data, err := os.ReadFile(filepath.Join(dir, session)); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
					return pid
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("session %s's command never started its child", session)
		return 0
	}
	target, bystander := start(mine), start(other)
	mineChild, otherChild := child(mine), child(other)
	t.Cleanup(func() {
		for _, pid := range []int{mineChild, otherChild} {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	})
	if out, err := exec.Command("/bin/sh", "-c", reapScript, "defenseclaw-reap", mine).CombinedOutput(); err != nil {
		t.Fatalf("reaper: %v\n%s", err, out)
	}
	done := make(chan error, 1)
	go func() { done <- target.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the session's process is still running")
	}
	// Its command's child went with it (gone from /proc, or a zombie its
	// new parent has not reaped yet).
	gone := false
	for i := 0; i < 100 && !gone; i++ {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", mineChild))
		gone = os.IsNotExist(err) || strings.Contains(string(status), "State:\tZ")
		time.Sleep(50 * time.Millisecond)
	}
	if !gone {
		t.Fatal("the session's command's child is still running")
	}
	if err := bystander.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("another session's process was stopped: %v", err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", otherChild)); err != nil {
		t.Fatalf("another session's child was stopped: %v", err)
	}
	status := exec.Command(execSessionArgv(mine, []string{"/bin/sh", "-c", "exit 7"})[0], execSessionArgv(mine, []string{"/bin/sh", "-c", "exit 7"})[1:]...)
	var exit *exec.ExitError
	if err := status.Run(); !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("the session shell's status = %v, want 7", err)
	}
	if out, err := exec.Command("/bin/sh", "-c", reapScript, "defenseclaw-reap", "not-hex").CombinedOutput(); err == nil {
		t.Fatalf("a malformed session id was accepted:\n%s", out)
	}
}

func TestExecAndLogs(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("box"))
	ta.IO.TTY = false
	ta.stream.answer = func(argv []string) (int, string) {
		_, cmd := execSession(sandboxCommand(argv))
		switch {
		case len(cmd) > 2 && cmd[2] == runTailScript:
			return 0, "log line\n"
		case len(cmd) > 2 && cmd[2] == runFollowScript:
			return 0, "log line\nmore\n"
		case isRunStatus(cmd):
			// The run started a minute ago; the sandbox's last hook is now.
			return 0, fmt.Sprintf("run_started=%d\nrun=exited\nrun_exit=0\n", time.Now().Add(-time.Minute).Unix())
		case cmd[0] == "false":
			return 7, ""
		}
		return 0, ""
	}
	ta.ok(t, ta.Exec(bg, ExecOptions{Name: "box", Command: []string{"ls", "-la"}}))
	wantExit(t, ta.Exec(bg, ExecOptions{Name: "box", Command: []string{"false"}}), 7)
	ta.ok(t, ta.Logs(bg, LogsOptions{Name: "box", Lines: 50}))
	cmds := ta.stream.commands()
	// `sandbox exec` runs the command through sandbox-env, under its
	// session shell.
	wrapped := slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
		cmd := sandboxCommand(argv)
		session, rest := execSession(cmd)
		return session != "" && len(cmd) > 4 && cmd[4] == harness.SandboxEnvPath && slices.Equal(rest, []string{"ls", "-la"})
	})
	if !wrapped || slices.Contains(cmds, "ls -la") || !slices.Contains(cmds, "sh -c "+runTailScript+" sh "+RunDir+" 50") ||
		!slices.ContainsFunc(ta.stream.runs, func(argv []string) bool { return isRunStatus(sandboxCommand(argv)) }) {
		t.Fatalf("commands = %q", cmds)
	}
	has(t, ta.output(), "log line", "exited with status 0")
	lacks(t, ta.output(), "not reaching")
	// -f follows the log until the run ends, then reports how it ended.
	ta.ok(t, ta.fresh().Logs(bg, LogsOptions{Name: "box", Follow: true}))
	runs := ta.stream.runs
	follow, status := sandboxCommand(runs[len(runs)-2]), sandboxCommand(runs[len(runs)-1])
	if len(follow) != 6 || follow[2] != runFollowScript || follow[4] != RunDir || follow[5] != "200" || !isRunStatus(status) {
		t.Fatalf("follow = %q, then %q", follow, status)
	}
	has(t, ta.output(), "more", "exited with status 0")
}

// TestLogsWithoutARunLog: a sandbox without a run log gets DefenseClaw's
// answer, and a log that could not be read is not taken for a missing run.
func TestLogsWithoutARunLog(t *testing.T) {
	for _, c := range []struct {
		follow bool
		code   int
		want   string
	}{
		{false, runNoLog, "box has no detached run output (start one with"},
		{true, runNoLog, "box has no detached run output (start one with"},
		{false, 255, "could not read the run log of box (exit status 255)"},
		{true, 1, "could not read the run log of box (exit status 1)"},
	} {
		t.Run(fmt.Sprintf("exit %d follow=%t", c.code, c.follow), func(t *testing.T) {
			ta := newTestApp(t, "", sampleSandbox("box"))
			ta.IO.TTY = false
			ta.stream.answer = func(argv []string) (int, string) {
				if cmd := sandboxCommand(argv); len(cmd) > 2 && (cmd[2] == runTailScript || cmd[2] == runFollowScript) {
					return c.code, ""
				}
				return 0, ""
			}
			wantErr(t, ta.Logs(bg, LogsOptions{Name: "box", Follow: c.follow}), c.want)
		})
	}
}

// A run's log is the agent's to write: on a terminal nothing in it drives
// the terminal (a title sequence, the stand-in here for any escape the
// agent could send, prints as U+FFFD), while color codes pass; a file or a
// pipe gets the log as it is.
func TestLogsCannotDriveTheTerminal(t *testing.T) {
	const title, red = "\x1b]0;DCMARK\x07", "\x1b[31mred\x1b[0m"
	for _, c := range []struct{ harness, log string }{
		// Claude Code's stream-json carries the escapes JSON-encoded; the
		// renderer decodes them.
		{"claudecode", `{"type":"assistant","message":{"content":[{"type":"text","text":"\u001b]0;DCMARK\u0007 \u001b[31mred\u001b[0m"}]}}` + "\n"},
		{"codex", title + " " + red + "\n"},
	} {
		for _, tty := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s tty=%t", c.harness, tty), func(t *testing.T) {
				ta := newTestApp(t, "")
				ta.IO.OutTTY = tty
				sb := sampleSandbox("box")
				sb.Harness = c.harness
				ta.daemon.add(sb)
				ta.stream.answer = func(argv []string) (int, string) {
					if isRunStatus(sandboxCommand(argv)) {
						return 0, "run=running\n"
					}
					return 0, c.log
				}
				ta.ok(t, ta.Logs(bg, LogsOptions{Name: "box"}))
				out := ta.out.String()
				switch {
				case !tty && !strings.Contains(out, title+" "+red):
					t.Fatalf("a log that is not on a terminal changed:\n%q", out)
				case tty && (strings.Contains(out, "\x1b]") || strings.Contains(out, "\x07")):
					t.Fatalf("an escape sequence reached the terminal:\n%q", out)
				case tty && (!strings.Contains(out, "�]0;DCMARK�") || !strings.Contains(out, red)):
					t.Fatalf("the log on a terminal lost its text or its colors:\n%q", out)
				}
			})
		}
	}
}

// What the agent writes (sandboxText) and what it names in DefenseClaw's
// own lines (terminalText) keep their colors but cannot drive the
// terminal: no escape sequences, carriage returns or direction overrides.
func TestTerminalSafeText(t *testing.T) {
	for _, c := range []struct {
		fn       func(string) string
		in, want string
	}{
		{sandboxText, "plain\ttext\n", "plain\ttext\n"},
		{sandboxText, "\x1b[1;31mbold red\x1b[0m", "\x1b[1;31mbold red\x1b[0m"},
		{sandboxText, "\x1b]52;c;DCMARK\x07", "�]52;c;DCMARK�"},
		{sandboxText, "\x1b[2J\x1b[H", "�[2J�[H"},
		{sandboxText, "over\rwrite", "over write"},
		{sandboxText, "\u202eevil", "�evil"},
		{sandboxText, "caf\xc3", "caf�"},
		{terminalText, ansiYellow + "⚠ risk" + ansiReset + " → x", ansiYellow + "⚠ risk" + ansiReset + " → x"},
		{terminalText, "a\x1b[2Jb", "a�[2Jb"},
		{terminalText, "a\x1b]0;title\x07b", "a�]0;title�b"},
		{terminalText, "line\roverwrite", "line overwrite"},
		{terminalText, "x\u202ey\u0085z\xffw", "x�y�z�w"},
	} {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%q = %q, want %q", c.in, got, c.want)
		}
	}
	// A line longer than sanitizingWriter holds goes out in pieces, none
	// splitting a character.
	var out bytes.Buffer
	w, flush := sandboxOutput(&out, true)
	long := strings.Repeat("é", maxSandboxLine)
	if _, err := io.WriteString(w, long); err != nil || flush() != nil || out.String() != long {
		t.Fatalf("a long line changed: %d bytes out of %d, valid %t", out.Len(), len(long), utf8.Valid(out.Bytes()))
	}
	// The palette's own codes pass through the helpers.
	ta := newTestApp(t, "")
	ta.IO.Color = true
	ta.warn("x\x1b[2Jy")
	has(t, ta.output(), ansiYellow+ansiBold+"⚠"+ansiReset+" x�[2Jy")
}

// TestRunTailScript runs the script `sandbox logs` runs in the sandbox: no
// log is exit runNoLog with nothing on stderr (not tail's complaint).
func TestRunTailScript(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	dir := t.TempDir()
	run := func(what string, code int, stdout string) {
		t.Helper()
		var out, errOut bytes.Buffer
		cmd := exec.Command("/bin/sh", "-c", runTailScript, "sh", dir, "2")
		cmd.Stdout, cmd.Stderr = &out, &errOut
		got := 0
		var exit *exec.ExitError
		if err := cmd.Run(); errors.As(err, &exit) {
			got = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if got != code || out.String() != stdout || errOut.Len() != 0 {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", what, got, out.String(), errOut.String())
		}
	}
	run("without a log", runNoLog, "")
	// latest.log links to the run's log: a dangling link is no log either.
	if err := os.Symlink(filepath.Join(dir, "gone.log"), filepath.Join(dir, "latest.log")); err != nil {
		t.Fatal(err)
	}
	run("dangling link", runNoLog, "")
	writeFile(t, filepath.Join(dir, "gone.log"), "one\ntwo\nthree\n")
	run("with a log", 0, "two\nthree\n")
}

func TestPullCopyModeToBranch(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.wantCalls(t, 1, "POST", "copybox/start")
	if n := ta.calls("POST", "copybox/stop"); n != 1 || !strings.Contains(ta.output(), "stopped copybox again") {
		t.Fatalf("the sandbox the pull started was not stopped again (%d):\n%s", n, ta.output())
	}
	// Where the work goes is checked before the sandbox starts.
	if !slices.Equal(ta.copy.steps, []string{"check branch", "pull copybox", "apply branch"}) {
		t.Fatalf("steps = %v", ta.copy.steps)
	}
	if r := ta.bodies("POST", "copybox/workspace"); len(r) != 1 || !strings.Contains(r[0], `"pull_mode":"branch"`) || !strings.Contains(r[0], `"lines_added":4`) {
		t.Fatalf("report = %q", r)
	}
	if err := ta.Pull(bg, PullOptions{Name: "copybox", Apply: true, PatchOut: "x.patch"}); err == nil {
		t.Fatal("two modes were accepted")
	}
	ta.daemon.add(sampleSandbox("mounted"))
	wantErr(t, ta.Pull(bg, PullOptions{Name: "mounted", Apply: true}), "works on your folder directly")
	// Sensitive changes need consent.
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Changes: []workspace.TreeChange{{Path: ".envrc", Status: "A"}},
		Review: workspace.ReviewReport{FilesChanged: 1, Flags: []workspace.Flag{{Path: ".envrc", Label: ".envrc", Severity: workspace.SeverityHigh}}}}
	ta.IO.TTY = false
	wantErr(t, ta.Pull(bg, PullOptions{Name: "copybox", Apply: true}), "--accept-sensitive")
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Apply: true, AcceptSensitive: true}))
	if last := ta.copy.apply[len(ta.copy.apply)-1]; last.Mode != workspace.ApplyMerge || !last.AcceptSensitive {
		t.Fatalf("apply = %+v", last)
	}
	// Work the folder already has is not "applied 0 changes".
	ta.out.Reset()
	ta.copy.pull, ta.copy.applied = nil, &workspace.ApplyResult{Mode: workspace.ApplyMerge, UpToDate: true}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Apply: true}))
	has(t, ta.output(), "nothing to apply: ", "already has these changes")
	lacks(t, ta.output(), "applied 0 changes")
}

// `sandbox pull --branch` and `--patch-out FILE` are checked against the
// project before the sandbox is started: a branch that holds other work, a
// patch file that exists and a folder without git are refused before
// "starting …". A branch that holds the work already takes nothing new, so
// nothing is asked about its sensitive changes (#965).
func TestPullChecksWhereTheWorkGoesFirst(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	for _, c := range []struct {
		o    PullOptions
		err  error
		want string
	}{
		{PullOptions{Name: "copybox", Branch: true}, errors.New("workspace: branch dc/copybox already exists"),
			"bring back copybox's changes: branch dc/copybox already exists; pass --branch-name NAME for another branch, or --force to move this one"},
		{PullOptions{Name: "copybox", PatchOut: "copybox.patch"}, errors.New("workspace: /tmp/copybox.patch already exists"),
			"pass another --patch-out FILE, or --force to overwrite this one"},
		{PullOptions{Name: "copybox", BranchAs: "fix"}, workspace.ErrNotGitProject, "not a git repository, so there is no branch to put its changes on"},
		{PullOptions{Name: "copybox", Apply: true}, workspace.ErrCopyNotFound, "pull copybox: copy-mode record not found"},
	} {
		ta.copy.checkErr = c.err
		wantErr(t, ta.Pull(bg, c.o), c.want)
	}
	ta.wantCalls(t, 0, "POST", "copybox/start")
	lacks(t, ta.output(), "starting copybox")
	if len(ta.copy.checks) != 4 || !filepath.IsAbs(ta.copy.checks[1].PatchPath) || ta.copy.checks[2].Branch != "fix" {
		t.Fatalf("checks = %+v", ta.copy.checks)
	}
	// A preview has nowhere to go.
	ta.copy.checkErr = nil
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox"}))
	if len(ta.copy.checks) != 4 {
		t.Fatalf("a preview checked %+v", ta.copy.checks[4:])
	}

	ta = newTestApp(t, "")
	sb := copySandbox("copybox")
	sb.Phase = "ready"
	ta.daemon.add(sb)
	ta.IO.TTY = false
	ta.copy.held = true
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Effective: "e1", Changes: []workspace.TreeChange{{Path: ".envrc", Status: "A"}},
		Review: workspace.ReviewReport{FilesChanged: 1, Flags: []workspace.Flag{{Path: ".envrc", Label: ".envrc", Severity: workspace.SeverityHigh}}}}
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyBranch, UpToDate: true, Branch: "dc/copybox"}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	has(t, ta.output(), "nothing to do: branch dc/copybox already has these changes (your checkout is unchanged)")
	lacks(t, ta.output(), "--accept-sensitive", "Bring them back anyway?")
}

// A branch that holds only the sandbox's earlier pull is refused before the
// boot when the stopped sandbox has run since (the #1019 retest: `pull
// --branch` started it, pulled, stopped it and only then refused), naming
// that pull. The check is told whether the pull starts the sandbox and
// which pull it would reuse; a running sandbox starts nothing.
func TestPullRefusesABranchOfEarlierWorkBeforeTheBoot(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.copy.checkErr = &workspace.EarlierPullError{Branch: "dc/copybox", PulledAt: ta.Now().Add(-time.Hour)}
	wantErr(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}),
		"bring back copybox's changes: branch dc/copybox already exists: it holds copybox's pull at "+ta.clock(ta.Now().Add(-time.Hour))+
			", and copybox has run since, so its work may have changed; pass --branch-name NAME for another branch, or --force to move this one")
	ta.wantCalls(t, 0, "POST", "copybox/start")
	lacks(t, ta.output(), "starting copybox")
	if len(ta.copy.checks) != 1 || !ta.copy.checks[0].Starts || ta.copy.checks[0].Reuse != "" {
		t.Fatalf("checks = %+v", ta.copy.checks)
	}

	// Stopped by a pull that read it: the next pull would reuse that one.
	ta.copy.checkErr = nil
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Result: "r1", Effective: "r1", PulledAt: ta.Now(),
		Changes: []workspace.TreeChange{{Path: "main.go", Status: "M", Added: 4}}}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.wantCalls(t, 1, "POST", "copybox/start")
	if len(ta.copy.checks) != 3 || !ta.copy.checks[2].Starts || ta.copy.checks[2].Reuse != "r1" {
		t.Fatalf("checks = %+v", ta.copy.checks)
	}

	// A running sandbox is read as it is.
	ta = newTestApp(t, "")
	sb := copySandbox("copybox")
	sb.Phase = "ready"
	ta.daemon.add(sb)
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	if len(ta.copy.checks) == 0 || ta.copy.checks[0].Starts || ta.copy.checks[0].Reuse != "" {
		t.Fatalf("checks = %+v", ta.copy.checks)
	}
}

// A pull of a stopped copy-mode sandbox that has not run since its last
// pull read its copy is made from that pull: the second `pull --branch`
// starts nothing and finds the branch done. A pull the workspace cannot
// reuse, or a sandbox started since, is read again (#965).
func TestPullOfAStoppedSandboxReusesItsLastPull(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Result: "r1", Effective: "r1", PulledAt: ta.Now(),
		Changes: []workspace.TreeChange{{Path: "main.go", Status: "M", Added: 4}}, Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 4}}
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyBranch, Applied: true, Branch: "dc/copybox"}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.wantCalls(t, 1, "POST", "copybox/start")

	ta.fresh()
	ta.copy.steps = nil
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyBranch, UpToDate: true, Branch: "dc/copybox"}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.wantCalls(t, 1, "POST", "copybox/start")
	has(t, ta.output(), "copybox's copy has not changed since its last pull at "+ta.clock(ta.Now())+"; using that pull instead of starting it",
		"copybox: 1 file changed (+4 −0)", "nothing to do: branch dc/copybox already has these changes")
	lacks(t, ta.output(), "starting copybox", "stopped copybox again")
	if !slices.Equal(ta.copy.steps, []string{"check branch", "reuse copybox r1", "apply branch"}) {
		t.Fatalf("steps = %v", ta.copy.steps)
	}
	// The review of it reads nothing either.
	ta.ok(t, ta.Review(bg, ReviewOptions{Name: "copybox"}))
	ta.wantCalls(t, 1, "POST", "copybox/start")

	// A pull the workspace cannot reuse starts it.
	ta.copy.reuseErr = errors.New("another pull since")
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox"}))
	ta.wantCalls(t, 2, "POST", "copybox/start")
	// So does a sandbox that started since (and was stopped outside the
	// CLI: nothing marked it again).
	ta.copy.reuseErr = nil
	ta.ok(t, ta.Start(bg, "copybox", StartOptions{}))
	ta.daemon.add(copySandbox("copybox"))
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox"}))
	ta.wantCalls(t, 4, "POST", "copybox/start")
}

// After a start and a stop whose look found the copy as the last pull read
// it, that pull is reused, and the note says what holds: the copy has not
// changed since that pull (it said the sandbox "has not run since" the pull,
// which it had, the #1019 retest).
func TestPullReuseNoteAfterAStartAndAStop(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	pulledAt := ta.Now().Add(-time.Hour)
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Result: "r1", Effective: "r1", PulledAt: pulledAt,
		Changes: []workspace.TreeChange{{Path: "main.go", Status: "M", Added: 4}}}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox"}))
	ta.ok(t, ta.Start(bg, "copybox", StartOptions{}))
	ta.copy.pending, ta.copy.pendingPulled = map[string]workspace.CopyWork{"copybox": workspace.CopyWorkUnpulled}, map[string]string{"copybox": "r1"}
	ta.ok(t, ta.Stop(bg, StopOptions{Name: "copybox"}))
	ta.ok(t, ta.fresh().Pull(bg, PullOptions{Name: "copybox"}))
	ta.wantCalls(t, 2, "POST", "copybox/start")
	has(t, ta.output(), "copybox's copy has not changed since its last pull at "+ta.clock(pulledAt)+"; using that pull instead of starting it")
	lacks(t, ta.output(), "has not run since", "starting copybox")
}

// An apply that had fewer paths to write than the pull changed says the
// rest already matched the folder (retest RT-B-2: "3 files changed", then
// "applied 2 changes" with nothing about the third, which an undo had left
// on the host).
func TestPullApplySaysWhatAlreadyMatched(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Changes: []workspace.TreeChange{
		{Path: "README.md", Status: "M"}, {Path: "alpha.txt", Status: "A"}, {Path: "beta.txt", Status: "A"}}}
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyMerge, Applied: true,
		Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}, {Path: "beta.txt", Status: "A"}}}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Apply: true}))
	has(t, ta.output(), "applied 2 changes to ", "; 1 already matched your folder")
	// Every path written: nothing more is said.
	ta.out.Reset()
	ta.copy.applied.Changes = append(ta.copy.applied.Changes, workspace.TreeChange{Path: "alpha.txt", Status: "A"})
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Apply: true}))
	has(t, ta.output(), "applied 3 changes to ")
	lacks(t, ta.output(), "already matched")
}

// A conflicted `pull --apply` exits 4 and says how to merge (manual test
// L2: status 0 and no hint).
func TestPullApplyConflictExitsWithItsOwnStatus(t *testing.T) {
	ta := newTestApp(t, "")
	sb := copySandbox("m2-b")
	sb.Phase = "ready"
	ta.daemon.add(sb)
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyMerge, Conflicts: []string{"README.md"}, Branch: "dc/m2-b",
		PatchPath: "/data/sandboxes/m2-b/copy/m2-b.patch"}
	wantExit(t, ta.Pull(bg, PullOptions{Name: "m2-b", Apply: true}), ExitPullConflict)
	has(t, ta.output(), "the 3-way apply conflicted in README.md; your working tree is unchanged", "the changes are on branch dc/m2-b instead",
		"merge them when you are ready: git merge dc/m2-b")
	// A git too old to merge in place falls back the same way.
	ta.out.Reset()
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyMerge, Branch: "dc/m2-b",
		Warnings: []string{"git 2.34.1 cannot merge without touching the working tree (git 2.38+ can)"}}
	wantExit(t, ta.Pull(bg, PullOptions{Name: "m2-b", Apply: true}), ExitPullConflict)
	has(t, ta.output(), "could not be applied to your working tree")
	lacks(t, ta.output(), "applied 1 change")
	// A branch or patch that exists says how to go on, without the
	// workspace package's prefix.
	ta.copy.applied, ta.copy.applyErr = nil, errors.New("workspace: branch dc/m2-b already exists")
	err := ta.Pull(bg, PullOptions{Name: "m2-b", Branch: true})
	if err == nil || err.Error() != "bring back m2-b's changes: branch dc/m2-b already exists; pass --branch-name NAME for another branch, or --force to move this one" {
		t.Fatalf("Pull --branch = %v", err)
	}
	ta.copy.applyErr = errors.New("workspace: /tmp/x.patch already exists")
	err = ta.Pull(bg, PullOptions{Name: "m2-b", PatchOut: "/tmp/x.patch"})
	if err == nil || !strings.HasSuffix(err.Error(), "/tmp/x.patch already exists; pass another --patch-out FILE, or --force to overwrite this one") {
		t.Fatalf("Pull --patch-out = %v", err)
	}
}

func TestUndoCopyModeRevertsTheLastApply(t *testing.T) {
	// Nothing was applied: say so, not "never changed the folder".
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.ok(t, ta.Undo(bg, UndoOptions{Name: "copybox"}))
	has(t, ta.output(), "nothing to undo: copybox works on a copy, and no `pull --apply` of its work is left to revert")
	if ta.calls("POST", "copybox/undo") != 0 {
		t.Fatal("a copy-mode undo went to the daemon's mount undo")
	}
	// An apply: preview, consent, revert, report.
	ta = newTestApp(t, "y\n", copySandbox("copybox"))
	const ref = "refs/defenseclaw/copy/copybox/pre-apply"
	ta.copy.undo = &workspace.UndoApplyResult{Name: "copybox", Project: ta.project, PreApplyRef: ref,
		Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}, {Path: "NEW.md", Status: "D"}}}
	ta.ok(t, ta.Undo(bg, UndoOptions{Name: "copybox"}))
	has(t, ta.output(), "Undo will revert the last `pull --apply` of copybox", "revert  README.md", "remove  NEW.md",
		"edits you made since the apply stay", "reverted the last apply: 2 paths")
	if !slices.Equal(ta.copy.steps, []string{"undo-apply copybox preview=true", "undo-apply copybox preview=false"}) {
		t.Errorf("steps = %v", ta.copy.steps)
	}
	if r := ta.bodies("POST", "copybox/workspace"); len(r) != 1 || !strings.Contains(r[0], `"operation":"undo"`) || !strings.Contains(r[0], `"file_count":2`) {
		t.Errorf("reports = %q", r)
	}
	if ta.calls("POST", "copybox/undo") != 0 {
		t.Error("a copy-mode undo went to the daemon's mount undo")
	}
	// Edits since the apply overlap it: refuse, change nothing, and say
	// where the old folder is.
	ta = newTestApp(t, "y\n", copySandbox("copybox"))
	ta.copy.undo = &workspace.UndoApplyResult{Name: "copybox", Project: ta.project, PreApplyRef: ref, Conflicts: []string{"README.md"}}
	wantErr(t, ta.Undo(bg, UndoOptions{Name: "copybox"}), "you also changed README.md since the apply", "diff "+ref)
	if len(ta.copy.steps) != 1 {
		t.Errorf("a conflicting undo went past the preview: %v", ta.copy.steps)
	}
	// -o json: one document on stdout.
	ta = newTestApp(t, "y\n", copySandbox("copybox"))
	ta.copy.undo = &workspace.UndoApplyResult{Name: "copybox", Project: ta.project, Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}}}
	ta.ok(t, ta.Undo(bg, UndoOptions{Name: "copybox", Output: OutputJSON}))
	var res sandboxapi.UndoResponse
	if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Apply == nil || !res.Apply.Undone {
		t.Fatalf("stdout is not one undo response (%v):\n%s", err, ta.out.String())
	}
}

// With -o json stdout holds exactly one JSON document; the progress lines
// go to stderr.
func TestPullJSONKeepsStdoutParseable(t *testing.T) {
	for _, c := range []struct {
		name  string
		opts  PullOptions
		empty bool // the pull brings nothing back
		// review is whether stdout is the pull's result rather than the
		// apply's.
		review  bool
		mode    workspace.ApplyMode
		applied bool
		stderr  []string
		// since is a pull that starts from an earlier apply.
		since bool
	}{
		{"review", PullOptions{}, false, true, "", false, []string{"starting copybox", "Pulling copybox's work"}, false},
		{"branch", PullOptions{Branch: true}, false, false, workspace.ApplyBranch, true,
			[]string{"Pulling copybox's work", "copybox: ", "M main.go", "the changes are on branch"}, false},
		{"nothing to bring back", PullOptions{Apply: true}, true, false, workspace.ApplyMerge, false, []string{"nothing to bring back"}, false},
		// What the operator took back of that apply is not in the folder:
		// only what is known is said.
		{"nothing new since the last apply", PullOptions{Apply: true}, true, false, workspace.ApplyMerge, false,
			[]string{"nothing new since the last apply to "}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "", copySandbox("copybox"))
			if c.empty {
				ta.copy.pull = &workspace.PullResult{Name: "copybox"}
				if c.since {
					ta.copy.pull.Since = strings.Repeat("d", 40)
				}
			}
			o := c.opts
			o.Name, o.Output = "copybox", OutputJSON
			ta.ok(t, ta.Pull(bg, o))
			var res struct {
				Name    string
				Mode    workspace.ApplyMode
				Applied bool
			}
			if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || (c.review && res.Name != "copybox") ||
				(!c.review && (res.Mode != c.mode || res.Applied != c.applied)) {
				t.Fatalf("stdout is not one result (%v):\n%s", err, ta.output())
			}
			has(t, ta.err.String(), c.stderr...)
			lacks(t, ta.err.String(), "has the sandbox's changes")
			if ta.IO.Out != io.Writer(ta.out) {
				t.Fatal("stdout was not restored after the command")
			}
		})
	}
}

// A pull with no mode that finds nothing to bring back says so, as --apply
// does, instead of how to bring it back (retest RT-B-1: "bring it back with
// --apply, --branch or --patch-out FILE" after "0 files changed … since the
// last apply"). So does `review` of a copy-mode sandbox.
func TestPullWithNothingToBringBackSaysSo(t *testing.T) {
	for _, c := range []struct {
		name    string
		since   bool
		preview bool
		want    string
	}{
		{"since the last apply", true, false, "nothing new since the last apply to "},
		{"nothing changed", false, false, "nothing to bring back"},
		{"review since the last apply", true, true, "nothing new since the last apply to "},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "", copySandbox("copybox"))
			ta.copy.pull = &workspace.PullResult{Name: "copybox"}
			if c.since {
				ta.copy.pull.Since = strings.Repeat("d", 40)
			}
			ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", preview: c.preview}))
			has(t, ta.output(), "copybox: 0 files changed", c.want)
			lacks(t, ta.output(), "bring it back with", "nothing was applied")
		})
	}
}

// `policy allow|block` edits config.yaml. A refused entry writes nothing: a
// catch-all, any edit of a managed install, and a host the organization's
// policy keeps closed, whatever the entry says (manual test M10: "✓ added"
// for a host the organization blocks). A host name on the organization's
// blocklist covers its subdomains (#946), so the doctor no longer warns
// that it leaves them open.
func TestPolicyEdit(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.ok(t, ta.PolicyEdit(bg, "allow", []string{"Registry.NPMjs.org", "*.pypi.org"}))
	ta.ok(t, ta.PolicyEdit(bg, "block", []string{"paste.example"}))
	if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Egress.Allow, []string{"registry.npmjs.org", "*.pypi.org"}) ||
		!slices.Equal(c.OpenShell.Egress.Block, []string{"paste.example"}) {
		t.Fatalf("egress = %+v", c.OpenShell.Egress)
	}
	off := false
	for _, c := range []struct {
		name  string
		admin config.OpenShellAdminConfig
		host  string
		want  string
	}{
		{"a catch-all", config.OpenShellAdminConfig{}, "*", ""},
		{"a managed install", config.OpenShellAdminConfig{}, "x.example", sandboxapi.AdminMessage},
		{"egress_block", config.OpenShellAdminConfig{EgressBlock: []string{"example.net"}}, "example.net",
			"blocked by your organization's DefenseClaw policy: egress.allow — example.net is on your organization's blocklist (example.net) (openshell.admin.egress_block)"},
		{"egress_block wildcard", config.OpenShellAdminConfig{EgressBlock: []string{"*.example.net"}}, "*.api.example.net", "openshell.admin.egress_block"},
		{"egress_block subdomain", config.OpenShellAdminConfig{EgressBlock: []string{"example.net"}}, "www.example.net",
			"www.example.net is on your organization's blocklist (example.net) (openshell.admin.egress_block)"},
		{"egress_block subdomain wildcard", config.OpenShellAdminConfig{EgressBlock: []string{"Example.NET."}}, "*.cdn.example.net",
			"*.cdn.example.net is on your organization's blocklist (Example.NET.) (openshell.admin.egress_block)"},
		{"egress_allow_only", config.OpenShellAdminConfig{EgressAllowOnly: []string{"*.github.com"}}, "example.com",
			"example.com is not on your organization's list of allowed destinations (openshell.admin.egress_allow_only)"},
		{"allow_unblock", config.OpenShellAdminConfig{AllowUnblock: &off}, "example.com",
			"your own allow entries are ignored; ask your administrator to add destinations (openshell.admin.allow_unblock)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			writeConfig(t, ta, "")
			ta.Cfg.OpenShell.Admin = c.admin
			if c.name == "a managed install" {
				ta.Cfg.DeploymentMode = "managed_enterprise"
			}
			before, _ := os.ReadFile(ta.ConfigPath)
			wantErr(t, ta.PolicyEdit(bg, "allow", []string{c.host}), c.want)
			if after, _ := os.ReadFile(ta.ConfigPath); string(after) != string(before) {
				t.Fatal("a refused entry was written")
			}
		})
	}
	ta = newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.Cfg.OpenShell.Admin = config.OpenShellAdminConfig{EgressAllowOnly: []string{"*.github.com"}, EgressBlock: []string{"example.net", "*.example.org", "example.org"}}
	ta.ok(t, ta.PolicyEdit(bg, "allow", []string{"api.github.com"}))
	// Only the organization's blocklist widens: an allow entry for a
	// subdomain of a bare allow-only name is still refused.
	ta.Cfg.OpenShell.Admin.EgressAllowOnly = []string{"github.com"}
	wantErr(t, ta.PolicyEdit(bg, "allow", []string{"api.github.com"}), "api.github.com is not on your organization's list of allowed destinations")
	if c := ta.adminCheck(); c.Status != openshell.StatusPass || strings.Contains(c.Detail, "subdomains") {
		t.Fatalf("doctor check = %+v", c)
	}
}

// An organization's refusal names the key, the reason, the constraint and
// the way on (manual test M9: "blocked by your organization's DefenseClaw
// policy: harness" and nothing else). The violations are the ones package
// packs produces for each openshell.admin constraint.
func TestAdminRefusalsSayWhy(t *testing.T) {
	on, off := true, false
	project := filepath.Join(t.TempDir(), "work", "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		admin  config.OpenShellAdminConfig
		action packs.Action
		want   string
	}{
		{"allowed_harnesses", config.OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode"}}, packs.Action{Kind: packs.ActionHarness, Harness: "codex"},
			"blocked by your organization's DefenseClaw policy: harness — your organization allows only claude (openshell.admin.allowed_harnesses); ask your administrator if you need it"},
		{"allow_unblock", config.OpenShellAdminConfig{AllowUnblock: &off}, packs.Action{Kind: packs.ActionUnblock, Host: "example.org"},
			"blocked by your organization's DefenseClaw policy: egress.unblock — blocked destinations cannot be unblocked; ask your administrator (openshell.admin.allow_unblock)"},
		{"egress_block", config.OpenShellAdminConfig{EgressBlock: []string{"*.example.net"}}, packs.Action{Kind: packs.ActionUnblock, Host: "www.example.net"},
			"egress.unblock — www.example.net matches *.example.net on your organization's blocklist (openshell.admin.egress_block); ask your administrator if you need it"},
		{"egress_allow_only", config.OpenShellAdminConfig{EgressAllowOnly: []string{"*.github.com"}}, packs.Action{Kind: packs.ActionUnblock, Host: "example.org"},
			"— example.org is not on your organization's list of allowed destinations (openshell.admin.egress_allow_only); ask your administrator if you need it"},
		{"allow_mount", config.OpenShellAdminConfig{AllowMount: &off}, packs.Action{Kind: packs.ActionMount, Path: project},
			"workdir.mode — live host mounts are disabled; use copy mode (openshell.admin.allow_mount); run it with --copy (a sandbox that mounts the folder live must be deleted and run again with --copy)"},
		{"require_copy_for", config.OpenShellAdminConfig{AllowMount: &on, RequireCopyFor: []string{project}}, packs.Action{Kind: packs.ActionMount, Path: project},
			"your organization requires copy mode for projects matching " + project + " (openshell.admin.require_copy_for); run it with --copy"},
		{"allow_host_ports", config.OpenShellAdminConfig{AllowHostPorts: &off}, packs.Action{Kind: packs.ActionHostPort, Port: 3000},
			"mcp.host_ports — host ports cannot be opened to sandboxes (openshell.admin.allow_host_ports); run it without --host-port"},
		{"allow_yolo", config.OpenShellAdminConfig{AllowYolo: &off}, packs.Action{Kind: packs.ActionYolo},
			"yolo — skip-permissions mode is disabled; the harness keeps its permission prompts (openshell.admin.allow_yolo)"},
		{"allow_learn_mode", config.OpenShellAdminConfig{AllowLearnMode: &off}, packs.Action{Kind: packs.ActionLearnMode},
			"learn — learn mode is disabled (openshell.admin.allow_learn_mode)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{DataDir: t.TempDir()}
			cfg.OpenShell.Enabled = true
			cfg.OpenShell.Admin = c.admin
			eff, _, err := packs.Resolve(cfg, packs.Flags{Harness: "claudecode", Project: project})
			if err != nil {
				t.Fatal(err)
			}
			var v *packs.Violation
			if err := eff.Allow(c.action); !errors.As(err, &v) {
				t.Fatalf("Allow = %v", err)
			}
			w := wireViolation(*v)
			// The daemon's API error carries the same violation.
			got := apiError(&sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: v.Message, Detail: v.Detail, Violation: &w}).Error()
			if !strings.Contains(got, c.want) || !strings.HasPrefix(got, sandboxapi.AdminMessage+": ") {
				t.Fatalf("message:\n%s\nwant it to contain:\n%s", got, c.want)
			}
		})
	}
}

func TestPolicyShowExplainSuggest(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Admin = sandboxapi.AdminStatus{Configured: true, Authority: "advisory", Detail: "config.yaml is yours"}
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{Key: "profile", Value: "balanced", Source: "admin",
		Origin: "openshell.admin.min_profile", Requested: "open"})
	ta.ok(t, ta.PolicyShow(bg, PolicyOptions{Harness: "claude"}))
	has(t, ta.output(), "Pack          open (builtin:open) sha256:", "advisory: config.yaml is yours")
	if q := ta.daemon.callsTo("GET", sandboxapi.PathPolicyExplain); len(q) != 1 || !strings.Contains(q[0].Query, "harness=claudecode") {
		t.Fatalf("explain query = %+v", q)
	}
	ta.ok(t, ta.fresh().PolicyExplain(bg, PolicyOptions{Sandbox: "box"}))
	has(t, ta.output(), "balanced (instead of open)", "openshell.admin.min_profile")
	lacks(t, ta.output(), "-o json lists all")
	// A long list is cut to what fits, and says so.
	var masks []string
	for i := range 40 {
		masks = append(masks, fmt.Sprintf("**/secret-%02d.pem", i))
	}
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{Key: "workdir.masks", Value: strings.Join(masks, ", "),
		Source: "pack", Origin: "pack open"})
	ta.ok(t, ta.fresh().PolicyExplain(bg, PolicyOptions{Sandbox: "box"}))
	has(t, ta.output(), "**/secret-00.pem, **/secret-01.pem (+38 more; -o json lists all)")
	// "asked for" only for what the user asked for (manual R2-104).
	ta.daemon.explain.Settings = []sandboxapi.Setting{
		{Key: "resources.cpu", Value: "1", Source: "admin", Origin: "openshell.admin.max_resources", Requested: "(unlimited)"},
		{Key: "profile", Value: "strict", Source: "admin", Origin: "openshell.admin.required_pack", Requested: "open"}}
	ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "profile", Source: "flag", Attempted: "open", Enforced: "strict", Admin: true,
		Constraint: "openshell.admin.required_pack"}}
	ta.ok(t, ta.fresh().PolicyExplain(bg, PolicyOptions{Harness: "claude", Profile: "open"}))
	has(t, ta.output(), "1 (instead of unlimited)", "strict (asked for open)")
	lacks(t, ta.output(), "asked for (unlimited)")
	ta.daemon.events = []sandboxapi.ActivityEvent{
		{Kind: sandboxapi.ActivityEgressAllowed, Host: "registry.npmjs.org"}, {Kind: sandboxapi.ActivityEgressAllowed, Host: "registry.npmjs.org"},
		{Kind: sandboxapi.ActivityEgressAllowed, Host: "docs.python.org"}, {Kind: sandboxapi.ActivityEgressBlocked, Host: "webhook.site"},
	}
	ta.ok(t, ta.fresh().PolicySuggest(bg, SuggestOptions{}))
	has(t, ta.output(), "      - docs.python.org  # 1\n      - registry.npmjs.org  # 2", "Blocked (not suggested): webhook.site")
}

// `policy show` sizes its key column to the longest key; `policy explain`
// cuts long values, lists every organization constraint, and allow entries
// outside the allow-only list as unreachable (manual test L7).
func TestPolicyOutputFormatting(t *testing.T) {
	on, off := true, false
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Admin = config.OpenShellAdminConfig{RequiredPack: "strict", AllowYolo: &off, AllowMount: &on,
		RequireCopyFor: []string{"~/clients/*"}, EgressAllowOnly: []string{"*.github.com"}}
	var masks []string
	for i := 0; i < 24; i++ {
		masks = append(masks, "**/secret-"+strings.Repeat("x", 30)+string(rune('a'+i))+"/*")
	}
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
		sandboxapi.Setting{Key: "hooks.fail_mode", Value: "closed", Source: "pack", Origin: "pack strict"},
		sandboxapi.Setting{Key: "egress.admin_block", Value: "example.net", Source: "admin", Origin: "openshell.admin.egress_block"},
		sandboxapi.Setting{Key: "egress.allow_only", Value: "*.github.com", Source: "admin", Origin: "openshell.admin.egress_allow_only"},
		sandboxapi.Setting{Key: "egress.allow", Value: "api.github.com, registry.npmjs.org", Source: "user", Origin: "openshell.egress.allow"},
		sandboxapi.Setting{Key: "workdir.masks", Value: strings.Join(masks, ", "), Source: "pack", Origin: "pack strict"},
	)
	ta.ok(t, ta.PolicyShow(bg, PolicyOptions{}))
	has(t, ta.output(), "hooks.fail_mode     closed", "egress.admin_block  example.net",
		"egress.allow        api.github.com (1 entry outside the organization's allow-only list: not reachable)")
	ta.ok(t, ta.fresh().PolicyExplain(bg, PolicyOptions{}))
	out := ta.output()
	// Every line of the table and the constraints fits 120 columns; only
	// the warnings, which are sentences, may wrap.
	for _, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > 120 && !strings.HasPrefix(line, "  ⚠") {
			t.Fatalf("explain line of %d characters:\n%s", n, line)
		}
	}
	has(t, out, "more; -o json lists all)", "Organization constraints (openshell.admin)",
		"required_pack          strict", "allow_yolo             false", "require_copy_for       ~/clients/*", "egress_allow_only      *.github.com",
		"egress.allow: 1 entry outside the organization's allow-only list: not reachable")
}

// `policy show` says when large uploads to first-seen hosts are cut, and at
// what size; `policy explain` lists the administrator's block among the
// organization constraints.
func TestPolicyShowsTheLargeUploadBlock(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
		sandboxapi.Setting{Key: "egress.large_upload_mb", Value: "10", Source: "pack", Origin: "pack balanced"},
		sandboxapi.Setting{Key: "egress.block_large_uploads", Value: "false", Source: "pack", Origin: "pack balanced"})
	ta.ok(t, ta.PolicyShow(bg, PolicyOptions{}))
	lacks(t, ta.output(), "egress.block_large_uploads")
	ta.Cfg.OpenShell.Admin.BlockLargeUploads = true
	ta.daemon.explain.Settings[len(ta.daemon.explain.Settings)-1] = sandboxapi.Setting{Key: "egress.block_large_uploads", Value: "true",
		Source: "admin", Origin: "openshell.admin.block_large_uploads"}
	ta.ok(t, ta.fresh().PolicyShow(bg, PolicyOptions{}))
	has(t, ta.output(), "egress.block_large_uploads  true (an upload of more than 10 MiB to a host the sandbox had not contacted is cut)")
	ta.ok(t, ta.fresh().PolicyExplain(bg, PolicyOptions{}))
	has(t, ta.output(), "openshell.admin.block_large_uploads", "Organization constraints (openshell.admin)", "block_large_uploads    true")
}

func TestPackCommands(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.PackDir = filepath.Join(ta.Cfg.DataDir, "policies", "sandbox")
	ta.ok(t, ta.PackList(PackOptions{}))
	has(t, ta.output(), "open", "balanced", "strict", "sha256:")
	ta.ok(t, ta.fresh().PackList(PackOptions{Output: OutputJSON}))
	var list struct {
		Packs []struct{ Name, Digest string }
	}
	if err := json.Unmarshal(ta.out.Bytes(), &list); err != nil || len(list.Packs) < 3 || !strings.HasPrefix(list.Packs[0].Digest, "sha256:") {
		t.Fatalf("pack list json: %v %s", err, ta.output())
	}
	ta.ok(t, ta.fresh().PackShow("strict", PackOptions{}))
	has(t, ta.output(), "# digest sha256:", "name: strict")
	bad := filepath.Join(t.TempDir(), "pack.yaml")
	writeFile(t, bad, "version: 1\nname: bad\nunknown_key: 1\n")
	if err := ta.PackValidate(bad); err == nil {
		t.Fatal("an invalid pack validated")
	}
	// `pack list` shows an invalid pack's whole error below the table, not
	// cut with "…" (manual test L10).
	ta.out.Reset()
	key := "a_key_no_pack_format_has_ever_had_" + strings.Repeat("x", 60)
	writeFile(t, filepath.Join(ta.Cfg.OpenShell.PackDir, "broken", "pack.yaml"), "version: 1\nname: broken\n"+key+": 1\n")
	ta.ok(t, ta.PackList(PackOptions{}))
	has(t, ta.output(), "invalid (see below)", "✗ broken: ", key)
	lacks(t, ta.output(), "…")
}

func TestEnableDisableWrappers(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.env["SHELL"] = "/bin/zsh"
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude"}))
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "codex", Shell: "bash"}))
	zshrc, _ := os.ReadFile(filepath.Join(ta.home, ".zshrc"))
	bashrc, _ := os.ReadFile(filepath.Join(ta.home, ".bashrc"))
	if !strings.Contains(string(zshrc), "/usr/local/bin/defenseclaw-gateway' sandbox run claude") &&
		!strings.Contains(string(zshrc), "/usr/local/bin/defenseclaw-gateway sandbox run claude") {
		t.Fatalf(".zshrc:\n%s", zshrc)
	}
	has(t, string(bashrc), "sandbox run codex")
	if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Wrappers, []string{"claudecode", "codex"}) {
		t.Fatalf("openshell.wrappers = %v", c.OpenShell.Wrappers)
	}
	ta.ok(t, ta.Disable(WrapperOptions{Harness: "claude"}))
	zshrc, _ = os.ReadFile(filepath.Join(ta.home, ".zshrc"))
	lacks(t, string(zshrc), "sandbox run")
	if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Wrappers, []string{"codex"}) {
		t.Fatalf("openshell.wrappers = %v", c.OpenShell.Wrappers)
	}
	if err := ta.Enable(WrapperOptions{Harness: "claude", Shell: "tcsh"}); err == nil {
		t.Fatal("an unsupported shell was accepted")
	}
}

// A wrapper enable wrote to an --rc file is found again: by the wrapped
// list, doctor, a disable without --rc, and teardown.
func TestWrappersInACustomRCFile(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	custom := filepath.Join(ta.home, "dotfiles", "shell.rc")
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude", Shell: "bash", RC: custom}))
	if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Wrappers, []string{"claudecode"}) {
		t.Fatalf("openshell.wrappers = %v", c.OpenShell.Wrappers)
	}
	has(t, ta.wrappersCheck().Detail, "~/dotfiles/shell.rc")
	ta.ok(t, ta.Teardown(bg, TeardownOptions{DryRun: true}))
	has(t, ta.output(), "claude in ~/dotfiles/shell.rc")
	ta.ok(t, ta.Disable(WrapperOptions{Harness: "claude"}))
	if b, err := wrapper.Read(custom); err != nil || len(b.Wraps) != 0 {
		t.Fatalf("custom rc after disable = %+v, %v", b, err)
	}
	if c := loadConfig(t, ta); len(c.OpenShell.Wrappers) != 0 {
		t.Fatalf("openshell.wrappers = %v", c.OpenShell.Wrappers)
	}
	if r, err := ta.loadReceipt(); err != nil || len(r.Wrappers) != 0 {
		t.Fatalf("receipt wrappers after the last disable = %+v, %v", r, err)
	}
}

func TestResolveHarness(t *testing.T) {
	for in, want := range map[string]string{"claude": "claudecode", "claudecode": "claudecode", "claude-code": "claudecode",
		"Claude Code": "claudecode", "codex": "codex", "CODEX": "codex"} {
		if spec, err := ResolveHarness(in); err != nil || spec.Name != want {
			t.Errorf("ResolveHarness(%q) = %v, %v; want %s", in, spec, err, want)
		}
	}
	wantErr(t, errOf(ResolveHarness("vim")), "claude (Claude Code)")
	// Certification AG-MAC-F8: Antigravity is named as image build, image
	// list and openshell.harnesses name it, and its command agy works too;
	// Kiro by its connector name, not the kiro-cli-chat nobody types.
	for _, in := range []string{"antigravity", "agy", "Antigravity"} {
		if spec, err := ResolveHarness(in); err != nil || spec.Name != "antigravity" {
			t.Errorf("ResolveHarness(%q) = %v, %v; want antigravity", in, spec, err)
		}
	}
	if got := HarnessArg(harnessSpec(t, "antigravity")); got != "antigravity" {
		t.Errorf("HarnessArg(antigravity) = %q", got)
	}
	wantErr(t, errOf(ResolveHarness("vim")), "antigravity (Antigravity)", "kiro (Kiro CLI)")
	// Every harness's name, as setup and the hints give it, resolves back.
	for _, h := range harness.Names() {
		spec, _ := harness.Get(h)
		if got, err := ResolveHarness(HarnessArg(spec)); err != nil || got != spec {
			t.Errorf("HarnessArg(%s) = %q resolves to %v, %v", h, HarnessArg(spec), got, err)
		}
	}
}

func TestDetectLLM(t *testing.T) {
	get := func(name string) *harness.Spec { return harnessSpec(t, name) }
	claude, codex, opencode, hermes := get("claudecode"), get("codex"), get("opencode"), get("hermes")
	cases := []struct {
		name    string
		spec    *harness.Spec
		env     map[string]string
		auth    string
		choice  string
		profile string
		source  string
		wantErr bool
	}{
		{"claude api key", claude, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", profiles.AnthropicID, "ANTHROPIC_API_KEY", false},
		{"claude oauth", claude, map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "t"}, "", "auto", profiles.ClaudeOAuthID, "CLAUDE_CODE_OAUTH_TOKEN", false},
		{"claude bedrock", claude, map[string]string{EnvBedrockToken: "b", "AWS_REGION": "us-west-2"}, "", "bedrock", profiles.ClaudeBedrockMantleID, EnvBedrockToken, false},
		// auto takes an Amazon Bedrock key when it is the one set, and
		// every other credential before it (#955).
		{"claude bedrock under auto", claude, map[string]string{EnvBedrockToken: "b"}, "", "auto", profiles.ClaudeBedrockMantleID, EnvBedrockToken, false},
		{"claude api key before bedrock", claude, map[string]string{EnvBedrockToken: "b", "ANTHROPIC_API_KEY": "k"}, "", "", profiles.AnthropicID, "ANTHROPIC_API_KEY", false},
		{"codex bedrock under auto", codex, map[string]string{EnvBedrockToken: "b"}, "", "", profiles.CodexBedrockMantleID, EnvBedrockToken, false},
		{"codex auth.json before bedrock", codex, map[string]string{EnvBedrockToken: "b"}, `{"OPENAI_API_KEY":"from-file"}`, "", profiles.OpenAIID, "~/.codex/auth.json", false},
		{"copilot bedrock under auto", get("copilot"), map[string]string{EnvBedrockToken: "b"}, "", "", profiles.CopilotBedrockMantleID, EnvBedrockToken, false},
		{"hermes bedrock under auto", hermes, map[string]string{EnvBedrockToken: "b"}, "", "", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"antigravity has no bedrock", get("antigravity"), map[string]string{EnvBedrockToken: "b"}, "", "", "", "", false},
		{"codex env", codex, map[string]string{"CODEX_API_KEY": "c"}, "", "", profiles.OpenAIID, "OPENAI_API_KEY", false},
		{"codex auth.json", codex, nil, `{"OPENAI_API_KEY":"from-file"}`, "", profiles.OpenAIID, "~/.codex/auth.json", false},
		{"codex chatgpt login", codex, nil, `{"OPENAI_API_KEY":null,"tokens":{"id_token":"x"}}`, "", "", "", false},
		{"none", claude, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "none", "", "", false},
		{"explicit missing", claude, nil, "", "anthropic", "", "", true},
		{"wrong provider", codex, nil, "", "anthropic", "", "", true},
		{"opencode anthropic", opencode, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", profiles.OpenCodeAnthropicID, "ANTHROPIC_API_KEY", false},
		{"opencode openai", opencode, map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", profiles.OpenCodeOpenAIID, "OPENAI_API_KEY", false},
		{"opencode bedrock", opencode, map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.OpenCodeBedrockMantleID, EnvBedrockToken, false},
		{"copilot byok anthropic", get("copilot"), map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", profiles.CopilotAnthropicID, "ANTHROPIC_API_KEY", false},
		{"copilot has no openai", get("copilot"), map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", "", "", true},
		{"kiro logs in inside", get("kiro"), map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", "", "", false},
		{"hermes openai", hermes, map[string]string{"OPENAI_API_KEY": "k", "ANTHROPIC_API_KEY": "a"}, "", "", profiles.OpenAIID, "OPENAI_API_KEY", false},
		{"hermes anthropic", hermes, map[string]string{"ANTHROPIC_API_KEY": "a"}, "", "", profiles.AnthropicID, "ANTHROPIC_API_KEY", false},
		{"hermes bedrock", hermes, map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"openhands bedrock", get("openhands"), map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"openhands openai", get("openhands"), map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", profiles.OpenAIID, "OPENAI_API_KEY", false},
		{"antigravity gemini", get("antigravity"), map[string]string{"GEMINI_API_KEY": "g"}, "", "", profiles.GeminiID, "GEMINI_API_KEY", false},
		{"antigravity has no openai", get("antigravity"), map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", "", "", true},
		{"antigravity signs in inside", get("antigravity"), nil, "", "", "", "", false},
		{"omnigent bedrock", get("omnigent"), map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"omnigent openai", get("omnigent"), map[string]string{"OPENAI_API_KEY": "k"}, "", "", profiles.OpenAIID, "OPENAI_API_KEY", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			for k, v := range c.env {
				ta.env[k] = v
			}
			if c.auth != "" {
				writeFile(t, filepath.Join(ta.home, ".codex", "auth.json"), c.auth)
			}
			got, err := ta.detectLLM(c.spec, c.choice, "", "", nil)
			if (err != nil) != c.wantErr {
				t.Fatalf("detectLLM err = %v, want error %t", err, c.wantErr)
			}
			switch {
			case c.wantErr:
			case c.profile == "" && got.Credential != nil:
				t.Fatalf("credential = %+v, want none", got.Credential)
			case c.profile != "" && (got.Credential == nil || got.Credential.Profile != c.profile || got.Source != c.source):
				t.Fatalf("detectLLM = %+v, want %s from %s", got, c.profile, c.source)
			case c.name == "copilot byok anthropic" && got.Credential.Credentials["COPILOT_PROVIDER_API_KEY"] != "k":
				t.Fatalf("copilot credentials = %v", got.Credential.Credentials)
			case c.name == "claude bedrock" && got.Credential.BedrockRegion != "us-west-2":
				t.Fatalf("region = %q", got.Credential.BedrockRegion)
			}
		})
	}
}

// Without a shared credential a Claude subscriber is pointed at `claude
// setup-token` where Claude Code is installed, and a login inside is named
// for what it is: a real token the agent can read (manual R2-42). A binding
// of Hermes's managed-provider key is the model credential (R2-87).
func TestDetectLLMNotes(t *testing.T) {
	claude := harnessSpec(t, "claudecode")
	for _, c := range []struct {
		name   string
		setup  func(*testApp)
		spec   *harness.Spec
		choice string
		bound  map[string]bool
		want   []string
		not    string
	}{
		{"claude", nil, claude, "", nil, []string{"CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`", "stores a real token the agent can read"}, ""},
		{"claude none", nil, claude, "none", nil, []string{"stores a real token the agent can read"}, ""},
		{"claude not installed", func(ta *testApp) { ta.LookPath = func(string) (string, error) { return "", errors.New("not found") } }, claude, "", nil,
			[]string{"set ANTHROPIC_API_KEY, or use /login in the sandbox"}, "setup-token"},
		{"claude wrapped", func(ta *testApp) { ta.Cfg.OpenShell.Wrappers = []string{"claudecode"} }, claude, "", nil,
			[]string{"CLAUDE_CODE_OAUTH_TOKEN from `DEFENSECLAW_NO_SANDBOX=1 claude setup-token`"}, ""},
		{"hermes provider key", nil, harnessSpec(t, "hermes"), "", map[string]bool{"HERMES_DEFENSECLAW_API_KEY": true},
			[]string{"HERMES_DEFENSECLAW_API_KEY comes from --credential"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			if c.setup != nil {
				c.setup(ta)
			}
			got, err := ta.detectLLM(c.spec, c.choice, "", "", c.bound)
			if err != nil || got.Credential != nil {
				t.Fatalf("detectLLM = %+v, %v", got, err)
			}
			has(t, got.Note, c.want...)
			if c.not != "" {
				lacks(t, got.Note, c.not)
			}
		})
	}
	_, err := newTestApp(t, "").detectLLM(claude, "claude-oauth", "", "", nil)
	wantErr(t, err, "claude setup-token")
}

func TestParseCredentialAndEnv(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["STRIPE_API_KEY"] = "v"
	b, err := ta.ParseCredential("STRIPE_API_KEY=API.Stripe.com.")
	if err != nil || b.Host != "api.stripe.com" || b.Port != 0 || b.Value != "v" {
		t.Fatalf("ParseCredential = %+v, %v", b, err)
	}
	if b, err = ta.ParseCredential("STRIPE_API_KEY=localhost:8443"); err != nil || b.Port != 8443 {
		t.Fatalf("with port = %+v, %v", b, err)
	}
	for _, bad := range []string{"STRIPE_API_KEY", "=host", "1BAD=host", "STRIPE_API_KEY=*.stripe.com", "STRIPE_API_KEY=h:0", "STRIPE_API_KEY=https://x/y"} {
		if _, err := ta.ParseCredential(bad); err == nil {
			t.Errorf("ParseCredential(%q) accepted", bad)
		}
	}
	_, err = ta.ParseCredential("STRIPE_API_KEY=https://api.stripe.com")
	wantErr(t, err, "name a host, not a URL")
	env, err := ParseEnv([]string{"A=1", "B=x=y"})
	if err != nil || env["A"] != "1" || env["B"] != "x=y" {
		t.Fatalf("ParseEnv = %v, %v", env, err)
	}
	if _, err := ParseEnv([]string{"no-equals"}); err == nil {
		t.Fatal("bad env accepted")
	}
}

// TestPrintModeEveryHarness: each harness's own headless switch in the
// pass-through arguments makes a detached run acceptable without --prompt,
// and every registered harness has a hint naming it.
func TestPrintModeEveryHarness(t *testing.T) {
	for name, args := range map[string][]string{
		"claudecode": {"-p", "x"}, "codex": {"exec", "x"}, "opencode": {"run", "x"}, "copilot": {"--prompt=x"},
		"amp": {"-x", "x"}, "cursor": {"--print", "x"}, "kiro": {"--no-interactive", "x"}, "devin": {"-p", "x"},
		"hermes": {"chat", "-q", "x"}, "openhands": {"--headless", "-t", "x"}, "antigravity": {"-p", "x"}, "omnigent": {"--prompt=x"},
	} {
		if spec := harnessSpec(t, name); !printMode(spec, args) || printMode(spec, []string{"--model", "m"}) {
			t.Errorf("%s: printMode(%q) is wrong", name, args)
		}
	}
	for _, name := range harness.Names() {
		if printHint(harnessSpec(t, name)) == "" {
			t.Errorf("registered harness %s has no headless switch", name)
		}
	}
}
