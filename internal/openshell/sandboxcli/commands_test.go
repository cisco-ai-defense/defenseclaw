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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

func sampleSandbox(name string) sandboxapi.Sandbox {
	return sandboxapi.Sandbox{
		Name: name, ID: "sb-" + name, Harness: "claudecode", HarnessName: "Claude Code", Phase: "ready", Profile: "open",
		Pack: "open", NetworkMode: "open", Yolo: true, WorkdirMode: "mount", Project: "/home/u/proj", Workdir: "/work/proj",
		UptimeSeconds: 3700, Launch: sandboxapi.Launch{Yolo: true}, TamperTier: "managed", HookContract: "claude-code-hooks-v1",
		Hooks:  sandboxapi.HookCoverage{LastHookAt: time.Now(), HookRequests: 9, ToolCalls: 4, ToolBlocked: 1, LastBlocked: "marker"},
		Egress: sandboxapi.EgressStats{Destinations: 3, Blocked: 1, BytesUp: 2048, BytesDown: 1 << 20},
	}
}

func TestListAndStatus(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.add(sampleSandbox("b-box"))
	ta.daemon.add(sampleSandbox("a-box"))
	if err := ta.List(context.Background(), OutputText); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	if !strings.Contains(out, "NAME") || strings.Index(out, "a-box") > strings.Index(out, "b-box") || !strings.Contains(out, "4 calls, 1 blocked") || !strings.Contains(out, "1h01m") {
		t.Fatalf("list:\n%s", out)
	}
	ta.out.Reset()
	if err := ta.List(context.Background(), OutputJSON); err != nil {
		t.Fatal(err)
	}
	var list struct{ Sandboxes []sandboxapi.Sandbox }
	if err := json.Unmarshal(ta.out.Bytes(), &list); err != nil || len(list.Sandboxes) != 2 || list.Sandboxes[0].Name != "a-box" {
		t.Fatalf("list json = %s, %v", ta.out.String(), err)
	}
	ta.out.Reset()
	if err := ta.Status(context.Background(), "", OutputText); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "Sandboxes       on") || !strings.Contains(out, "openshell 0.1.1") {
		t.Fatalf("status:\n%s", out)
	}
	ta.out.Reset()
	if err := ta.Status(context.Background(), "a-box", OutputText); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"skip-permissions on", "managed tier", "9 requests, 4 tool calls, 1 blocked", "2.0 KiB up, 1.0 MiB down"} {
		if !strings.Contains(ta.output(), want) {
			t.Errorf("status a-box lacks %q:\n%s", want, ta.output())
		}
	}
	ta.out.Reset()
	if err := ta.Status(context.Background(), "a-box", OutputJSON); err != nil {
		t.Fatal(err)
	}
	var sb sandboxapi.Sandbox
	if err := json.Unmarshal(ta.out.Bytes(), &sb); err != nil || sb.Name != "a-box" {
		t.Fatalf("status json: %v", err)
	}
	if err := ta.Status(context.Background(), "missing", OutputText); err == nil {
		t.Fatal("status of a missing sandbox succeeded")
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
	}
	if err := ta.Activity(context.Background(), ActivityOptions{Sandbox: "box"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(ta.output()), "\n")
	want := []string{
		"12:01:02 ✓ registry.npmjs.org",
		"12:01:02 ✗ webhook.site (exfil destination)  → unblock: defenseclaw sandbox unblock webhook.site --sandbox box",
		"12:01:02 ✗ tool Bash blocked: E2E marker",
		"12:01:02 ? ask ap-1: 10.0.0.5:5432  → defenseclaw sandbox approve box ap-1",
		"12:01:02 ⚠ quarantined a new git repository at x/.git",
		"12:01:02 ✗ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked (OpenShell refused the hooks' connections). Run: defenseclaw sandbox doctor",
		"12:01:02 ✓ DefenseClaw hooks reach the daemon again",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("activity =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	ta.out.Reset()
	if err := ta.Activity(context.Background(), ActivityOptions{Output: OutputJSON}); err != nil {
		t.Fatal(err)
	}
	var got struct{ Events []sandboxapi.ActivityEvent }
	if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil || len(got.Events) != 7 {
		t.Fatalf("activity json: %v %s", err, ta.output())
	}
	ta.out.Reset()
	if err := ta.Activity(context.Background(), ActivityOptions{Follow: true, Sandbox: "box"}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(ta.output(), "\n"); n != 7 {
		t.Fatalf("followed %d events:\n%s", n, ta.output())
	}
}

func TestApprovalsAndDecisions(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.approvals = []sandboxapi.Approval{{ID: "ap-1", Sandbox: "box", Kind: "host_port", Host: "127.0.0.1", Port: 5432, Risky: true,
		Reason: "a door into your machine", Status: sandboxapi.ApprovalPending}}
	if err := ta.Approvals(context.Background(), ApprovalsOptions{}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "ap-1") || !strings.Contains(out, "127.0.0.1:5432") || !strings.Contains(out, "risky") {
		t.Fatalf("approvals:\n%s", out)
	}
	ta.out.Reset()
	// An ask for several ports shows every one approving opens.
	ta.daemon.approvals[0].Endpoints = []sandboxapi.ApprovalEndpoint{{Host: "127.0.0.1", Port: 5432}, {Host: "127.0.0.1", Port: 6379}}
	if err := ta.Approvals(context.Background(), ApprovalsOptions{}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "127.0.0.1:5432,6379") {
		t.Fatalf("approvals with two ports:\n%s", out)
	}
	ta.out.Reset()
	if err := ta.Approvals(context.Background(), ApprovalsOptions{Output: OutputJSON}); err != nil {
		t.Fatal(err)
	}
	var list struct{ Approvals []sandboxapi.Approval }
	if err := json.Unmarshal(ta.out.Bytes(), &list); err != nil || len(list.Approvals) != 1 {
		t.Fatalf("approvals json: %v", err)
	}
	if err := ta.Decide(context.Background(), DecideOptions{Sandbox: "other", ID: "ap-1", Approve: true}); err == nil ||
		!strings.Contains(err.Error(), "has no pending ask") {
		t.Fatalf("approve for the wrong sandbox = %v", err)
	}
	if err := ta.Decide(context.Background(), DecideOptions{Sandbox: "box", ID: "ap-1", Approve: true, Always: true}); err != nil {
		t.Fatal(err)
	}
	calls := ta.daemon.callsTo("POST", sandboxapi.PathApprovals+"/ap-1")
	if len(calls) != 1 || !strings.Contains(string(calls[0].Body), `"decision":"approve"`) || !strings.Contains(string(calls[0].Body), `"always":true`) {
		t.Fatalf("decide calls = %+v", calls)
	}
	if out := ta.output(); !strings.Contains(out, "approved ap-1") || !strings.Contains(out, "next quiet moment") || !strings.Contains(out, "kept for future sandboxes") {
		t.Fatalf("decide output:\n%s", out)
	}
	if err := ta.Decide(context.Background(), DecideOptions{Sandbox: "box", ID: "ap-1"}); err != nil {
		t.Fatal(err)
	}
	if calls := ta.daemon.callsTo("POST", sandboxapi.PathApprovals+"/ap-1"); !strings.Contains(string(calls[1].Body), `"decision":"reject"`) {
		t.Fatalf("reject body = %s", calls[1].Body)
	}
}

func TestUnblock(t *testing.T) {
	ta := newTestApp(t, "")
	if err := ta.Unblock(context.Background(), UnblockOptions{Host: "webhook.site"}); err == nil {
		t.Fatal("an unscoped unblock was accepted")
	}
	if err := ta.Unblock(context.Background(), UnblockOptions{Host: "webhook.site", Sandbox: "box", Always: true}); err == nil {
		t.Fatal("--sandbox with --always was accepted")
	}
	if err := ta.Unblock(context.Background(), UnblockOptions{Host: "webhook.site", Sandbox: "box"}); err != nil {
		t.Fatal(err)
	}
	if err := ta.Unblock(context.Background(), UnblockOptions{Host: "paste.example", Always: true}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "unblocked webhook.site in box") || !strings.Contains(out, "unblocked paste.example for every sandbox") {
		t.Fatalf("output:\n%s", out)
	}
	ta.daemon.errors["POST "+sandboxapi.PathEgressUnblock] = &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "egress.unblock", Admin: true}}
	err := ta.Unblock(context.Background(), UnblockOptions{Host: "x.example", Sandbox: "box"})
	if err == nil || err.Error() != "blocked by your organization's DefenseClaw policy: egress.unblock" {
		t.Fatalf("admin unblock = %v", err)
	}
}

func TestUndoPreviewThenRestore(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.daemon.add(sampleSandbox("box"))
	if err := ta.Undo(context.Background(), UndoOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	calls := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/undo")
	if len(calls) != 2 || !strings.Contains(string(calls[0].Body), `"preview":true`) || !strings.Contains(string(calls[1].Body), `"stop":true`) {
		t.Fatalf("undo calls = %+v", calls)
	}
	if out := ta.output(); !strings.Contains(out, "revert  README.md") || !strings.Contains(out, "restored: 1 file restored") {
		t.Fatalf("undo output:\n%s", out)
	}
	// No terminal and no --yes: the preview is shown, nothing restored.
	ta2 := newTestApp(t, "")
	ta2.IO.TTY = false
	ta2.daemon.add(sampleSandbox("box"))
	if err := ta2.Undo(context.Background(), UndoOptions{Name: "box"}); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("undo without a terminal = %v", err)
	}
	if n := len(ta2.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/undo")); n != 1 {
		t.Fatalf("undo calls without consent = %d", n)
	}
}

func TestUndoNamesWhatItCannotRestore(t *testing.T) {
	deps := workspace.IgnoredChange{Path: "node_modules/", Modified: 1, Executables: []string{"node_modules/.bin/tool"}, ExecutableCount: 1,
		Dependencies: true, Remedy: "delete it and reinstall the packages (for example `npm ci`)"}
	cache := workspace.IgnoredChange{Path: "calc/__pycache__/", Added: 1, Modified: 1, Removed: true, Remedy: "delete it; Python rebuilds it"}

	// Only changes undo cannot restore: no clean "nothing to undo".
	ta := newTestApp(t, "")
	ta.daemon.add(sampleSandbox("box"))
	ta.daemon.undo = sandboxapi.UndoResponse{Result: &workspace.UndoResult{Project: ta.project, Preview: true, Ignored: []workspace.IgnoredChange{deps}}}
	if err := ta.Undo(context.Background(), UndoOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	for _, want := range []string{
		"undo cannot restore node_modules/ (1 file added or changed during the session, including .bin/tool): delete it and reinstall the packages (for example `npm ci`)",
		"nothing else to undo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✓ nothing to undo") {
		t.Errorf("undo reported a clean folder:\n%s", out)
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/undo")); n != 1 {
		t.Errorf("undo calls = %d, want the preview only", n)
	}

	// With something to restore: the bytecode cache is listed as removed,
	// and the result repeats what was left.
	ta = newTestApp(t, "y\n")
	ta.daemon.add(sampleSandbox("box"))
	ta.daemon.undo = sandboxapi.UndoResponse{Result: &workspace.UndoResult{Project: ta.project,
		Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}}, Ignored: []workspace.IgnoredChange{cache, deps}}}
	if err := ta.Undo(context.Background(), UndoOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	out = ta.output()
	for _, want := range []string{
		"remove  2 files the session wrote to calc/__pycache__/ (a Python bytecode cache)",
		"undo cannot restore node_modules/",
		"restored: 1 file restored",
		"not restored (see above): node_modules/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "undo cannot restore calc/__pycache__/") {
		t.Errorf("the removed bytecode cache is reported as unrestorable:\n%s", out)
	}
}

func TestReviewAndDelete(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.add(sampleSandbox("box"))
	ta.daemon.review = sandboxapi.ReviewResponse{Summary: "8 files changed (+212 −37)",
		RiskLine: "⚠ Changed files that can run code on your machine: package.json#scripts.postinstall  → review before running",
		Report: &workspace.ReviewReport{FilesChanged: 8, Flags: []workspace.Flag{{Path: "package.json", Label: "package.json#scripts.postinstall",
			Severity: workspace.SeverityHigh, Detail: "runs on npm install"}},
			Findings: []workspace.ScanFinding{{Path: "config/dev.env", Scanner: "clawshield-secrets", RuleID: "aws-key",
				Severity: "critical", Title: "AWS access key", Location: "config/dev.env:3"}}}}
	if err := ta.Review(context.Background(), ReviewOptions{Name: "box", Diff: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"box: 8 files changed (+212 −37)", "package.json#scripts.postinstall — runs on npm install", "+changed",
		"  CRITICAL config/dev.env:3 — clawshield-secrets: AWS access key"} {
		if !strings.Contains(ta.output(), want) {
			t.Errorf("review lacks %q:\n%s", want, ta.output())
		}
	}
	if strings.Contains(ta.output(), "{Path:") {
		t.Errorf("review dumps a Go struct:\n%s", ta.output())
	}
	if err := ta.Delete(context.Background(), DeleteOptions{Names: []string{"box"}, Yes: true, KeepSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	calls := ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/box")
	if len(calls) != 1 || !strings.Contains(string(calls[0].Body), `"keep_snapshot":true`) {
		t.Fatalf("delete calls = %+v", calls)
	}
}

func TestExecAndLogs(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.add(sampleSandbox("box"))
	ta.IO.TTY = false
	ta.stream.answer = func(argv []string) (int, string) {
		cmd := sandboxCommand(argv)
		if cmd[0] == harness.SandboxEnvPath {
			cmd = cmd[1:]
		}
		switch {
		case cmd[0] == "tail":
			return 0, "log line\n"
		case isRunStatus(cmd):
			// The run started a minute ago; the sandbox's last hook is now.
			return 0, fmt.Sprintf("0\n%d\n", time.Now().Add(-time.Minute).Unix())
		case cmd[0] == "false":
			return 7, ""
		}
		return 0, ""
	}
	if err := ta.Exec(context.Background(), ExecOptions{Name: "box", Command: []string{"ls", "-la"}}); err != nil {
		t.Fatal(err)
	}
	var exit *ExitError
	if err := ta.Exec(context.Background(), ExecOptions{Name: "box", Command: []string{"false"}}); !errors.As(err, &exit) || exit.Code != 7 {
		t.Fatalf("exec false = %v", err)
	}
	if err := ta.Logs(context.Background(), LogsOptions{Name: "box", Lines: 50}); err != nil {
		t.Fatal(err)
	}
	cmds := ta.stream.commands()
	if !slices.Contains(cmds, harness.SandboxEnvPath+" ls -la") || slices.Contains(cmds, "ls -la") || !slices.Contains(cmds, "tail -n 50 "+RunDir+"/latest.log") || !slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
		return isRunStatus(sandboxCommand(argv))
	}) {
		t.Fatalf("commands = %q", cmds)
	}
	if out := ta.output(); !strings.Contains(out, "log line") || !strings.Contains(out, "exited with status 0") || strings.Contains(out, "not reaching") {
		t.Fatalf("logs output:\n%s", out)
	}
	if err := ta.Logs(context.Background(), LogsOptions{Name: "box", Follow: true}); err != nil {
		t.Fatal(err)
	}
	if cmds := ta.stream.commands(); cmds[len(cmds)-1] != "tail -n 200 -F "+RunDir+"/latest.log" {
		t.Fatalf("follow = %q", cmds[len(cmds)-1])
	}
}

func TestPullCopyModeToBranch(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("copybox")
	sb.WorkdirMode, sb.Workdir, sb.Phase = "copy", "/sandbox/work/proj", "stopped"
	ta.daemon.add(sb)
	if err := ta.Pull(context.Background(), PullOptions{Name: "copybox", Branch: true}); err != nil {
		t.Fatalf("Pull: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/copybox/start")); n != 1 {
		t.Fatalf("a stopped sandbox was not started for the pull (%d)", n)
	}
	if !slices.Equal(ta.copy.steps, []string{"pull copybox", "apply branch"}) {
		t.Fatalf("steps = %v", ta.copy.steps)
	}
	reports := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/copybox/workspace")
	if len(reports) != 1 || !strings.Contains(string(reports[0].Body), `"pull_mode":"branch"`) || !strings.Contains(string(reports[0].Body), `"lines_added":4`) {
		t.Fatalf("report = %+v", reports)
	}
	if err := ta.Pull(context.Background(), PullOptions{Name: "copybox", Apply: true, PatchOut: "x.patch"}); err == nil {
		t.Fatal("two modes were accepted")
	}
	mounted := sampleSandbox("mounted")
	ta.daemon.add(mounted)
	if err := ta.Pull(context.Background(), PullOptions{Name: "mounted", Apply: true}); err == nil || !strings.Contains(err.Error(), "works on your folder directly") {
		t.Fatalf("pull of a mounted sandbox = %v", err)
	}
	// Sensitive changes need consent.
	ta.copy.pull = &workspace.PullResult{Name: "copybox", Changes: []workspace.TreeChange{{Path: ".envrc", Status: "A"}},
		Review: workspace.ReviewReport{FilesChanged: 1, Flags: []workspace.Flag{{Path: ".envrc", Label: ".envrc", Severity: workspace.SeverityHigh}}}}
	ta.IO.TTY = false
	if err := ta.Pull(context.Background(), PullOptions{Name: "copybox", Apply: true}); err == nil || !strings.Contains(err.Error(), "--accept-sensitive") {
		t.Fatalf("sensitive pull without consent = %v", err)
	}
	if err := ta.Pull(context.Background(), PullOptions{Name: "copybox", Apply: true, AcceptSensitive: true}); err != nil {
		t.Fatal(err)
	}
	if last := ta.copy.apply[len(ta.copy.apply)-1]; last.Mode != workspace.ApplyMerge || !last.AcceptSensitive {
		t.Fatalf("apply = %+v", last)
	}
}

func copySandbox(name string) sandboxapi.Sandbox {
	sb := sampleSandbox(name)
	sb.WorkdirMode, sb.Workdir, sb.Phase = "copy", "/sandbox/work/proj", "stopped"
	return sb
}

func TestUndoCopyModeRevertsTheLastApply(t *testing.T) {
	undoCalls := func(ta *testApp) int { return len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/copybox/undo")) }

	// Nothing was applied: say so, not "never changed the folder".
	ta := newTestApp(t, "")
	ta.daemon.add(copySandbox("copybox"))
	if err := ta.Undo(context.Background(), UndoOptions{Name: "copybox"}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "nothing to undo: copybox works on a copy, and `pull --apply` has not brought its work into your folder") {
		t.Fatalf("output:\n%s", out)
	}
	if undoCalls(ta) != 0 {
		t.Fatal("a copy-mode undo went to the daemon's mount undo")
	}

	// An apply: preview, consent, revert, report.
	ta = newTestApp(t, "y\n")
	ta.daemon.add(copySandbox("copybox"))
	ta.copy.undo = &workspace.UndoApplyResult{Name: "copybox", Project: ta.project, PreApplyRef: "refs/defenseclaw/copy/copybox/pre-apply",
		Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}, {Path: "NEW.md", Status: "D"}}}
	if err := ta.Undo(context.Background(), UndoOptions{Name: "copybox"}); err != nil {
		t.Fatalf("Undo: %v\n%s", err, ta.output())
	}
	out := ta.output()
	for _, want := range []string{"Undo will revert the last `pull --apply` of copybox", "revert  README.md", "remove  NEW.md",
		"edits you made since the apply stay", "reverted the last apply: 2 paths"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !slices.Equal(ta.copy.steps, []string{"undo-apply copybox preview=true", "undo-apply copybox preview=false"}) {
		t.Errorf("steps = %v", ta.copy.steps)
	}
	reports := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/copybox/workspace")
	if len(reports) != 1 || !strings.Contains(string(reports[0].Body), `"operation":"undo"`) || !strings.Contains(string(reports[0].Body), `"file_count":2`) {
		t.Errorf("reports = %+v", reports)
	}
	if undoCalls(ta) != 0 {
		t.Error("a copy-mode undo went to the daemon's mount undo")
	}

	// Edits since the apply overlap it: refuse, change nothing, and say
	// where the old folder is.
	ta = newTestApp(t, "y\n")
	ta.daemon.add(copySandbox("copybox"))
	ta.copy.undo = &workspace.UndoApplyResult{Name: "copybox", Project: ta.project, PreApplyRef: "refs/defenseclaw/copy/copybox/pre-apply",
		Conflicts: []string{"README.md"}}
	err := ta.Undo(context.Background(), UndoOptions{Name: "copybox"})
	if err == nil || !strings.Contains(err.Error(), "you also changed README.md since the apply") || !strings.Contains(err.Error(), "diff refs/defenseclaw/copy/copybox/pre-apply") {
		t.Fatalf("conflicting undo = %v", err)
	}
	if len(ta.copy.steps) != 1 {
		t.Errorf("a conflicting undo went past the preview: %v", ta.copy.steps)
	}

	// -o json: one document on stdout.
	ta = newTestApp(t, "y\n")
	ta.daemon.add(copySandbox("copybox"))
	ta.copy.undo = &workspace.UndoApplyResult{Name: "copybox", Project: ta.project, Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}}}
	if err := ta.Undo(context.Background(), UndoOptions{Name: "copybox", Output: OutputJSON}); err != nil {
		t.Fatal(err)
	}
	var res sandboxapi.UndoResponse
	if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Apply == nil || !res.Apply.Undone {
		t.Fatalf("stdout is not one undo response (%v):\n%s", err, ta.out.String())
	}
}

func TestPullApplyThatIsAlreadyInTheFolder(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.add(copySandbox("copybox"))
	ta.copy.applied = &workspace.ApplyResult{Mode: workspace.ApplyMerge, UpToDate: true}
	if err := ta.Pull(context.Background(), PullOptions{Name: "copybox", Apply: true}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	if !strings.Contains(out, "nothing to apply: ") || !strings.Contains(out, "already has these changes") || strings.Contains(out, "applied 0 changes") {
		t.Fatalf("output:\n%s", out)
	}
}

// With -o json stdout holds exactly one JSON document; the preview, the
// prompt and the progress lines go to stderr.
func TestUndoJSONKeepsStdoutParseable(t *testing.T) {
	cases := []struct {
		name  string
		input string
		setup func(*testApp)
		// restored is whether stdout is the restore's response rather
		// than the preview's.
		restored bool
		undos    int
		stderr   []string
	}{
		{"restore", "y\n", nil, true, 2, []string{"revert  README.md", "Restore "}},
		{"declined", "n\n", nil, false, 1, []string{"revert  README.md", "nothing changed"}},
		{"nothing to undo", "", func(ta *testApp) {
			ta.daemon.undo = sandboxapi.UndoResponse{Result: &workspace.UndoResult{Project: ta.project, Preview: true}}
		}, false, 1, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, c.input)
			ta.daemon.add(sampleSandbox("box"))
			if c.setup != nil {
				c.setup(ta)
			}
			if err := ta.Undo(context.Background(), UndoOptions{Name: "box", Output: OutputJSON}); err != nil {
				t.Fatal(err)
			}
			var res sandboxapi.UndoResponse
			if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Result == nil || res.Stopped != c.restored {
				t.Fatalf("stdout is not one undo response (%v):\n%s", err, ta.output())
			}
			if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/undo")); n != c.undos {
				t.Fatalf("undo calls = %d, want %d", n, c.undos)
			}
			for _, want := range c.stderr {
				if !strings.Contains(ta.err.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, ta.err.String())
				}
			}
			if ta.IO.Out != io.Writer(ta.out) {
				t.Fatal("stdout was not restored after the command")
			}
		})
	}
}

func TestPullJSONKeepsStdoutParseable(t *testing.T) {
	cases := []struct {
		name  string
		opts  PullOptions
		setup func(*testApp)
		// review is whether stdout is the pull's result rather than the
		// apply's.
		review  bool
		mode    workspace.ApplyMode
		applied bool
		stderr  []string
	}{
		{"review", PullOptions{}, nil, true, "", false, []string{"starting copybox", "Pulling copybox's work"}},
		{"branch", PullOptions{Branch: true}, nil, false, workspace.ApplyBranch, true,
			[]string{"Pulling copybox's work", "copybox: ", "M main.go", "the changes are on branch"}},
		{"nothing to bring back", PullOptions{Apply: true}, func(ta *testApp) {
			ta.copy.pull = &workspace.PullResult{Name: "copybox"}
		}, false, workspace.ApplyMerge, false, []string{"nothing to bring back"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			sb := sampleSandbox("copybox")
			sb.WorkdirMode, sb.Workdir, sb.Phase = "copy", "/sandbox/work/proj", "stopped"
			ta.daemon.add(sb)
			if c.setup != nil {
				c.setup(ta)
			}
			o := c.opts
			o.Name, o.Output = "copybox", OutputJSON
			if err := ta.Pull(context.Background(), o); err != nil {
				t.Fatalf("Pull: %v\n%s", err, ta.err.String())
			}
			if c.review {
				var res workspace.PullResult
				if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Name != "copybox" {
					t.Fatalf("stdout is not one pull result (%v):\n%s", err, ta.output())
				}
			} else {
				var res workspace.ApplyResult
				if err := json.Unmarshal(ta.out.Bytes(), &res); err != nil || res.Mode != c.mode || res.Applied != c.applied {
					t.Fatalf("stdout is not one apply result (%v):\n%s", err, ta.output())
				}
			}
			for _, want := range c.stderr {
				if !strings.Contains(ta.err.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, ta.err.String())
				}
			}
			if ta.IO.Out != io.Writer(ta.out) {
				t.Fatal("stdout was not restored after the command")
			}
		})
	}
}

// writeConfig writes a minimal valid v8 config.yaml.
func writeConfig(t *testing.T, ta *testApp, extra string) {
	t.Helper()
	body := "config_version: 8\ndata_dir: " + ta.Cfg.DataDir + "\ngateway:\n  host: 127.0.0.1\n  api_port: 18970\nopenshell:\n  enabled: true\n" + extra
	if err := os.WriteFile(ta.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadConfig(t *testing.T, ta *testApp) *config.Config {
	t.Helper()
	c, err := config.LoadRuntimeV8File(ta.ConfigPath)
	if err != nil {
		t.Fatalf("load %s: %v", ta.ConfigPath, err)
	}
	return c
}

func TestPolicyEditWritesConfig(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	if err := ta.PolicyEdit(context.Background(), "allow", []string{"Registry.NPMjs.org", "*.pypi.org"}); err != nil {
		t.Fatal(err)
	}
	if err := ta.PolicyEdit(context.Background(), "block", []string{"paste.example"}); err != nil {
		t.Fatal(err)
	}
	c := loadConfig(t, ta)
	if !slices.Equal(c.OpenShell.Egress.Allow, []string{"registry.npmjs.org", "*.pypi.org"}) || !slices.Equal(c.OpenShell.Egress.Block, []string{"paste.example"}) {
		t.Fatalf("egress = %+v", c.OpenShell.Egress)
	}
	before, _ := os.ReadFile(ta.ConfigPath)
	if err := ta.PolicyEdit(context.Background(), "allow", []string{"*"}); err == nil {
		t.Fatal("a catch-all allow was accepted")
	}
	if after, _ := os.ReadFile(ta.ConfigPath); string(after) != string(before) {
		t.Fatal("a refused edit changed config.yaml")
	}
	ta.Cfg.DeploymentMode = "managed_enterprise"
	if err := ta.PolicyEdit(context.Background(), "block", []string{"x.example"}); err == nil || !strings.Contains(err.Error(), sandboxapi.AdminMessage) {
		t.Fatalf("managed edit = %v", err)
	}
}

func TestPolicyShowExplainSuggest(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Admin = sandboxapi.AdminStatus{Configured: true, Authority: "advisory", Detail: "config.yaml is yours"}
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{Key: "profile", Value: "balanced", Source: "admin",
		Origin: "openshell.admin.min_profile", Requested: "open"})
	if err := ta.PolicyShow(context.Background(), PolicyOptions{Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "Pack          open (builtin:open) sha256:") || !strings.Contains(out, "advisory: config.yaml is yours") {
		t.Fatalf("show:\n%s", out)
	}
	if q := ta.daemon.callsTo("GET", sandboxapi.PathPolicyExplain); len(q) != 1 || !strings.Contains(q[0].Query, "harness=claudecode") {
		t.Fatalf("explain query = %+v", q)
	}
	ta.out.Reset()
	if err := ta.PolicyExplain(context.Background(), PolicyOptions{Sandbox: "box"}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "balanced (asked for open)") || !strings.Contains(out, "openshell.admin.min_profile") {
		t.Fatalf("explain:\n%s", out)
	}
	if strings.Contains(ta.output(), "prints them in full") {
		t.Fatalf("short values were reported as shortened:\n%s", ta.output())
	}
	ta.out.Reset()
	var masks []string
	for i := range 40 {
		masks = append(masks, fmt.Sprintf("**/secret-%02d.pem", i))
	}
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{Key: "workdir.masks",
		Value: strings.Join(masks, ", "), Source: "pack", Origin: "pack open"})
	if err := ta.PolicyExplain(context.Background(), PolicyOptions{Sandbox: "box"}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	for _, line := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(line); n > 120 {
			t.Errorf("explain line is %d columns wide: %q", n, line)
		}
	}
	if !strings.Contains(out, "**/secret-00.pem, **/secret-01.pem, … (+38 more)") ||
		!strings.Contains(out, "defenseclaw sandbox policy explain -o json prints them in full") {
		t.Fatalf("explain did not shorten the long list:\n%s", out)
	}
	ta.out.Reset()
	ta.daemon.events = []sandboxapi.ActivityEvent{
		{Kind: sandboxapi.ActivityEgressAllowed, Host: "registry.npmjs.org"}, {Kind: sandboxapi.ActivityEgressAllowed, Host: "registry.npmjs.org"},
		{Kind: sandboxapi.ActivityEgressAllowed, Host: "docs.python.org"}, {Kind: sandboxapi.ActivityEgressBlocked, Host: "webhook.site"},
	}
	if err := ta.PolicySuggest(context.Background(), SuggestOptions{}); err != nil {
		t.Fatal(err)
	}
	out = ta.output()
	if !strings.Contains(out, "      - docs.python.org  # 1\n      - registry.npmjs.org  # 2") || !strings.Contains(out, "Blocked (not suggested): webhook.site") {
		t.Fatalf("suggest:\n%s", out)
	}
}

func TestPackCommands(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.PackDir = filepath.Join(ta.Cfg.DataDir, "policies", "sandbox")
	if err := ta.PackList(PackOptions{}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	for _, name := range []string{"open", "balanced", "strict", "sha256:"} {
		if !strings.Contains(out, name) {
			t.Fatalf("pack list lacks %q:\n%s", name, out)
		}
	}
	ta.out.Reset()
	if err := ta.PackList(PackOptions{Output: OutputJSON}); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Packs []struct {
			Name   string
			Digest string
		}
	}
	if err := json.Unmarshal(ta.out.Bytes(), &list); err != nil || len(list.Packs) < 3 || !strings.HasPrefix(list.Packs[0].Digest, "sha256:") {
		t.Fatalf("pack list json: %v %s", err, ta.output())
	}
	ta.out.Reset()
	if err := ta.PackShow("strict", PackOptions{}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "# digest sha256:") || !strings.Contains(out, "name: strict") {
		t.Fatalf("pack show:\n%s", out)
	}
	bad := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nname: bad\nunknown_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ta.PackValidate(bad); err == nil {
		t.Fatal("an invalid pack validated")
	}
}

func TestEnableDisableWrappers(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.env["SHELL"] = "/bin/zsh"
	if err := ta.Enable(WrapperOptions{Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	if err := ta.Enable(WrapperOptions{Harness: "codex", Shell: "bash"}); err != nil {
		t.Fatal(err)
	}
	zshrc, _ := os.ReadFile(filepath.Join(ta.home, ".zshrc"))
	bashrc, _ := os.ReadFile(filepath.Join(ta.home, ".bashrc"))
	if !strings.Contains(string(zshrc), "'/usr/local/bin/defenseclaw-gateway' sandbox run claude") && !strings.Contains(string(zshrc), "/usr/local/bin/defenseclaw-gateway sandbox run claude") {
		t.Fatalf(".zshrc:\n%s", zshrc)
	}
	if !strings.Contains(string(bashrc), "sandbox run codex") {
		t.Fatalf(".bashrc:\n%s", bashrc)
	}
	if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Wrappers, []string{"claudecode", "codex"}) {
		t.Fatalf("openshell.wrappers = %v", c.OpenShell.Wrappers)
	}
	if err := ta.Disable(WrapperOptions{Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	zshrc, _ = os.ReadFile(filepath.Join(ta.home, ".zshrc"))
	if strings.Contains(string(zshrc), "sandbox run") {
		t.Fatalf(".zshrc after disable:\n%s", zshrc)
	}
	if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Wrappers, []string{"codex"}) {
		t.Fatalf("openshell.wrappers = %v", c.OpenShell.Wrappers)
	}
	if err := ta.Enable(WrapperOptions{Harness: "claude", Shell: "tcsh"}); err == nil {
		t.Fatal("an unsupported shell was accepted")
	}
}

func TestResolveHarness(t *testing.T) {
	for in, want := range map[string]string{"claude": "claudecode", "claudecode": "claudecode", "claude-code": "claudecode",
		"Claude Code": "claudecode", "codex": "codex", "CODEX": "codex"} {
		spec, err := ResolveHarness(in)
		if err != nil || spec.Name != want {
			t.Errorf("ResolveHarness(%q) = %v, %v; want %s", in, spec, err, want)
		}
	}
	if _, err := ResolveHarness("vim"); err == nil || !strings.Contains(err.Error(), "claude (Claude Code)") {
		t.Fatalf("unknown harness error = %v", err)
	}
}

func TestDetectLLM(t *testing.T) {
	claude, _ := harness.Get("claudecode")
	codex, _ := harness.Get("codex")
	opencode, _ := harness.Get("opencode")
	copilot, _ := harness.Get("copilot")
	kiro, _ := harness.Get("kiro")
	hermes, _ := harness.Get("hermes")
	openhands, _ := harness.Get("openhands")
	antigravity, _ := harness.Get("antigravity")
	omnigent, _ := harness.Get("omnigent")
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
		{"bedrock not automatic", claude, map[string]string{EnvBedrockToken: "b"}, "", "auto", "", "", false},
		{"codex env", codex, map[string]string{"CODEX_API_KEY": "c"}, "", "", profiles.OpenAIID, "OPENAI_API_KEY", false},
		{"codex auth.json", codex, nil, `{"OPENAI_API_KEY":"from-file"}`, "", profiles.OpenAIID, "~/.codex/auth.json", false},
		{"codex chatgpt login", codex, nil, `{"OPENAI_API_KEY":null,"tokens":{"id_token":"x"}}`, "", "", "", false},
		{"none", claude, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "none", "", "", false},
		{"explicit missing", claude, nil, "", "anthropic", "", "", true},
		{"wrong provider", codex, nil, "", "anthropic", "", "", true},
		{"opencode anthropic", opencode, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", profiles.OpenCodeAnthropicID, "ANTHROPIC_API_KEY", false},
		{"opencode openai", opencode, map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", profiles.OpenCodeOpenAIID, "OPENAI_API_KEY", false},
		{"opencode bedrock", opencode, map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.OpenCodeBedrockMantleID, EnvBedrockToken, false},
		{"copilot byok anthropic", copilot, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", profiles.CopilotAnthropicID, "ANTHROPIC_API_KEY", false},
		{"copilot has no openai", copilot, map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", "", "", true},
		{"kiro logs in inside", kiro, map[string]string{"ANTHROPIC_API_KEY": "k"}, "", "", "", "", false},
		{"hermes openai", hermes, map[string]string{"OPENAI_API_KEY": "k", "ANTHROPIC_API_KEY": "a"}, "", "", profiles.OpenAIID, "OPENAI_API_KEY", false},
		{"hermes anthropic", hermes, map[string]string{"ANTHROPIC_API_KEY": "a"}, "", "", profiles.AnthropicID, "ANTHROPIC_API_KEY", false},
		{"hermes bedrock", hermes, map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"openhands bedrock", openhands, map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"openhands openai", openhands, map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", profiles.OpenAIID, "OPENAI_API_KEY", false},
		{"antigravity gemini", antigravity, map[string]string{"GEMINI_API_KEY": "g"}, "", "", profiles.GeminiID, "GEMINI_API_KEY", false},
		{"antigravity has no openai", antigravity, map[string]string{"OPENAI_API_KEY": "k"}, "", "openai", "", "", true},
		{"antigravity signs in inside", antigravity, nil, "", "", "", "", false},
		{"omnigent bedrock", omnigent, map[string]string{EnvBedrockToken: "b"}, "", "bedrock", profiles.BedrockMantleOpenAIID, EnvBedrockToken, false},
		{"omnigent openai", omnigent, map[string]string{"OPENAI_API_KEY": "k"}, "", "", profiles.OpenAIID, "OPENAI_API_KEY", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			for k, v := range c.env {
				ta.env[k] = v
			}
			if c.auth != "" {
				if err := os.MkdirAll(filepath.Join(ta.home, ".codex"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(ta.home, ".codex", "auth.json"), []byte(c.auth), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ta.detectLLM(c.spec, c.choice, "", nil)
			if (err != nil) != c.wantErr {
				t.Fatalf("detectLLM err = %v, want error %t", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			switch {
			case c.profile == "" && got.Credential != nil:
				t.Fatalf("credential = %+v, want none", got.Credential)
			case c.profile != "" && (got.Credential == nil || got.Credential.Profile != c.profile || got.Source != c.source):
				t.Fatalf("detectLLM = %+v, want %s from %s", got, c.profile, c.source)
			}
			if c.name == "copilot byok anthropic" && got.Credential.Credentials["COPILOT_PROVIDER_API_KEY"] != "k" {
				t.Fatalf("copilot credentials = %v", got.Credential.Credentials)
			}
			if c.name == "claude bedrock" && got.Credential.BedrockRegion != "us-west-2" {
				t.Fatalf("region = %q", got.Credential.BedrockRegion)
			}
		})
	}
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
// and the hint names it.
func TestPrintModeEveryHarness(t *testing.T) {
	for name, args := range map[string][]string{
		"claudecode": {"-p", "x"}, "codex": {"exec", "x"}, "opencode": {"run", "x"}, "copilot": {"--prompt=x"},
		"amp": {"-x", "x"}, "cursor": {"--print", "x"}, "kiro": {"--no-interactive", "x"}, "devin": {"-p", "x"},
		"hermes": {"chat", "-q", "x"}, "openhands": {"--headless", "-t", "x"}, "antigravity": {"-p", "x"}, "omnigent": {"--prompt=x"},
	} {
		spec, ok := harness.Get(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if !printMode(spec, args) || printMode(spec, []string{"--model", "m"}) {
			t.Errorf("%s: printMode(%q) is wrong", name, args)
		}
		if printHint(spec) == "" {
			t.Errorf("%s has no print hint", name)
		}
	}
	for _, name := range harness.Names() {
		spec, _ := harness.Get(name)
		if printHint(spec) == "" {
			t.Errorf("registered harness %s has no headless switch", name)
		}
	}
}
