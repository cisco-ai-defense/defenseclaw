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
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

func createRequest(t *testing.T, d *fakeDaemon) sandboxapi.CreateRequest {
	t.Helper()
	calls := d.callsTo("POST", sandboxapi.PathSandboxes)
	if len(calls) != 1 {
		t.Fatalf("create calls = %d (calls: %v)", len(calls), d.paths())
	}
	var req sandboxapi.CreateRequest
	if err := json.Unmarshal(calls[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRunMountSessionKeepsChanges(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.env["ANTHROPIC_API_KEY"] = "sk-test-not-a-secret"
	ta.env["STRIPE_API_KEY"] = "stripe-test-value"
	notice := "MCP: blocked the repository's servers repo-tool (mcp.project_servers: block; a sandbox pack with mcp.project_servers: allow runs them)"
	ta.daemon.createMCP = &sandboxapi.MCPSummary{Imported: []string{"github", "linear"}, ProjectServers: "block", Project: []string{"repo-tool"}}
	ta.daemon.createWarnings = []string{notice}
	ta.term.during = func() {
		ta.daemon.mu.Lock()
		sb := ta.daemon.sandboxes["dc-claude-proj-1a2b"]
		sb.Hooks = sandboxapi.HookCoverage{ToolCalls: 57, ToolBlocked: 1, LastBlocked: "E2E marker command"}
		sb.Egress = sandboxapi.EgressStats{Destinations: 23, Blocked: 1}
		sb.NestedRepos = []sandboxapi.NestedRepo{{Kind: "repository", Path: "vendor/x/.git", Quarantined: "vendor/x/.git.defenseclaw-quarantine-1"}}
		ta.daemon.mu.Unlock()
	}
	err := ta.Run(context.Background(), RunOptions{
		Harness: "claude", Credentials: []string{"STRIPE_API_KEY=api.stripe.com"}, Env: []string{"FOO=bar"},
		Args: []string{"--model", "sonnet"},
	})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	req := createRequest(t, ta.daemon)
	if req.Harness != "claudecode" || req.Project != ta.project || req.Copy || req.LLM == nil ||
		req.LLM.Profile != profiles.AnthropicID || req.LLM.Credentials["ANTHROPIC_API_KEY"] != "sk-test-not-a-secret" ||
		len(req.Credentials) != 1 || req.Credentials[0].Host != "api.stripe.com" || req.Credentials[0].Value != "stripe-test-value" ||
		req.Env["FOO"] != "bar" {
		t.Fatalf("create request = %+v", req)
	}
	out := ta.output()
	for _, want := range []string{
		"Sandbox dc-claude-proj-1a2b · Claude Code · skip-permissions ON · network: open + blocklist",
		"Project   ~/proj → /work/proj (live)   undo point taken → `defenseclaw sandbox undo dc-claude-proj-1a2b` restores it",
		"Hidden    .env",
		"Protected .git/hooks .git/config (read-only)",
		"Model     sonnet · ANTHROPIC_API_KEY → api.anthropic.com only",
		"Secret    STRIPE_API_KEY → api.stripe.com only",
		"MCP       github ✓ · linear ✓",
		notice,
		"Session ended · 57 tool calls (1 blocked: E2E marker command) · 23 new sites contacted (1 request blocked) · 2 files changed (+10 −3)",
		"quarantined as vendor/x/.git.defenseclaw-quarantine-1",
		"Sandbox kept (stopped) → resume: defenseclaw sandbox connect dc-claude-proj-1a2b",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sk-test-not-a-secret") || strings.Contains(out, "stripe-test-value") {
		t.Fatal("a secret was printed")
	}
	// The probe ran before the harness, which got the terminal.
	if cmds := ta.stream.commands(); len(cmds) == 0 || cmds[0] != "true" {
		t.Fatalf("stream commands = %v, want the probe first", cmds)
	}
	if len(ta.term.runs) != 1 {
		t.Fatalf("terminal runs = %v", ta.term.runs)
	}
	argv := ta.term.runs[0]
	want := []string{"/usr/bin/openshell", "sandbox", "exec", "-g", "openshell", "--workspace", "default", "--name", "dc-claude-proj-1a2b",
		"--workdir", "/work/proj", "--tty", "--no-login-shell", "--", harness.ClaudeCodeLauncherPath, "--dangerously-skip-permissions", "--model", "sonnet"}
	argv[0] = "/usr/bin/openshell"
	if !slices.Equal(argv, want) {
		t.Fatalf("attach argv =\n%q\nwant\n%q", argv, want)
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/stop")); n != 1 {
		t.Fatalf("stop calls = %d; the kept sandbox must be stopped", n)
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/undo")); n != 0 {
		t.Fatal("undo ran although the user kept the changes")
	}
}

func TestRunMountSessionUndoAfterDiff(t *testing.T) {
	ta := newTestApp(t, "d\nu\n")
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Rm: true}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	reviews := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/review")
	if len(reviews) != 2 || !strings.Contains(string(reviews[1].Body), `"diff":true`) {
		t.Fatalf("review calls = %+v", reviews)
	}
	undo := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/undo")
	if len(undo) != 1 || !strings.Contains(string(undo[0].Body), `"stop":true`) {
		t.Fatalf("undo calls = %+v", undo)
	}
	if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b")); n != 1 {
		t.Fatalf("--rm delete calls = %d", n)
	}
	if out := ta.output(); !strings.Contains(out, "+changed") || !strings.Contains(out, "undone: 1 file restored") {
		t.Fatalf("output:\n%s", out)
	}
}

// Undo at the end of a session names what it could not restore.
func TestRunMountSessionUndoNamesWhatItCannotRestore(t *testing.T) {
	ta := newTestApp(t, "u\n")
	ta.daemon.undo = sandboxapi.UndoResponse{Result: &workspace.UndoResult{Project: ta.project,
		Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}},
		Ignored: []workspace.IgnoredChange{{Path: ".venv/", Modified: 1, Dependencies: true, Remedy: "delete it and create the virtual environment again"}}}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	for _, want := range []string{"undone: 1 file restored, except .venv/ (see below)",
		"undo cannot restore .venv/ (1 file added or changed during the session): delete it and create the virtual environment again"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRunHarnessExitStatusPropagates(t *testing.T) {
	ta := newTestApp(t, "")
	ta.term.code = 3
	ta.daemon.review = sandboxapi.ReviewResponse{Summary: "0 files changed (+0 −0)", Report: &workspace.ReviewReport{}}
	err := ta.Run(context.Background(), RunOptions{Harness: "claude"})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 3 {
		t.Fatalf("Run = %v, want exit status 3", err)
	}
}

// TestRunOffersChoicesForAFolderMountedLive pins that on a terminal a run
// whose folder another sandbox mounts live (here a kept, stopped Codex one)
// asks instead of failing: a copy by default, deleting that sandbox first,
// or nothing. Without a terminal the daemon's refusal names the command.
func TestRunOffersChoicesForAFolderMountedLive(t *testing.T) {
	setup := func(t *testing.T, input string) *testApp {
		ta := newTestApp(t, input)
		sb := sampleSandbox("dc-codex-proj-9z9z")
		sb.Harness, sb.HarnessName, sb.Phase, sb.Project = "codex", "Codex", "stopped", ta.project
		ta.daemon.add(sb)
		ta.daemon.review = sandboxapi.ReviewResponse{Summary: "0 files changed (+0 −0)", Report: &workspace.ReviewReport{}}
		return ta
	}
	creates := func(ta *testApp) []sandboxapi.CreateRequest {
		var out []sandboxapi.CreateRequest
		for _, c := range ta.daemon.callsTo("POST", sandboxapi.PathSandboxes) {
			var req sandboxapi.CreateRequest
			if err := json.Unmarshal(c.Body, &req); err != nil {
				t.Fatal(err)
			}
			out = append(out, req)
		}
		return out
	}
	t.Run("copy by default", func(t *testing.T) {
		ta := setup(t, "\n\n")
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
			t.Fatalf("Run: %v\n%s", err, ta.output())
		}
		if got := creates(ta); len(got) != 1 || !got[0].Copy {
			t.Fatalf("creates = %+v, want one copy-mode create", got)
		}
		if out := ta.output(); !strings.Contains(out, "Sandbox dc-codex-proj-9z9z (Codex, stopped) already mounts this folder live") {
			t.Fatalf("output:\n%s", out)
		}
	})
	t.Run("delete first", func(t *testing.T) {
		ta := setup(t, "d\ny\n\n")
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
			t.Fatalf("Run: %v\n%s", err, ta.output())
		}
		if n := len(ta.daemon.callsTo("DELETE", sandboxapi.PathSandboxes+"/dc-codex-proj-9z9z")); n != 1 {
			t.Fatalf("delete calls = %d", n)
		}
		if got := creates(ta); len(got) != 1 || got[0].Copy {
			t.Fatalf("creates = %+v, want one live-mount create", got)
		}
	})
	t.Run("quit", func(t *testing.T) {
		ta := setup(t, "q\n")
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
			t.Fatalf("Run: %v\n%s", err, ta.output())
		}
		if got := creates(ta); len(got) != 0 {
			t.Fatalf("creates = %+v, want none", got)
		}
		if out := ta.output(); !strings.Contains(out, "`defenseclaw sandbox delete dc-codex-proj-9z9z` frees the folder") {
			t.Fatalf("output:\n%s", out)
		}
	})
}

// TestRunSummaryWaitsForLateDenials pins that the session summary counts
// the denials OpenShell reports a moment after the session ends, so it
// agrees with a later status.
func TestRunSummaryWaitsForLateDenials(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.review = sandboxapi.ReviewResponse{Summary: "0 files changed (+0 −0)", Report: &workspace.ReviewReport{}}
	var armed atomic.Bool
	var late atomic.Int32
	late.Store(2)
	ta.daemon.onGet = func(sb *sandboxapi.Sandbox) {
		if armed.Load() && late.Add(-1) >= 0 {
			sb.Egress.Blocked++
		}
	}
	ta.term.during = func() { armed.Store(true) }
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if out := ta.output(); !strings.Contains(out, "0 new sites contacted (2 requests blocked)") {
		t.Fatalf("the summary missed the late denials:\n%s", out)
	}
}

// TestRunCarriesTheGitIdentity pins that the sandbox's git gets the
// identity the host's git uses for the project, so commits work and git
// does not look up the sandbox's host name for an address. --env wins, and
// a value no environment variable can carry is dropped.
func TestRunCarriesTheGitIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]string
		env    []string
		want   map[string]string
	}{
		{"the project's identity", map[string]string{"user.name": "Dana Dev", "user.email": "dana@example.org"}, nil,
			map[string]string{"GIT_AUTHOR_NAME": "Dana Dev", "GIT_COMMITTER_NAME": "Dana Dev",
				"GIT_AUTHOR_EMAIL": "dana@example.org", "GIT_COMMITTER_EMAIL": "dana@example.org"}},
		{"--env wins", map[string]string{"user.name": "Dana Dev", "user.email": "dana@example.org"},
			[]string{"GIT_AUTHOR_EMAIL=bot@example.org"},
			map[string]string{"GIT_AUTHOR_NAME": "Dana Dev", "GIT_COMMITTER_NAME": "Dana Dev",
				"GIT_AUTHOR_EMAIL": "bot@example.org", "GIT_COMMITTER_EMAIL": "dana@example.org"}},
		{"no identity", nil, nil, map[string]string{}},
		{"a malformed value", map[string]string{"user.name": "Dana\x1b[2J", "user.email": "dana@example.org"}, nil,
			map[string]string{"GIT_AUTHOR_EMAIL": "dana@example.org", "GIT_COMMITTER_EMAIL": "dana@example.org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.gitConfig = tc.config
			ta.daemon.review = sandboxapi.ReviewResponse{Summary: "0 files changed (+0 −0)", Report: &workspace.ReviewReport{}}
			if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Env: tc.env}); err != nil {
				t.Fatalf("Run: %v\n%s", err, ta.output())
			}
			req := createRequest(t, ta.daemon)
			got := map[string]string{}
			for k, v := range req.Env {
				if strings.HasPrefix(k, "GIT_") {
					got[k] = v
				}
			}
			if !maps.Equal(got, tc.want) {
				t.Fatalf("git environment = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunDetachedStartsInBackground(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", Detach: true, Prompt: "fix the failing tests"})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	cmds := ta.stream.commands()
	if len(cmds) != 2 || cmds[0] != "true" || !strings.HasPrefix(cmds[1], "sh -c set -eu") {
		t.Fatalf("stream commands = %q", cmds)
	}
	last := sandboxCommand(ta.stream.runs[1])
	tail := last[4:]
	want := []string{harness.ClaudeCodeLauncherPath, "--dangerously-skip-permissions", "-p", "fix the failing tests", "--output-format", "stream-json", "--verbose"}
	if !slices.Equal(tail, want) {
		t.Fatalf("detached harness argv = %q, want %q", tail, want)
	}
	if !strings.Contains(last[2], "d="+RunDir+"\n") || !strings.Contains(last[2], `"$d/latest.log"`) || !strings.Contains(last[2], "setsid") {
		t.Fatalf("detach script = %s", last[2])
	}
	if len(ta.term.runs) != 0 {
		t.Fatal("a detached run attached the terminal")
	}
	out := ta.output()
	if !strings.Contains(out, "defenseclaw sandbox logs dc-claude-proj-1a2b -f") {
		t.Fatalf("output:\n%s", out)
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/stop")); n != 0 {
		t.Fatal("a detached run was stopped")
	}
}

func TestRunHeadlessForegroundStreams(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.stream.answer = func(argv []string) (int, string) {
		if cmd := sandboxCommand(argv); len(cmd) > 0 && cmd[0] == harness.ClaudeCodeLauncherPath {
			return 0, "harness output\n"
		}
		return 0, ""
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"-p", "hello"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(ta.output(), "harness output") {
		t.Fatalf("output:\n%s", ta.output())
	}
	// Without a terminal the end of the session keeps the changes.
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/stop")); n != 1 {
		t.Fatalf("stop calls = %d", n)
	}
}

func TestRunRefusals(t *testing.T) {
	cases := []struct {
		name  string
		opts  RunOptions
		setup func(*testApp)
		want  string
	}{
		{"detach with rm", RunOptions{Harness: "claude", Detach: true, Rm: true, Prompt: "x"}, nil, "--rm cannot be combined with --detach"},
		{"detach without prompt", RunOptions{Harness: "claude", Detach: true}, nil, "needs a prompt"},
		{"no terminal", RunOptions{Harness: "codex"}, func(ta *testApp) { ta.IO.TTY = false }, "there is none"},
		{"unknown harness", RunOptions{Harness: "vim"}, nil, "unknown harness"},
		{"disabled", RunOptions{Harness: "claude"}, func(ta *testApp) { ta.daemon.status.Enabled = false }, "sandboxes are off"},
		{"unavailable", RunOptions{Harness: "claude"}, func(ta *testApp) {
			ta.daemon.status.Available, ta.daemon.status.Reason = false, "the OpenShell gateway is down"
		}, "the OpenShell gateway is down"},
		{"admin refuses harness", RunOptions{Harness: "codex"}, func(ta *testApp) {
			ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "harness", Fatal: true, Admin: true, Message: "codex is not an allowed harness"}}
		}, "blocked by your organization's DefenseClaw policy: harness"},
		{"daemon down", RunOptions{Harness: "claude"}, func(ta *testApp) { ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x") }, "daemon is not running"},
		{"windows", RunOptions{Harness: "claude"}, func(ta *testApp) { ta.GOOS = "windows" }, "Windows and WSL2 are not supported"},
		{"wsl2", RunOptions{Harness: "claude"}, func(ta *testApp) { ta.WSL = func() bool { return true } }, "Windows and WSL2 are not supported"},
		{"root", RunOptions{Harness: "claude"}, func(ta *testApp) { ta.Geteuid = func() int { return 0 } }, "not root"},
		{"bad credential", RunOptions{Harness: "claude", Credentials: []string{"NOPE=api.x.com"}}, nil, "is not set in this shell"},
		{"bad name", RunOptions{Harness: "claude", Name: "Bad_Name"}, nil, "--name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			if c.setup != nil {
				c.setup(ta)
			}
			err := ta.Run(context.Background(), c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run = %v, want %q", err, c.want)
			}
			if len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)) != 0 {
				t.Fatal("a refused run created a sandbox")
			}
		})
	}
}

func TestRunAdminCreateRefusalMessage(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "yolo", Admin: true, Message: "skip-permissions mode is not allowed"}}
	err := ta.Run(context.Background(), RunOptions{Harness: "claude"})
	if err == nil || err.Error() != "blocked by your organization's DefenseClaw policy: yolo (skip-permissions mode is not allowed)" {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunNestedRunsNatively(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["DEFENSECLAW_SANDBOX_ID"] = "sb-1"
	ta.API = nil
	ta.Cfg = nil
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"-c"}}); err != nil {
		t.Fatal(err)
	}
	if len(ta.execs) != 1 || !slices.Equal(ta.execs[0], []string{"/usr/bin/claude", "claude", "-c"}) {
		t.Fatalf("execs = %v", ta.execs)
	}
}

func TestRunSafeDropsBypassFlags(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "codex", Safe: true, Args: []string{"--yolo", "--search"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	argv := sandboxCommand(ta.term.runs[0])
	if slices.Contains(argv, "--yolo") || slices.Contains(argv, "--dangerously-bypass-approvals-and-sandbox") || !slices.Contains(argv, "--search") {
		t.Fatalf("safe argv = %q", argv)
	}
	if !strings.Contains(ta.output(), "--yolo is ignored") {
		t.Fatal("no notice for the dropped flag")
	}
	if req := createRequest(t, ta.daemon); !req.Safe {
		t.Fatal("--safe did not reach the daemon")
	}
}

// TestRunBannerShowsTheModel pins the banner's model: Codex on Bedrock runs
// the Mantle profile's default model (the daemon pins it in the run's
// managed config) unless -m picks another, and the banner names it either
// way (Mantle does not serve Codex's own default).
func TestRunBannerShowsTheModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "Model     openai.gpt-oss-20b (the default; -- -m MODEL picks another) · AWS_BEARER_TOKEN_BEDROCK → bedrock-mantle.us-east-1.api.aws only (the sandbox sees a placeholder)"},
		{"-m", []string{"-m", "openai.gpt-oss-120b"}, "Model     openai.gpt-oss-120b · AWS_BEARER_TOKEN_BEDROCK → bedrock-mantle.us-east-1.api.aws only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.env[EnvBedrockToken] = "bedrock-test-not-a-secret"
			ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
			if err := ta.Run(context.Background(), RunOptions{Harness: "codex", LLM: LLMBedrock, Args: tc.args}); err != nil {
				t.Fatalf("Run: %v\n%s", err, ta.output())
			}
			out := ta.output()
			if !strings.Contains(out, tc.want) || strings.Contains(out, "bedrock-test-not-a-secret") {
				t.Fatalf("output lacks %q (or prints the key):\n%s", tc.want, out)
			}
			// Mantle's multi-turn limit is said before the session starts.
			if !strings.Contains(out, "⚠ Bedrock Mantle rejects every turn after the first of a Codex conversation") {
				t.Fatalf("output lacks the Mantle caveat:\n%s", out)
			}
		})
	}
	// A one-prompt run has no second turn to warn about.
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.env[EnvBedrockToken] = "bedrock-test-not-a-secret"
	if err := ta.Run(context.Background(), RunOptions{Harness: "codex", LLM: LLMBedrock, Prompt: "fix the tests"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if out := ta.output(); strings.Contains(out, "rejects every turn") || !strings.Contains(out, "Model     openai.gpt-oss-20b") {
		t.Fatalf("headless banner:\n%s", out)
	}
	// Claude Code names the model its --model flag picks.
	ta = newTestApp(t, "")
	ta.env["ANTHROPIC_API_KEY"] = "sk-test-not-a-secret"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"--model", "sonnet"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out := ta.output(); !strings.Contains(out, "Model     sonnet · ANTHROPIC_API_KEY → api.anthropic.com only") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestRunProbeFailureDeletesSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	ta.stream.answer = func([]string) (int, string) { return 124, "timed out" }
	err := ta.Run(context.Background(), RunOptions{Harness: "claude"})
	if err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("Run = %v", err)
	}
	if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b")); n != 1 {
		t.Fatalf("delete calls = %d; a failed launch must not leave the sandbox", n)
	}
}

// A harness that fails to start leaves no sandbox behind, like a failed
// probe: nothing else deletes it (a detached run cannot take --rm).
func TestRunHarnessStartFailureDeletesSandbox(t *testing.T) {
	cases := []struct {
		name  string
		opts  RunOptions
		setup func(*testApp)
		want  string
	}{
		{"detach", RunOptions{Harness: "claude", Detach: true, Prompt: "fix the failing tests"}, func(ta *testApp) {
			ta.IO.TTY = false
			ta.stream.answer = func(argv []string) (int, string) {
				if cmd := sandboxCommand(argv); len(cmd) > 0 && cmd[0] == "sh" {
					return 1, "mkdir: read-only file system"
				}
				return 0, ""
			}
		}, "start Claude Code in the background: exit status 1"},
		{"attach", RunOptions{Harness: "claude"}, func(ta *testApp) {
			ta.term.startErr = errors.New("exec: openshell: permission denied")
		}, "permission denied"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			c.setup(ta)
			err := ta.Run(context.Background(), c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run = %v, want %q", err, c.want)
			}
			if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b")); n != 1 {
				t.Fatalf("delete calls = %d; a harness that did not start must not leave the sandbox", n)
			}
			if !strings.Contains(ta.output(), "removing sandbox dc-claude-proj-1a2b after the failure") {
				t.Fatalf("output:\n%s", ta.output())
			}
		})
	}
}

func TestRunCopySession(t *testing.T) {
	ta := newTestApp(t, "a\n")
	ta.env["OPENAI_API_KEY"] = "sk-openai-test"
	err := ta.Run(context.Background(), RunOptions{Harness: "codex", Copy: true, Name: "fix-tests"})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	req := createRequest(t, ta.daemon)
	if !req.Copy || req.Name != "fix-tests" || req.LLM == nil || req.LLM.Profile != profiles.OpenAIID {
		t.Fatalf("create request = %+v", req)
	}
	want := []string{"stage fix-tests", "upload fix-tests", "baseline fix-tests", "pull fix-tests", "apply apply"}
	if !slices.Equal(ta.copy.steps, want) {
		t.Fatalf("copy steps = %v, want %v", ta.copy.steps, want)
	}
	// Staging happens before the sandbox exists.
	if paths := ta.daemon.paths(); slices.Index(paths, "POST "+sandboxapi.PathSandboxes) < 0 {
		t.Fatalf("paths = %v", paths)
	}
	reports := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/fix-tests/workspace")
	if len(reports) != 2 || !strings.Contains(string(reports[0].Body), `"operation":"upload"`) ||
		!strings.Contains(string(reports[1].Body), `"pull_mode":"apply"`) {
		t.Fatalf("workspace reports = %+v", reports)
	}
	out := ta.output()
	for _, w := range []string{"Project   ~/proj → /sandbox/work/proj (copy)", "applied 1 change to ~/proj", "1 file changed (+4 −1)"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// The copy's workdir exists only once the copy is uploaded: a copy-mode run
// stages, creates the sandbox, uploads, sets the baseline, then probes the
// workdir, then starts the harness. Nothing runs in the workdir before the
// upload.
func TestRunCopyOrdersUploadBaselineProbeAttach(t *testing.T) {
	const workdir = "/sandbox/work/proj"
	cases := []struct {
		name  string
		opts  RunOptions
		setup func(*testApp)
		want  []string
	}{
		{"attached", RunOptions{Harness: "claude", Copy: true, Name: "copybox"}, nil, []string{
			"stage copybox", "create copybox", "upload copybox", "baseline copybox", "exec true in " + workdir, "attach", "pull copybox",
		}},
		{"detached", RunOptions{Harness: "claude", Copy: true, Name: "copybox", Detach: true, Prompt: "fix it"},
			func(ta *testApp) { ta.IO.TTY = false }, []string{
				"stage copybox", "create copybox", "upload copybox", "baseline copybox", "exec true in " + workdir, "exec sh in " + workdir,
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "s\n")
			if c.setup != nil {
				c.setup(ta)
			}
			if err := ta.Run(context.Background(), c.opts); err != nil {
				t.Fatalf("Run: %v\n%s", err, ta.output())
			}
			if got := ta.daemon.timeline.list(); !slices.Equal(got, c.want) {
				t.Fatalf("steps =\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

// A failed upload removes the sandbox without having probed a workdir that
// does not exist.
func TestRunCopyUploadFailureDeletesSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Workspace = &failingUpload{fakeCopy: ta.copy}
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox"})
	if err == nil || !strings.Contains(err.Error(), "upload the project copy") {
		t.Fatalf("Run = %v", err)
	}
	if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/copybox")); n != 1 {
		t.Fatalf("delete calls = %d", n)
	}
	if runs := ta.stream.commands(); len(runs) != 0 {
		t.Fatalf("execs before the upload: %q", runs)
	}
}

// A create the daemon refuses leaves no staged copy behind, unless the
// name belongs to a sandbox that exists: its copy is not this run's.
func TestRunCopyCreateFailureDiscardsTheStagedCopy(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable, Message: "no verified image"}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox"}); err == nil {
		t.Fatal("Run succeeded")
	}
	if !slices.Equal(ta.copy.steps, []string{"stage copybox", "discard copybox"}) {
		t.Fatalf("steps = %v", ta.copy.steps)
	}

	ta = newTestApp(t, "")
	ta.daemon.add(copySandbox("copybox"))
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: "a sandbox named copybox already exists"}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox"}); err == nil {
		t.Fatal("Run succeeded")
	}
	if slices.Contains(ta.copy.steps, "discard copybox") {
		t.Fatalf("the existing sandbox's copy was discarded: %v", ta.copy.steps)
	}
}

type failingUpload struct{ *fakeCopy }

func (f *failingUpload) Upload(context.Context, string, string, workspace.Uploader) (*workspace.CopyRecord, error) {
	return nil, errors.New("openshell upload failed (exit 1)")
}

// Resuming a copy-mode sandbox with --refresh probes outside the workdir
// (a failed refresh may have left none), then refreshes, then attaches; a
// plain resume probes the workdir.
func TestConnectRefreshOrdersProbeRefreshAttach(t *testing.T) {
	for _, refresh := range []bool{true, false} {
		t.Run(fmt.Sprintf("refresh=%t", refresh), func(t *testing.T) {
			ta := newTestApp(t, "s\n")
			sb := sampleSandbox("copybox")
			sb.WorkdirMode, sb.Workdir, sb.Phase = "copy", "/sandbox/work/proj", "stopped"
			ta.daemon.add(sb)
			if err := ta.Connect(context.Background(), ConnectOptions{Name: "copybox", Refresh: refresh}); err != nil {
				t.Fatalf("Connect: %v\n%s", err, ta.output())
			}
			want := []string{"exec true in /sandbox/work/proj", "attach", "pull copybox"}
			if refresh {
				want = []string{"exec true in -", "refresh copybox", "attach", "pull copybox"}
			}
			if got := ta.daemon.timeline.list(); !slices.Equal(got, want) {
				t.Fatalf("steps = %q, want %q", got, want)
			}
		})
	}
}

// A copy of a plain folder has no branch to bring work back on: the end of
// the session does not offer one, and `pull --branch` says what works.
func TestPlainFolderCopyHasNoBranchChoice(t *testing.T) {
	ta := newTestApp(t, "p\n")
	ta.copy.pull = &workspace.PullResult{Name: "plainbox", Kind: workspace.CopyPlain,
		Changes: []workspace.TreeChange{{Path: "notes.md", Status: "M", Added: 1}}, Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 1}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "plainbox"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if !strings.Contains(out, "Bring the changes back? [A] apply (3-way)  [p] patch file  [s] skip") || strings.Contains(out, "branch dc/") {
		t.Fatalf("choices:\n%s", out)
	}
	if len(ta.copy.apply) != 1 || ta.copy.apply[0].Mode != workspace.ApplyPatch {
		t.Fatalf("apply = %+v", ta.copy.apply)
	}
	err := ta.Pull(context.Background(), PullOptions{Name: "plainbox", Branch: true})
	if err == nil || !strings.Contains(err.Error(), "not a git repository") || !strings.Contains(err.Error(), "--apply or --patch-out") {
		t.Fatalf("pull --branch = %v", err)
	}
	if len(ta.copy.apply) != 1 {
		t.Fatal("pull --branch applied something")
	}
}

// TestRunFallsBackToCopyMode pins the plan's fallback: a project the
// daemon cannot mount live (a linked worktree, a git directory outside the
// folder) runs in copy mode, with an explanation, instead of failing.
func TestRunFallsBackToCopyMode(t *testing.T) {
	ta := newTestApp(t, "a\n")
	ta.env["OPENAI_API_KEY"] = "sk-openai-test"
	ta.daemon.refuseCreate = func(req sandboxapi.CreateRequest) *sandboxapi.Error {
		if req.Copy {
			return nil
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy",
			Detail: "the git directory is outside the project (a linked worktree)"}
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "codex", Name: "wt"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	creates := ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)
	if len(creates) != 2 || strings.Contains(string(creates[0].Body), `"copy":true`) || !strings.Contains(string(creates[1].Body), `"copy":true`) {
		t.Fatalf("create calls = %d, want a live mount and then a copy", len(creates))
	}
	if want := []string{"stage wt", "upload wt"}; len(ta.copy.steps) < 2 || !slices.Equal(ta.copy.steps[:2], want) {
		t.Fatalf("copy steps = %v, want %v first", ta.copy.steps, want)
	}
	if out := ta.output(); !strings.Contains(out, "⚠ ~/proj can't be mounted live (the git directory is outside the project (a linked worktree)), so it runs on a copy: `defenseclaw sandbox pull wt` brings the changes back") ||
		strings.Contains(out, "run it with --copy") {
		t.Fatalf("output does not explain the fallback:\n%s", out)
	}
}

// A copy-mode fallback whose create the daemon then refuses too removes the
// copy it staged, like an explicit --copy run.
func TestRunCopyFallbackCreateFailureDiscardsTheStagedCopy(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["OPENAI_API_KEY"] = "sk-openai-test"
	ta.daemon.refuseCreate = func(req sandboxapi.CreateRequest) *sandboxapi.Error {
		if req.Copy {
			return &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable, Message: "no verified image"}
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy",
			Detail: "the git directory is outside the project (a linked worktree)"}
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "codex", Name: "wt"}); err == nil {
		t.Fatalf("Run succeeded:\n%s", ta.output())
	}
	if !slices.Equal(ta.copy.steps, []string{"stage wt", "discard wt"}) {
		t.Fatalf("copy steps = %v, want the fallback's stage discarded", ta.copy.steps)
	}
}

// A name a deleted sandbox's kept snapshot holds is refused before
// anything is staged, without offering to resume what is gone.
func TestRunRefusesTheNameOfAKeptSnapshot(t *testing.T) {
	ta := newTestApp(t, "")
	kept := sampleSandbox("keptbox")
	kept.Phase = "deleted"
	ta.daemon.add(kept)
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "keptbox"})
	if err == nil || !strings.Contains(err.Error(), "holds the kept undo point of a deleted sandbox") ||
		!strings.Contains(err.Error(), "`defenseclaw sandbox delete keptbox` drops it") || strings.Contains(err.Error(), "connect") {
		t.Fatalf("Run = %v", err)
	}
	if len(ta.copy.steps) != 0 || len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)) != 0 {
		t.Fatalf("the refused name staged %v or created a sandbox", ta.copy.steps)
	}
}

func TestRunOffersResume(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.daemon.add(sandboxapi.Sandbox{Name: "dc-claude-proj-old", Harness: "claudecode", HarnessName: "Claude Code", Phase: "stopped",
		WorkdirMode: "mount", Project: ta.project, Workdir: "/work/proj", CreatedAt: time.Now()})
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)); n != 0 {
		t.Fatal("resume created a new sandbox")
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/dc-claude-proj-old/start")); n != 1 {
		t.Fatalf("start calls = %d", n)
	}
	if len(ta.term.runs) != 1 {
		t.Fatalf("terminal runs = %d", len(ta.term.runs))
	}
}

func TestRunCredentialBindingWinsOverLLM(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["ANTHROPIC_API_KEY"] = "mock-key"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Credentials: []string{"ANTHROPIC_API_KEY=host.openshell.internal:28921"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	req := createRequest(t, ta.daemon)
	if req.LLM != nil || len(req.Credentials) != 1 || req.Credentials[0].Port != 28921 {
		t.Fatalf("create request = %+v", req)
	}
}

func TestSummaryLineCountsBlockedRequests(t *testing.T) {
	s := &session{before: &sandboxapi.Sandbox{Egress: sandboxapi.EgressStats{Destinations: 1, Blocked: 1}}}
	for _, tc := range []struct {
		egress sandboxapi.EgressStats
		want   string
	}{
		{sandboxapi.EgressStats{Destinations: 1, Blocked: 1}, "Session ended · 0 tool calls · 0 new sites contacted"},
		{sandboxapi.EgressStats{Destinations: 2, Blocked: 2}, "Session ended · 0 tool calls · 1 new site contacted (1 request blocked)"},
		{sandboxapi.EgressStats{Destinations: 3, Blocked: 3}, "Session ended · 0 tool calls · 2 new sites contacted (2 requests blocked)"},
	} {
		if got := s.summaryLine(&sandboxapi.Sandbox{Egress: tc.egress}, nil); got != tc.want {
			t.Errorf("summaryLine(%+v) = %q, want %q", tc.egress, got, tc.want)
		}
	}
}

func TestBannerHostLineListsAcceptedPortsOnly(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	sb.Violations = []sandboxapi.Violation{{Key: "mcp.host_ports", Attempted: "18970", Constraint: "defenseclaw",
		Message: "DefenseClaw never opens DefenseClaw's API (port 18970) to a sandbox"}}
	ta.banner(&sb, bannerInfo{o: RunOptions{HostPorts: []int{5432, 18970, 5432}}})
	out := ta.output()
	if !strings.Contains(out, "Host      localhost:5432 (opens when you approve the sandbox's first connection)") {
		t.Fatalf("banner host line:\n%s", out)
	}
	if strings.Contains(out, "localhost:18970") {
		t.Fatalf("banner lists a refused port as reachable:\n%s", out)
	}
	ta.out.Reset()
	sb.Violations = []sandboxapi.Violation{{Key: "mcp.host_ports", Attempted: "5432", Constraint: "pack strict"}}
	ta.banner(&sb, bannerInfo{o: RunOptions{HostPorts: []int{5432}}})
	if strings.Contains(ta.output(), "Host ") {
		t.Fatalf("banner shows a Host line although every port was refused:\n%s", ta.output())
	}
}
