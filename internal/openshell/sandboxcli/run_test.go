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
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

func TestRunMountSessionKeepsChanges(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.env["ANTHROPIC_API_KEY"] = "sk-test-not-a-secret"
	ta.env["STRIPE_API_KEY"] = "stripe-test-value"
	ta.env["TZ"] = ":America/New_York"
	notice := "MCP: blocked the repository's servers repo-tool (mcp.project_servers: block; a sandbox pack with mcp.project_servers: allow runs them)"
	ta.daemon.createMCP = &sandboxapi.MCPSummary{Imported: []string{"github", "linear"}, ProjectServers: "block", Project: []string{"repo-tool"}}
	ta.daemon.createWarnings = []string{notice}
	ta.term.during = func() {
		ta.daemon.edit(sbName, func(sb *sandboxapi.Sandbox) {
			sb.Hooks = sandboxapi.HookCoverage{ToolCalls: 57, ToolBlocked: 1, LastBlocked: "E2E marker command"}
			sb.Egress = sandboxapi.EgressStats{Destinations: 23, Blocked: 1}
			sb.NestedRepos = []sandboxapi.NestedRepo{{Kind: "repository", Path: "vendor/x/.git", Quarantined: "vendor/x/.git.defenseclaw-quarantine-1"}}
		})
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Credentials: []string{"STRIPE_API_KEY=api.stripe.com"}, Env: []string{"FOO=bar"},
		Args: []string{"--model", "sonnet"}}))
	req := createRequest(t, ta.daemon)
	if req.Harness != "claudecode" || req.Project != ta.project || req.Copy || req.LLM == nil ||
		req.LLM.Profile != profiles.AnthropicID || req.LLM.Credentials["ANTHROPIC_API_KEY"] != "sk-test-not-a-secret" ||
		len(req.Credentials) != 1 || req.Credentials[0].Host != "api.stripe.com" || req.Credentials[0].Value != "stripe-test-value" ||
		req.Env["FOO"] != "bar" || req.TimeZone != "America/New_York" {
		t.Fatalf("create request = %+v", req)
	}
	has(t, ta.output(),
		"Sandbox dc-claude-proj-1a2b · Claude Code · skip-permissions ON · network: open + blocklist",
		"Project   ~/proj → /work/proj (live)   undo point taken → `defenseclaw sandbox undo dc-claude-proj-1a2b` restores it",
		"Hidden    .env",
		"Protected .git/hooks .git/config (read-only)",
		"Model     sonnet · ANTHROPIC_API_KEY → api.anthropic.com only",
		"Secret    STRIPE_API_KEY → api.stripe.com only",
		"MCP       github ✓ · linear ✓",
		notice,
		"Session ended · 57 tool calls (1 blocked: E2E marker command) · 23 new sites contacted · 1 site blocked · 2 files changed (+10 −3)",
		"quarantined as vendor/x/.git.defenseclaw-quarantine-1",
		"Sandbox kept (stopped) → resume: defenseclaw sandbox connect dc-claude-proj-1a2b")
	if strings.Contains(ta.output(), "sk-test-not-a-secret") || strings.Contains(ta.output(), "stripe-test-value") {
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
	argv[0] = "/usr/bin/openshell"
	want := []string{"/usr/bin/openshell", "sandbox", "exec", "-g", "openshell", "--workspace", "default", "--name", "dc-claude-proj-1a2b",
		"--workdir", "/work/proj", "--tty", "--no-login-shell", "--", harness.ClaudeCodeLauncherPath, "--dangerously-skip-permissions", "--model", "sonnet"}
	if !slices.Equal(argv, want) {
		t.Fatalf("attach argv =\n%q\nwant\n%q", argv, want)
	}
	ta.wantCalls(t, 1, "POST", sbName+"/stop")
	if n := ta.calls("POST", sbName+"/undo"); n != 0 {
		t.Fatal("undo ran although the user kept the changes")
	}
}

// "d" shows the diff and "u" undoes the session, naming what undo could not
// restore; --rm then deletes the sandbox.
func TestRunMountSessionUndoAfterDiff(t *testing.T) {
	ta := newTestApp(t, "d\nu\n")
	ta.daemon.undo = sandboxapi.UndoResponse{Result: &workspace.UndoResult{Project: ta.project, Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}},
		Ignored: []workspace.IgnoredChange{{Path: ".venv/", Modified: 1, Dependencies: true, Remedy: "delete it and create the virtual environment again"}}}}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: true}))
	if r := ta.bodies("POST", sbName+"/review"); len(r) != 2 || !strings.Contains(r[1], `"diff":true`) {
		t.Fatalf("review calls = %q", r)
	}
	if u := ta.bodies("POST", sbName+"/undo"); len(u) != 1 || !strings.Contains(u[0], `"stop":true`) {
		t.Fatalf("undo calls = %q", u)
	}
	ta.wantCalls(t, 1, "DELETE", sbName)
	has(t, ta.output(), "+changed", "undone: 1 file restored, except .venv/ (see below)",
		"undo cannot restore .venv/ (1 file added or changed during the session): delete it and create the virtual environment again")
}

// TestRunOffersChoicesForAFolderMountedLive pins that on a terminal a run
// whose folder another sandbox mounts live (here a kept, stopped Codex one)
// asks instead of failing: a copy by default, deleting that sandbox first,
// or nothing.
func TestRunOffersChoicesForAFolderMountedLive(t *testing.T) {
	other := func(ta *testApp) {
		sb := sampleSandbox("dc-codex-proj-9z9z")
		sb.Harness, sb.HarnessName, sb.Phase, sb.Project = "codex", "Codex", "stopped", ta.project
		ta.daemon.add(sb)
		noChanges(ta)
	}
	mode := func(copy bool) func(*testing.T, *testApp) {
		return func(t *testing.T, ta *testApp) {
			if req := createRequest(t, ta.daemon); req.Copy != copy {
				t.Fatalf("create request = %+v, want copy %t", req, copy)
			}
		}
	}
	claude := RunOptions{Harness: "claude"}
	runCases(t, []runCase{
		{name: "copy by default", input: "\n\n", setup: other, opts: claude, check: mode(true),
			want: []string{"Sandbox dc-codex-proj-9z9z (Codex, stopped) already mounts this folder live"}},
		{name: "delete first", input: "d\ny\n\n", setup: other, opts: claude, check: func(t *testing.T, ta *testApp) {
			ta.wantCalls(t, 1, "DELETE", "dc-codex-proj-9z9z")
			mode(false)(t, ta)
		}},
		{name: "quit", input: "q\n", setup: other, opts: claude, want: []string{"`defenseclaw sandbox delete dc-codex-proj-9z9z` frees the folder"},
			check: func(t *testing.T, ta *testApp) {
				if n := ta.creates(); n != 0 {
					t.Fatalf("creates = %d, want none", n)
				}
			}},
	})
}

// TestRunCarriesTheGitIdentity pins that the sandbox's git gets the
// identity the host's git uses for the project, so commits work and git
// does not look up the sandbox's host name for an address. --env wins, and
// a value no environment variable can carry is dropped.
func TestRunCarriesTheGitIdentity(t *testing.T) {
	dana := map[string]string{"user.name": "Dana Dev", "user.email": "dana@example.org"}
	for _, tc := range []struct {
		name   string
		config map[string]string
		env    []string
		want   map[string]string
	}{
		{"the project's identity", dana, nil, map[string]string{"GIT_AUTHOR_NAME": "Dana Dev", "GIT_COMMITTER_NAME": "Dana Dev",
			"GIT_AUTHOR_EMAIL": "dana@example.org", "GIT_COMMITTER_EMAIL": "dana@example.org"}},
		{"--env wins", dana, []string{"GIT_AUTHOR_EMAIL=bot@example.org"}, map[string]string{"GIT_AUTHOR_NAME": "Dana Dev", "GIT_COMMITTER_NAME": "Dana Dev",
			"GIT_AUTHOR_EMAIL": "bot@example.org", "GIT_COMMITTER_EMAIL": "dana@example.org"}},
		{"no identity", nil, nil, map[string]string{}},
		{"a malformed value", map[string]string{"user.name": "Dana\x1b[2J", "user.email": "dana@example.org"}, nil,
			map[string]string{"GIT_AUTHOR_EMAIL": "dana@example.org", "GIT_COMMITTER_EMAIL": "dana@example.org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.gitConfig = tc.config
			noChanges(ta)
			ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Env: tc.env}))
			got := map[string]string{}
			for k, v := range createRequest(t, ta.daemon).Env {
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

// TestHostGitConfigReadsTheRepositoryFirst runs the host's git: the
// repository's own identity wins over the user's, and an unset key or a
// folder outside any repository reads as the user's value or "".
func TestHostGitConfigReadsTheRepositoryFirst(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	global := filepath.Join(root, "gitconfig")
	writeFile(t, global, "[user]\n\tname = Global Name\n\temail = global@example.org\n")
	env := []string{"GIT_CONFIG_GLOBAL=" + global, "GIT_CONFIG_NOSYSTEM=1", "HOME=" + root, "PATH=" + os.Getenv("PATH")}
	repo, plain := filepath.Join(root, "repo"), filepath.Join(root, "plain")
	writeFile(t, filepath.Join(plain, "x"), "")
	writeFile(t, filepath.Join(repo, "x"), "")
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "repo@example.org"}} {
		cmd := exec.Command(git, append([]string{"-C", repo}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	a := &App{LookPath: exec.LookPath, Environ: func() []string { return env }}
	for _, tc := range []struct{ dir, key, want string }{
		{repo, "user.email", "repo@example.org"},
		{repo, "user.name", "Global Name"},
		{plain, "user.email", "global@example.org"},
		{repo, "user.signingkey", ""},
	} {
		if got := a.hostGitConfig(bg, tc.dir, tc.key); got != tc.want {
			t.Errorf("hostGitConfig(%s, %s) = %q, want %q", filepath.Base(tc.dir), tc.key, got, tc.want)
		}
	}
	missing := &App{LookPath: func(string) (string, error) { return "", exec.ErrNotFound }, Environ: func() []string { return env }}
	if got := missing.hostGitConfig(bg, repo, "user.email"); got != "" {
		t.Fatalf("without git = %q", got)
	}
}

// A detached run starts the harness in the background under setsid,
// recording its start and logging to the run directory; Claude Code
// streams its events, other harnesses keep their own output.
func TestRunDetachedStartsInBackground(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Detach: true, Prompt: "fix the failing tests"}))
	if cmds := ta.stream.commands(); len(cmds) != 2 || cmds[0] != "true" || !strings.HasPrefix(cmds[1], "sh -c set -eu") {
		t.Fatalf("stream commands = %q", cmds)
	}
	last := sandboxCommand(ta.stream.runs[1])
	tail := last[5:]
	want := []string{harness.ClaudeCodeLauncherPath, "--dangerously-skip-permissions", "-p", "fix the failing tests", "--output-format", "stream-json", "--verbose"}
	if !slices.Equal(tail, want) {
		t.Fatalf("detached harness argv = %q, want %q", tail, want)
	}
	if last[2] != detachScript || last[4] != RunDir {
		t.Fatalf("detach command = %q", last[:5])
	}
	has(t, last[2], `"$d/latest.log"`, "setsid", `date +%s > "$d/latest.started"`)
	if len(ta.term.runs) != 0 {
		t.Fatal("a detached run attached the terminal")
	}
	has(t, ta.output(), "defenseclaw sandbox logs dc-claude-proj-1a2b -f")
	if n := ta.calls("POST", sbName+"/stop"); n != 0 {
		t.Fatal("a detached run was stopped")
	}
	ta = newTestApp(t, "")
	ta.IO.TTY = false
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "codex", Detach: true, Prompt: "x"}))
	if last := sandboxCommand(ta.stream.runs[len(ta.stream.runs)-1]); slices.Contains(last, "stream-json") || last[4] != RunDir || last[5] != harness.CodexLauncherPath {
		t.Fatalf("detached codex argv = %q", last)
	}
}

// A refused run creates no sandbox and stages no copy, and says why: a
// --name OpenShell 0.1.1 cannot create is refused before anything else (H3),
// an existing sandbox's name before staging over its copy (H6), a host port
// before the banner calls it reachable (M15), and the organization's
// refusal before what the terminal lacks (L9).
func TestRunRefusals(t *testing.T) {
	ingress := newTestApp(t, "").Cfg.OpenShellIngressPort()
	off := false
	existing := func(name, phase string, tty bool) func(*testApp) {
		return func(ta *testApp) {
			sb := copySandbox(name)
			sb.Phase = phase
			ta.daemon.add(sb)
			ta.IO.TTY = tty
		}
	}
	cases := []struct {
		name    string
		opts    RunOptions
		setup   func(*testApp)
		want    []string
		not     string
		offline bool // refused before anything reaches the daemon
	}{
		{name: "detach with rm", opts: RunOptions{Harness: "claude", Detach: true, Rm: true, Prompt: "x"}, want: []string{"--rm cannot be combined with --detach"}},
		{name: "detach without prompt", opts: RunOptions{Harness: "claude", Detach: true}, want: []string{"needs a prompt"}},
		{name: "no terminal", opts: RunOptions{Harness: "codex"}, setup: func(ta *testApp) { ta.IO.TTY = false }, want: []string{"there is none"}},
		{name: "unknown harness", opts: RunOptions{Harness: "vim"}, want: []string{"unknown harness"}},
		{name: "disabled", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) { ta.daemon.status.Enabled = false }, want: []string{"sandboxes are off"}},
		{name: "unavailable", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) {
			ta.daemon.status.Available, ta.daemon.status.Reason = false, "the OpenShell gateway is down"
		}, want: []string{"the OpenShell gateway is down"}},
		{name: "admin refuses harness", opts: RunOptions{Harness: "codex"}, setup: func(ta *testApp) {
			ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "harness", Fatal: true, Admin: true, Message: "codex is not an allowed harness"}}
		}, want: []string{"blocked by your organization's DefenseClaw policy: harness"}},
		{name: "the organization before the terminal", opts: RunOptions{Harness: "codex"}, setup: func(ta *testApp) {
			ta.IO.TTY = false
			ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "harness", Fatal: true, Admin: true, Constraint: "openshell.admin.allowed_harnesses",
				Message: "blocked by your organization's DefenseClaw policy: harness", Detail: "your organization allows only claudecode"}}
		}, want: []string{"blocked by your organization's DefenseClaw policy: harness — your organization allows only claude " +
			"(openshell.admin.allowed_harnesses); ask your administrator if you need it"}, not: "there is none"},
		// A repository policy that would loosen names every key, one per line.
		{name: "a repository policy that loosens", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) {
			ta.daemon.explain.Violations = []sandboxapi.Violation{
				{Key: "harness.yolo", Source: "repo", Fatal: true, Message: "the repository policy .defenseclaw/sandbox.yaml would loosen the sandbox policy: harness.yolo true"},
				{Key: "egress.allow", Source: "repo", Fatal: true, Message: "the repository policy .defenseclaw/sandbox.yaml would loosen the sandbox policy: egress.allow 2 entries"},
			}
		}, want: []string{"harness.yolo true\nthe repository policy .defenseclaw/sandbox.yaml would loosen the sandbox policy: egress.allow 2 entries"}},
		{name: "daemon down", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) { ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x") },
			want: []string{"daemon is not running"}},
		{name: "windows", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) { ta.GOOS = "windows" }, want: []string{"Windows and WSL2 are not supported"}},
		{name: "wsl2", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) { ta.WSL = func() bool { return true } }, want: []string{"Windows and WSL2 are not supported"}},
		{name: "root", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) { ta.Geteuid = func() int { return 0 } },
			want: []string{"not root: the OpenShell gateway is a per-user service"}},
		// OpenShell's MicroVM driver, which a Mac runs sandboxes with, needs
		// Apple silicon.
		{name: "an Intel Mac", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) { ta.GOOS, ta.GOARCH = "darwin", "amd64" },
			want: []string{"OpenShell sandboxes are not supported here", "Apple silicon"}},
		{name: "bad credential", opts: RunOptions{Harness: "claude", Credentials: []string{"NOPE=api.x.com"}}, want: []string{"is not set in this shell"}},
		{name: "--github-write without a token", opts: RunOptions{Harness: "claude", GitHubWrite: true}, want: []string{"GH_TOKEN"}},
		// The OmniGent sandbox agent names no model, and a profile without a
		// default one needs --model.
		{name: "omnigent without a model", opts: RunOptions{Harness: "omnigent"}, setup: func(ta *testApp) { ta.env["OPENAI_API_KEY"] = "sk-test" },
			want: []string{"--model"}},
		{name: "a long name", opts: RunOptions{Harness: "claude", Copy: true, Name: "dc-claude-m1-calc-7500"}, offline: true,
			want: []string{`--name "dc-claude-m1-calc-7500" is 22 characters; OpenShell takes at most 19`}},
		{name: "a bad name", opts: RunOptions{Harness: "claude", Copy: true, Name: "Bad_Name"}, offline: true,
			want: []string{"use at most 19 lowercase letters, digits and '-'"}},
		{name: "a trailing dash", opts: RunOptions{Harness: "claude", Copy: true, Name: "trailing-"}, offline: true,
			want: []string{"starting and ending with a letter or digit"}},
		{name: "a reserved name", opts: RunOptions{Harness: "claude", Copy: true, Name: "git"}, offline: true, want: []string{`--name "git" is reserved`}},
		{name: "an existing name, headless copy", opts: RunOptions{Harness: "codex", Copy: true, Name: "m2-a", Detach: true, Prompt: "x"},
			setup: existing("m2-a", "stopped", false), want: []string{"a sandbox named m2-a already exists",
				"resume it with `defenseclaw sandbox connect m2-a --prompt TEXT`", "delete it with `defenseclaw sandbox delete m2-a`"}},
		{name: "an existing name, terminal", opts: RunOptions{Harness: "claude", Name: "m2-a"}, setup: existing("m2-a", "stopped", true),
			want: []string{"a sandbox named m2-a already exists", "resume it with `defenseclaw sandbox connect m2-a`", "delete it with `defenseclaw sandbox delete m2-a`"}},
		{name: "a kept snapshot's name", opts: RunOptions{Harness: "claude", Copy: true, Name: "keptbox"}, setup: existing("keptbox", "deleted", true),
			want: []string{"holds the kept undo point of a deleted sandbox", "`defenseclaw sandbox delete keptbox` drops it"}, not: "connect"},
		{name: "the hook ingress port", opts: RunOptions{Harness: "claude", HostPorts: []int{3000, ingress}},
			want: []string{fmt.Sprintf("--host-port %d: DefenseClaw never opens DefenseClaw's sandbox hook ingress (port %d) to a sandbox — choose another port", ingress, ingress)}},
		{name: "host ports the organization disables", opts: RunOptions{Harness: "claude", HostPorts: []int{3000}},
			setup: func(ta *testApp) { ta.Cfg.OpenShell.Admin.AllowHostPorts = &off },
			want: []string{"--host-port 3000: blocked by your organization's DefenseClaw policy: mcp.host_ports — host ports cannot be opened to sandboxes " +
				"(openshell.admin.allow_host_ports); run it without --host-port"}},
		// Manual R2-104: the refusal of the organization's required pack.
		{name: "a host port the required pack refuses", opts: RunOptions{Harness: "claude", HostPorts: []int{38790}}, setup: func(ta *testApp) {
			ta.Cfg.OpenShell.Admin.RequiredPack = "strict"
			ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{Key: "pack", Value: "strict", Source: "admin",
				Origin: "openshell.admin.required_pack"})
		}, want: []string{"--host-port 38790: not allowed by the strict sandbox pack your organization requires (openshell.admin.required_pack)"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			if c.setup != nil {
				c.setup(ta)
			}
			err := ta.Run(bg, c.opts)
			wantErr(t, err, c.want...)
			if c.not != "" && strings.Contains(err.Error(), c.not) {
				t.Fatalf("err = %v, which holds %q", err, c.not)
			}
			if ta.creates() != 0 || len(ta.copy.steps) != 0 || strings.Contains(ta.output(), "reachable") {
				t.Fatalf("a refused run created a sandbox or staged a copy %v:\n%s", ta.copy.steps, ta.output())
			}
			if paths := ta.daemon.paths(); c.offline && len(paths) != 0 {
				t.Fatalf("a refused name reached the daemon: %v", paths)
			}
		})
	}
	ta := newTestApp(t, "")
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Name: strings.Repeat("a", 19)}))
	// The daemon's own refusal of the create says why.
	ta = newTestApp(t, "")
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "yolo", Admin: true, Message: "skip-permissions mode is not allowed"}}
	if err := ta.Run(bg, RunOptions{Harness: "claude"}); err == nil || err.Error() != "blocked by your organization's DefenseClaw policy: yolo (skip-permissions mode is not allowed)" {
		t.Fatalf("Run = %v", err)
	}
}

// TestRunSaysWhyTheSandboxDidNotStart: on a Mac every run ended with
// "wait for sandbox … failed: … is in error state", OpenShell's reason (its
// supervisor's Landlock probe) only in the gateway log (manual test M13).
// The daemon now passes the reason on, and on macOS a run or a start that
// failed on Landlock on the docker driver (Docker Desktop's VM kernel) says
// what that means there and how to switch to MicroVMs, on a line of its own
// after OpenShell's output (it ended one long line, the #1019 retest); on
// the MicroVM driver, whose sandboxes boot kernels of their own, it says
// nothing more.
func TestRunSaysWhyTheSandboxDidNotStart(t *testing.T) {
	const detail = `openshell: wait for sandbox "myapp-d395": Internal: sandbox "myapp-d395" is in error state; ` +
		`OpenShell says: SupervisorFailed: Landlock allow/deny probe failed`
	failure := &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "OpenShell: wait for sandbox myapp-d395 failed", Detail: detail}
	hint := "\n  → this gateway runs sandboxes on the docker driver, and Docker Desktop's Linux VM has no Landlock, which OpenShell sandboxes need: " +
		"switch the gateway to MicroVMs with `defenseclaw sandbox setup` (or `defenseclaw sandbox doctor --fix`; see " + setupTroubleshootingURL + ")"
	for _, c := range []struct{ goos, driver, want string }{
		{"linux", "", failure.Error()},
		{"linux", "docker", failure.Error()},
		{"darwin", "", failure.Error() + hint},
		{"darwin", "docker", failure.Error() + hint},
		{"darwin", "vm", failure.Error()},
	} {
		ta := newTestApp(t, "")
		ta.GOOS = c.goos
		ta.daemon.status.Gateway.Driver = c.driver
		ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = failure
		if err := ta.Run(bg, RunOptions{Harness: "claude"}); err == nil || err.Error() != c.want {
			t.Fatalf("%s/%s: Run = %v\nwant %s", c.goos, c.driver, err, c.want)
		}
		old := sampleSandbox("myapp-d395")
		old.Phase, old.Project = "stopped", ta.project
		if c.driver == "vm" {
			old.WorkdirMode = "copy"
		}
		ta.daemon.add(old)
		ta.daemon.errors["POST /api/v1/sandbox/sandboxes/myapp-d395/start"] = failure
		if err := ta.Connect(bg, ConnectOptions{Name: "myapp-d395"}); err == nil || err.Error() != c.want {
			t.Fatalf("%s/%s: Connect = %v\nwant %s", c.goos, c.driver, err, c.want)
		}
	}
	// A configuration OpenShell refused for a Landlock path is not that.
	ta := newTestApp(t, "")
	ta.GOOS = "darwin"
	rejected := &sandboxapi.Error{Code: sandboxapi.CodePolicyRejected, Message: "OpenShell rejected the sandbox configuration", Detail: "landlock path /nope does not exist"}
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = rejected
	if err := ta.Run(bg, RunOptions{Harness: "claude"}); err == nil || err.Error() != rejected.Error() {
		t.Fatalf("Run = %v", err)
	}
}

// On a Mac whose gateway ran the docker driver on Docker Desktop, `sandbox
// run` built the harness image and made a sandbox before OpenShell's
// supervisor failed it on the Landlock the VM does not have, a certain
// failure (the Docker driver check of the #1019 retest). It is refused up
// front now, with the doctor's way on, on a line of its own; another Docker
// VM, one that does not answer, and Linux are left to try as before.
func TestRunRefusesDockerDesktopUpFront(t *testing.T) {
	const refusal = "no sandbox can start on this gateway: it runs sandboxes on the docker driver, and Docker Desktop's Linux VM has no Landlock, " +
		"which OpenShell sandboxes need; nothing was built or created\n" +
		"  → run sandboxes in OpenShell MicroVMs, which have their own kernel: `defenseclaw sandbox setup` switches the gateway to them " +
		"(or `defenseclaw sandbox doctor --fix`; details: " + setupTroubleshootingURL + ")"
	for _, c := range []struct {
		goos, driver, engine string
		refused              bool
		asked                int
	}{
		{"darwin", "docker", "Docker Desktop", true, 1},
		{"darwin", "", "Docker Desktop", true, 1}, // a daemon too old to name its driver drove docker
		{"darwin", "docker", "Ubuntu 24.04.2 LTS", false, 1},
		{"darwin", "docker", "", false, 1},
		{"darwin", "vm", "Docker Desktop", false, 0},
		{"linux", "docker", "Docker Desktop", false, 0},
	} {
		ta := newTestApp(t, "")
		ta.GOOS, ta.dockerEngine = c.goos, c.engine
		ta.daemon.status.Gateway.Driver = c.driver
		// A run let through ends at the create.
		ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "create reached"}
		err := ta.Run(bg, RunOptions{Harness: "claude"})
		creates := ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)
		switch {
		case c.refused && (err == nil || err.Error() != refusal):
			t.Fatalf("%+v: Run = %v\nwant %s", c, err, refusal)
		case c.refused && (len(creates) != 0 || len(ta.copy.steps) != 0 || strings.Contains(ta.output(), "Starting")):
			t.Fatalf("%+v: a refused run created %d sandboxes and staged %v:\n%s", c, len(creates), ta.copy.steps, ta.output())
		case !c.refused && (err == nil || !strings.HasPrefix(err.Error(), "create reached") || len(creates) != 1):
			t.Fatalf("%+v: Run = %v (%d creates), want it to reach the create", c, err, len(creates))
		}
		if ta.dockerAsked != c.asked {
			t.Fatalf("%+v: docker asked %d times, want %d", c, ta.dockerAsked, c.asked)
		}
	}
}

func TestRunNestedRunsNatively(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["DEFENSECLAW_SANDBOX_ID"] = "sb-1"
	ta.API, ta.Cfg = nil, nil
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Args: []string{"-c"}}))
	if len(ta.execs) != 1 || !slices.Equal(ta.execs[0], []string{"/usr/bin/claude", "claude", "-c"}) {
		t.Fatalf("execs = %v", ta.execs)
	}
}

// --safe drops the harness's bypass flags and says so; a flag dropped
// because the organization disables skip-permissions says whose doing it is
// (manual R2-102).
func TestRunSafeDropsBypassFlags(t *testing.T) {
	ta := newTestApp(t, "")
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "codex", Safe: true, Args: []string{"--yolo", "--search"}}))
	argv := sandboxCommand(ta.term.runs[0])
	if slices.Contains(argv, "--yolo") || slices.Contains(argv, "--dangerously-bypass-approvals-and-sandbox") || !slices.Contains(argv, "--search") {
		t.Fatalf("safe argv = %q", argv)
	}
	has(t, ta.output(), "--yolo is ignored")
	if req := createRequest(t, ta.daemon); !req.Safe {
		t.Fatal("--safe did not reach the daemon")
	}
	ta = newTestApp(t, "")
	off := false
	ta.Cfg.OpenShell.Admin.AllowYolo = &off
	sb := sampleSandbox("box")
	sb.Launch.Yolo = false
	ta.filterBypass(harnessSpec(t, "claudecode"), &sb, []string{"--dangerously-skip-permissions"})
	has(t, ta.output(), "--dangerously-skip-permissions is ignored: this sandbox keeps Claude Code's permission prompts (your organization disables skip-permissions)")
}

// The banner and the start say what the run brings: the model and where its
// key goes (Codex on Bedrock runs the Mantle profile's default model unless
// -m picks another), the image build only when the image is missing
// (manual test L9), and a copy the organization requires (manual R2-103).
func TestRunBanner(t *testing.T) {
	bedrock := func(ta *testApp) {
		ta.env[EnvBedrockToken] = "bedrock-test-not-a-secret"
		ta.IO.TTY = true
		noChanges(ta)
	}
	missing := func(ta *testApp) {
		noChanges(ta)
		ta.images.missing = map[string]bool{"claudecode": true}
	}
	copyNote := "copy mode: your organization requires copy mode for this folder (openshell.admin.require_copy_for); the agent works on a copy"
	runCases(t, []runCase{
		{name: "codex on bedrock", setup: bedrock, opts: RunOptions{Harness: "codex", LLM: LLMBedrock},
			want: []string{"Model     openai.gpt-5.5 (the default; -- -m MODEL picks another) · AWS_BEARER_TOKEN_BEDROCK → " +
				"bedrock-mantle.us-east-1.api.aws only (the sandbox sees a placeholder)"},
			not: []string{"bedrock-test-not-a-secret"}},
		{name: "codex on bedrock with -m", setup: bedrock, opts: RunOptions{Harness: "codex", LLM: LLMBedrock, Args: []string{"-m", "openai.gpt-5.4"}},
			want: []string{"Model     openai.gpt-5.4 · AWS_BEARER_TOKEN_BEDROCK → bedrock-mantle.us-east-1.api.aws only"}},
		{name: "image built", setup: noChanges, opts: RunOptions{Harness: "claude"}, not: []string{"building its image first"}},
		{name: "image missing", setup: missing, opts: RunOptions{Harness: "claude"}, want: []string{"building its image first"}},
		{name: "image missing, --no-build", setup: missing, opts: RunOptions{Harness: "claude", NoBuild: true}, not: []string{"building its image first"}},
		{name: "a copy the organization requires", input: "s\n", setup: func(ta *testApp) {
			ta.daemon.explain.Settings[0] = sandboxapi.Setting{Key: "workdir.mode", Value: "copy", Source: "admin", Origin: "openshell.admin.require_copy_for",
				Requested: "mount"}
		}, opts: RunOptions{Harness: "claude", Name: "r2f-acme"}, want: []string{copyNote}, check: func(t *testing.T, ta *testApp) {
			if strings.Index(ta.output(), copyNote) > strings.Index(ta.output(), "Copying") {
				t.Fatalf("the copy is not explained before it is made:\n%s", ta.output())
			}
		}},
	})
}

// openshell.llm is the default of --llm, so a run the shell wrapper, the
// TUI or the macOS app starts (none passes --llm) shares the model
// credential it names; --llm overrides it for one run, a provider the
// harness has no credential for gives way to auto, which the run says, and
// a configured provider without its key refuses the run, naming the key
// (#955).
func TestRunLLMFromConfig(t *testing.T) {
	profileOf := func(t *testing.T, ta *testApp) string {
		t.Helper()
		if req := createRequest(t, ta.daemon); req.LLM != nil {
			return req.LLM.Profile
		}
		return ""
	}
	configured := func(llm string, env map[string]string) func(*testApp) {
		return func(ta *testApp) {
			ta.Cfg.OpenShell.LLM = llm
			for k, v := range env {
				ta.env[k] = v
			}
			noChanges(ta)
		}
	}
	both := map[string]string{EnvBedrockToken: "bedrock-test-not-a-secret", "ANTHROPIC_API_KEY": "anthropic-test-not-a-secret"}
	profile := func(want string) func(*testing.T, *testApp) {
		return func(t *testing.T, ta *testApp) {
			if got := profileOf(t, ta); got != want {
				t.Fatalf("credential profile = %q, want %q", got, want)
			}
		}
	}
	fallback := "openshell.llm is gemini, which Claude Code cannot use, so this run shares the credential --llm auto finds"
	runCases(t, []runCase{
		{name: "bedrock from the config", setup: configured("bedrock", both), opts: RunOptions{Harness: "claude"},
			check: profile(profiles.ClaudeBedrockMantleID), not: []string{"bedrock-test-not-a-secret", fallback}},
		{name: "--llm overrides it", setup: configured("bedrock", both), opts: RunOptions{Harness: "claude", LLM: LLMAuto},
			check: profile(profiles.AnthropicID)},
		{name: "auto from the config", setup: configured("auto", both), opts: RunOptions{Harness: "claude"},
			check: profile(profiles.AnthropicID)},
		{name: "none from the config", setup: configured("none", both), opts: RunOptions{Harness: "claude"},
			check: profile(""), want: []string{"no model credential is shared (openshell.llm none)"}},
		{name: "a provider the harness cannot use", setup: configured("gemini", both), opts: RunOptions{Harness: "claude"},
			check: profile(profiles.AnthropicID), want: []string{fallback}},
	})
	// The run's record keeps the configured choice: a resume with the same
	// --llm does not call it ignored.
	ta := newTestApp(t, "")
	configured("bedrock", both)(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	sb := ta.mustGet(t, sbName)
	if got := resumeIgnores(RunOptions{LLM: LLMBedrock}, sb, ta.runLaunchOf(sb)); len(got) != 0 {
		t.Fatalf("a resume with the configured --llm ignores %v", got)
	}
	ta = newTestApp(t, "")
	configured("bedrock", map[string]string{"ANTHROPIC_API_KEY": "k"})(ta)
	wantErr(t, ta.Run(bg, RunOptions{Harness: "codex"}),
		"openshell.llm bedrock: no credential found (set AWS_BEARER_TOKEN_BEDROCK; `--llm auto` overrides openshell.llm for one run)")
	if n := ta.creates(); n != 0 {
		t.Fatalf("create calls = %d, want none", n)
	}
}

// openshell.llm is one key for every harness: a harness that shares no
// model credential (Kiro, Cursor Agent, Amp, Devin) takes auto without a
// note on every run; one that shares others but not this one is told.
func TestRunLLMNotesOnlyAHarnessWithOtherCredentials(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.LLM = LLMBedrock
	for _, h := range []string{"kiro", "cursor", "amp", "devin"} {
		spec := harnessSpec(t, h)
		if choice, from, note := ta.runLLM(spec, ""); choice != LLMAuto || from != llmFromFlag || note != "" {
			t.Fatalf("runLLM(%s) = %q, %q, %q; want auto without a note", h, choice, from, note)
		}
	}
	claude := harnessSpec(t, "claudecode")
	if _, _, note := ta.runLLM(claude, ""); note != "" {
		t.Fatalf("runLLM(claude) notes %q for a provider it can use", note)
	}
	ta.Cfg.OpenShell.LLM = LLMGemini
	if _, _, note := ta.runLLM(claude, ""); !strings.Contains(note, "which Claude Code cannot use") {
		t.Fatalf("runLLM(claude) with gemini: note = %q", note)
	}
}

// A --credential binding of the model's key wins over the detected
// credential, and the banner says where the key comes from; --github-write
// binds the token, by both names, to the API host alone and says what that
// allows. No secret is printed.
func TestRunCredentials(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["ANTHROPIC_API_KEY"] = "mock-key"
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Credentials: []string{"ANTHROPIC_API_KEY=host.openshell.internal:28921"}}))
	if req := createRequest(t, ta.daemon); req.LLM != nil || len(req.Credentials) != 1 || req.Credentials[0].Port != 28921 {
		t.Fatalf("create request = %+v", req)
	}
	has(t, ta.output(), "Model     ANTHROPIC_API_KEY comes from --credential")
	lacks(t, ta.output(), "mock-key")

	ta = newTestApp(t, "")
	ta.env["GITHUB_TOKEN"] = "gh-test-token"
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", GitHubWrite: true}))
	var names []string
	for _, c := range createRequest(t, ta.daemon).Credentials {
		if c.Host != "api.github.com" || c.Value != "gh-test-token" {
			t.Fatalf("credential = %+v", c)
		}
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"GH_TOKEN", "GITHUB_TOKEN"}) {
		t.Fatalf("bound names = %v", names)
	}
	has(t, ta.output(), "GH_TOKEN/GITHUB_TOKEN → api.github.com only", "with everything the token may do", "`git push` over HTTPS is not authenticated")
	lacks(t, ta.output(), "gh-test-token")
}

// A launch that fails before the session (the probe, the harness's start,
// the copy's upload) leaves no sandbox behind: nothing else would delete it
// (a detached run cannot take --rm). A failed upload probes no workdir,
// which does not exist.
func TestRunFailedLaunchDeletesTheSandbox(t *testing.T) {
	for _, c := range []struct {
		name, sandbox string
		opts          RunOptions
		setup         func(*testApp)
		want          string
	}{
		{"probe", sbName, RunOptions{Harness: "claude"}, func(ta *testApp) {
			ta.stream.answer = func([]string) (int, string) { return 124, "timed out" }
		}, "does not answer"},
		{"detached start", sbName, RunOptions{Harness: "claude", Detach: true, Prompt: "fix the failing tests"}, func(ta *testApp) {
			ta.IO.TTY = false
			ta.stream.answer = func(argv []string) (int, string) {
				if cmd := sandboxCommand(argv); len(cmd) > 0 && cmd[0] == "sh" {
					return 1, "mkdir: read-only file system"
				}
				return 0, ""
			}
		}, "start Claude Code in the background: exit status 1"},
		{"attached start", sbName, RunOptions{Harness: "claude"}, func(ta *testApp) {
			ta.term.startErr = errors.New("exec: openshell: permission denied")
		}, "permission denied"},
		{"copy upload", "copybox", RunOptions{Harness: "claude", Copy: true, Name: "copybox"}, func(ta *testApp) {
			ta.Workspace = &failingUpload{fakeCopy: ta.copy}
		}, "upload the project copy"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			c.setup(ta)
			wantErr(t, ta.Run(bg, c.opts), c.want)
			ta.wantCalls(t, 1, "DELETE", c.sandbox)
			has(t, ta.output(), "removing sandbox "+c.sandbox+" after the failure")
			if runs := ta.stream.commands(); c.sandbox == "copybox" && len(runs) != 0 {
				t.Fatalf("execs before the upload: %q", runs)
			}
		})
	}
}

type failingUpload struct{ *fakeCopy }

func (f *failingUpload) Upload(context.Context, string, string, workspace.Uploader, workspace.Execer) (*workspace.CopyRecord, error) {
	return nil, errors.New("openshell upload failed (exit 1)")
}

// A copy-mode run stages, creates the sandbox, uploads, sets the baseline,
// and only then probes the workdir (it exists once the copy is uploaded)
// and starts the harness; at its end it brings the changes back.
func TestRunCopySession(t *testing.T) {
	const workdir = "/sandbox/work/proj"
	start := []string{"stage copybox", "create copybox", "upload copybox", "baseline copybox", "exec true in " + workdir}
	for _, c := range []struct {
		name string
		opts RunOptions
		want []string
	}{
		{"attached", RunOptions{Harness: "claude", Copy: true, Name: "copybox"}, append(slices.Clone(start), "attach", "pull copybox", "apply apply")},
		{"detached", RunOptions{Harness: "claude", Copy: true, Name: "copybox", Detach: true, Prompt: "fix it"}, append(slices.Clone(start), "exec sh in "+workdir)},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "a\n")
			ta.IO.TTY = !c.opts.Detach
			ta.ok(t, ta.Run(bg, c.opts))
			if got := ta.daemon.timeline.list(); !slices.Equal(got, c.want) {
				t.Fatalf("steps =\n%q\nwant\n%q", got, c.want)
			}
			if req := createRequest(t, ta.daemon); !req.Copy || req.Name != "copybox" {
				t.Fatalf("create request = %+v", req)
			}
			if c.opts.Detach {
				return
			}
			if r := ta.bodies("POST", "copybox/workspace"); len(r) != 2 || !strings.Contains(r[0], `"operation":"upload"`) || !strings.Contains(r[1], `"pull_mode":"apply"`) {
				t.Fatalf("workspace reports = %q", r)
			}
			has(t, ta.output(), "Project   ~/proj → /sandbox/work/proj (copy)", "applied 1 change to ~/proj", "1 file changed (+4 −1)",
				"⚠ nested repository vendor/lib is not copied")
			// The held-back secrets are named once (cert copilot:F5).
			if out := ta.output(); strings.Count(out, ".env") != 1 || !strings.Contains(out, "⚠ 1 secret file held back from the copy: .env") {
				t.Fatalf("held-back lines:\n%s", out)
			}
		})
	}
}

// A copy-mode stage is this run's own when the daemon refuses the create
// for anything but the name, also after the fallback from a live mount: it
// is removed. When the daemon refuses the name (another run took it
// meanwhile), the stage is left alone.
func TestRunCopyCleansItsStageWhenTheCreateFails(t *testing.T) {
	unavailable := &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable, Message: "no verified image"}
	for _, c := range []struct {
		name   string
		opts   RunOptions
		refuse func(sandboxapi.CreateRequest) *sandboxapi.Error
		steps  []string
		want   string
	}{
		{"refused", RunOptions{Harness: "claude", Copy: true, Name: "copybox"}, func(sandboxapi.CreateRequest) *sandboxapi.Error { return unavailable },
			[]string{"stage copybox", "discard copybox"}, "no verified image"},
		{"name taken meanwhile", RunOptions{Harness: "claude", Copy: true, Name: "copybox"}, func(sandboxapi.CreateRequest) *sandboxapi.Error {
			return &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: "a sandbox named copybox already exists"}
		}, []string{"stage copybox"}, "resume it with `defenseclaw sandbox connect copybox`"},
		{"the fallback's copy refused too", RunOptions{Harness: "codex", Name: "wt"}, func(req sandboxapi.CreateRequest) *sandboxapi.Error {
			if req.Copy {
				return unavailable
			}
			return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy", Detail: "a linked worktree"}
		}, []string{"stage wt", "discard wt"}, "no verified image"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.refuseCreate = c.refuse
			wantErr(t, ta.Run(bg, c.opts), c.want)
			if !slices.Equal(ta.copy.steps, c.steps) {
				t.Fatalf("copy steps = %v, want %v", ta.copy.steps, c.steps)
			}
		})
	}
}

// Resuming a copy-mode sandbox with --refresh probes outside the workdir
// (a failed refresh may have left none), then refreshes, then attaches; a
// plain resume probes the workdir.
func TestConnectRefreshOrdersProbeRefreshAttach(t *testing.T) {
	for _, refresh := range []bool{true, false} {
		t.Run(fmt.Sprintf("refresh=%t", refresh), func(t *testing.T) {
			ta := newTestApp(t, "s\n", copySandbox("copybox"))
			ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "copybox", Refresh: refresh}))
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
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Copy: true, Name: "plainbox"}))
	has(t, ta.output(), "Bring the changes back? [A] apply (3-way)  [p] patch file  [s] skip")
	lacks(t, ta.output(), "branch dc/")
	if len(ta.copy.apply) != 1 || ta.copy.apply[0].Mode != workspace.ApplyPatch {
		t.Fatalf("apply = %+v", ta.copy.apply)
	}
	wantErr(t, ta.Pull(bg, PullOptions{Name: "plainbox", Branch: true}), "not a git repository", "--apply or --patch-out")
	if len(ta.copy.apply) != 1 {
		t.Fatal("pull --branch applied something")
	}
}

// TestRunFallsBackToCopyMode pins the plan's fallback: a project the
// daemon cannot mount live (a linked worktree, a git directory outside the
// folder) runs in copy mode instead of failing, explained in one sentence
// with the daemon's reason unwrapped and without advice the run already
// follows (manual R2-28).
func TestRunFallsBackToCopyMode(t *testing.T) {
	ta := newTestApp(t, "a\n")
	ta.env["OPENAI_API_KEY"] = "sk-openai-test"
	ta.daemon.refuseCreate = func(req sandboxapi.CreateRequest) *sandboxapi.Error {
		if req.Copy {
			return nil
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy",
			Detail: "workspace: " + ta.project + " cannot be mounted live: its git directory lives at " + ta.home + "/main/.git/worktrees/proj, " +
				"outside the folder (a git worktree or submodule checkout); run with --copy to work on a copy"}
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "codex", Name: "wt"}))
	creates := ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)
	if len(creates) != 2 || strings.Contains(string(creates[0].Body), `"copy":true`) || !strings.Contains(string(creates[1].Body), `"copy":true`) {
		t.Fatalf("create calls = %d, want a live mount and then a copy", len(creates))
	}
	if want := []string{"stage wt", "upload wt"}; len(ta.copy.steps) < 2 || !slices.Equal(ta.copy.steps[:2], want) {
		t.Fatalf("copy steps = %v, want %v first", ta.copy.steps, want)
	}
	has(t, ta.output(), "⚠ ~/proj can't be mounted live (its git directory lives at ~/main/.git/worktrees/proj, outside the folder "+
		"(a git worktree or submodule checkout)), so it runs on a copy: `defenseclaw sandbox pull wt` brings the changes back")
	lacks(t, ta.output(), "with --copy")

	// The daemon's needs-copy answer on a driver without host mounts, to a
	// run whose status did not name the driver (a daemon that reconnected
	// to a MicroVM gateway since): the same one sentence, with the driver's
	// reason.
	ta = newTestApp(t, "a\n")
	ta.daemon.refuseCreate = func(req sandboxapi.CreateRequest) *sandboxapi.Error {
		if req.Copy {
			return nil
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy",
			Detail: ta.project + " cannot be mounted live: the OpenShell MicroVM (vm) driver mounts no host folders"}
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "opencode", Name: "vmbox"}))
	has(t, ta.output(), "⚠ ~/proj can't be mounted live (the OpenShell MicroVM (vm) driver mounts no host folders), so it runs on a copy: "+
		"`defenseclaw sandbox pull vmbox` brings the changes back")
}

func TestSummaryLine(t *testing.T) {
	egress := func(n int) *sandboxapi.Sandbox {
		return &sandboxapi.Sandbox{Egress: sandboxapi.EgressStats{Destinations: n, Blocked: n}}
	}
	failed := sampleSandbox("f-box")
	failed.Hooks.HookFailed = 2
	asked := sampleSandbox("a-box")
	asked.Hooks.ToolAsked = 1
	onlyAsked := &sandboxapi.Sandbox{Hooks: sandboxapi.HookCoverage{ToolCalls: 2, ToolAsked: 1}}
	for _, c := range []struct {
		before, after *sandboxapi.Sandbox
		want          string
	}{
		{egress(1), egress(1), "Session ended · 0 tool calls · 0 new sites contacted"},
		{egress(1), egress(2), "Session ended · 0 tool calls · 1 new site contacted · 1 site blocked"},
		{egress(1), egress(3), "Session ended · 0 tool calls · 2 new sites contacted · 2 sites blocked"},
		// Hook calls DefenseClaw answered with an error were blocked (the
		// hooks fail closed).
		{&sandboxapi.Sandbox{Hooks: sandboxapi.HookCoverage{HookFailed: 1}}, &failed,
			"Session ended · 4 tool calls (1 blocked: marker) · 1 hook call failed (blocked) · 3 new sites contacted · 1 site blocked"},
		{&failed, &failed, "Session ended · 0 tool calls · 0 new sites contacted"},
		// DefenseClaw's asks, which the harness put to the user.
		{&sandboxapi.Sandbox{}, &asked, "Session ended · 4 tool calls (1 blocked: marker; 1 asked) · 3 new sites contacted · 1 site blocked"},
		{&sandboxapi.Sandbox{}, onlyAsked, "Session ended · 2 tool calls (1 asked) · 0 new sites contacted"},
	} {
		s := &session{app: newTestApp(t, "").App, before: c.before}
		if got := s.summaryLine(c.after, nil); got != c.want {
			t.Errorf("summaryLine(%+v) = %q, want %q", c.after.Egress, got, c.want)
		}
	}
	// The blocked sites are the ✗ lines the session announced, one per
	// destination however often it was tried, also when the daemon had
	// blocked one of them before the session (cert copilot:F8, kiro:KR-F7,
	// hermes:HERMES-8, openhands:MAC-OSH-OH-5: an invalid destination and
	// webhook.site read "1 request blocked" over two ✗ lines).
	box := sampleSandbox("f-box")
	s := &session{app: newTestApp(t, "").App, sb: &box, before: egress(1)}
	for _, ev := range []sandboxapi.ActivityEvent{
		{Kind: sandboxapi.ActivityEgressBlocked, Host: "echo", Port: 80, Category: "invalid_destination"},
		{Kind: sandboxapi.ActivityEgressBlocked, Host: "echo", Port: 80, Category: "invalid_destination"},
		{Kind: sandboxapi.ActivityEgressBlocked, Host: "webhook.site", Port: 443, Category: "webhook_catcher"},
	} {
		s.blockNotice(ev)
	}
	if got, want := s.summaryLine(egress(2), nil), "Session ended · 0 tool calls · 1 new site contacted · 2 sites blocked"; got != want {
		t.Errorf("summaryLine after two blocked destinations = %q, want %q", got, want)
	}
	// Manual R2-17: a blocked call is named by its rule's title and ID, not
	// the cut-off start of the reason.
	for in, want := range map[string]string{
		"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach that does not need this action, " +
			"or ask the user to review the DefenseClaw policy.": "E2E sandbox marker command (E2E-SANDBOX-MARKER)",
		"Blocked by DefenseClaw rule CMD-1: Destructive command (also CMD-2). Do not.": "Destructive command (CMD-1)",
		"Blocked by DefenseClaw rule CMD-1. Do not.":                                   "CMD-1",
		"Blocked by DefenseClaw policy. Try another approach.":                         "DefenseClaw policy",
		// The host hook's wording (GAP-1885).
		"DefenseClaw policy blocked this action (rule E2E-SANDBOX-MARKER: E2E sandbox marker command). Do not retry it in another form.": "E2E sandbox marker command (E2E-SANDBOX-MARKER)",
		"DefenseClaw policy blocked this action (rules CMD-1: Destructive command, CMD-2). Do not retry it in another form.":             "Destructive command (CMD-1)",
		"DefenseClaw policy blocked this action. Do not retry it in another form.":                                                       "DefenseClaw policy",
		"marker": "marker",
	} {
		if got := blockedReason(in); got != want {
			t.Errorf("blockedReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// The banner's Host line lists only the ports the daemon accepted, with the
// refusal's reason, and its permissions say whose choice they are (manual
// tests M15, R2-89).
func TestBanner(t *testing.T) {
	off := false
	refused := func(port, constraint, message, detail string) func(*testApp, *sandboxapi.Sandbox) {
		return func(_ *testApp, sb *sandboxapi.Sandbox) {
			sb.Violations = []sandboxapi.Violation{{Key: "mcp.host_ports", Attempted: port, Constraint: constraint, Message: message, Detail: detail}}
		}
	}
	for _, c := range []struct {
		name      string
		edit      func(*testApp, *sandboxapi.Sandbox)
		ports     []int
		want, not []string
	}{
		{"a port DefenseClaw never opens", refused("18970", "defenseclaw", "DefenseClaw never opens DefenseClaw's API (port 18970) to a sandbox", ""),
			[]int{5432, 18970, 5432}, []string{"Host      localhost:5432 (opens when you approve the sandbox's first connection)"}, []string{"localhost:18970"}},
		{"every port refused", refused("5432", "pack strict", "", ""), []int{5432}, nil, []string{"Host "}},
		{"the pack's refusal", refused("3000", "pack strict", "not allowed by the strict sandbox pack: mcp.host_ports", "the pack does not open host ports"),
			[]int{3000, 4000}, []string{"Host      localhost:4000 (opens when you approve",
				"not allowed by the strict sandbox pack: mcp.host_ports — the pack does not open host ports"}, []string{"localhost:3000"}},
		{"the organization keeps the prompts", func(ta *testApp, sb *sandboxapi.Sandbox) {
			ta.Cfg.OpenShell.Admin.AllowYolo, sb.Launch.Yolo = &off, false
		}, nil, []string{"skip-permissions OFF (your organization disables skip-permissions)"}, nil},
		{"the harness keeps the prompts", func(_ *testApp, sb *sandboxapi.Sandbox) { sb.Launch.Yolo = false }, nil,
			[]string{"skip-permissions OFF (harness prompts kept)"}, nil},
		{"omnigent", func(_ *testApp, sb *sandboxapi.Sandbox) { sb.Harness, sb.HarnessName = "omnigent", "OmniGent" }, nil,
			[]string{"OmniGent · approvals from OmniGent's policies, DefenseClaw's included"}, []string{"skip-permissions"}},
		// A user tier says what the image protects for that harness: Kiro's
		// and Hermes' hooks are root-owned (cert kiro:KR-F3,
		// hermes:HERMES-3).
		{"kiro's tier", func(_ *testApp, sb *sandboxapi.Sandbox) {
			sb.Harness, sb.HarnessName, sb.TamperTier = "kiro", "Kiro CLI", "user"
		}, nil,
			[]string{"Hooks     user tier: the hooks and the DefenseClaw agent that runs them are root-owned; Kiro's user and project settings, MCP servers and the TUI runtime it unpacks into the sandbox home are the agent's to edit"},
			[]string{"could edit its own hook settings"}},
		{"hermes' tier", func(_ *testApp, sb *sandboxapi.Sandbox) {
			sb.Harness, sb.HarnessName, sb.TamperTier = "hermes", "Hermes Agent", "user"
		}, nil,
			[]string{"Hooks     user tier: the hooks and their config (/etc/hermes/config.yaml) are root-owned; the Hermes home (.env files, profiles, plugins) is the agent's to write, and the launcher checks it at every start (hook silence is detected)"},
			nil},
		{"a managed tier", func(_ *testApp, sb *sandboxapi.Sandbox) { sb.TamperTier = "managed" }, nil, nil, []string{"Hooks "}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			sb := sampleSandbox("box")
			c.edit(ta, &sb)
			ta.banner(&sb, bannerInfo{o: RunOptions{HostPorts: c.ports}})
			has(t, ta.output(), c.want...)
			lacks(t, ta.output(), c.not...)
		})
	}
	for name, want := range map[string]string{"OpenHands": "an OpenHands", "OmniGent": "an OmniGent", "Codex": "a Codex"} {
		if got := withArticle(name); got != want {
			t.Errorf("withArticle(%s) = %q", name, got)
		}
	}
}

// silently runs o, which must end without an error of its own: the user
// declined.
func silently(o RunOptions) func(*testApp) error {
	return func(ta *testApp) error {
		var silent *Silent
		if err := ta.Run(bg, o); !errors.As(err, &silent) {
			return fmt.Errorf("Run = %v, want a silent end", err)
		}
		return nil
	}
}

// What the organization changed about a run is said before anything is
// copied or created, once; a flag it overrode (--profile under a required
// pack, --cpu above its limit) is confirmed on a terminal, and declining
// creates nothing (manual tests M10: `--profile open` under a required
// strict pack went straight to copying; R2-102: a limit reads as a limit).
func TestRunSaysWhatThePolicyOverrodeFirst(t *testing.T) {
	profile := sandboxapi.Violation{Key: "profile", Source: "flag", Attempted: "open", Enforced: "strict", Admin: true,
		Constraint: "openshell.admin.required_pack", Detail: "your organization requires the strict sandbox pack, whose profile is strict"}
	profileSaid := "limited by your organization's DefenseClaw policy: profile — your organization requires the strict sandbox pack, " +
		"whose profile is strict (openshell.admin.required_pack); running with profile strict instead of open"
	cpu := sandboxapi.Setting{Key: "resources.cpu", Value: "1", Source: "admin", Origin: "openshell.admin.max_resources", Requested: "(unlimited)"}
	cpuSaid := "running with resources.cpu 1 instead of 4"
	confirm := "overrides a flag you passed. Run with its setting? [Y/n]"
	nothingMade := func(t *testing.T, ta *testApp) {
		if len(ta.copy.steps) != 0 || ta.creates() != 0 {
			t.Fatalf("a declined run copied or created: %v", ta.copy.steps)
		}
	}
	// once checks said is said once, and, for a copy, before the copying.
	once := func(said string, copied bool) func(*testing.T, *testApp) {
		return func(t *testing.T, ta *testApp) {
			out := ta.output()
			if strings.Count(out, said) != 1 || (copied && strings.Index(out, said) > strings.Index(out, "Copying")) {
				t.Fatalf("%q is not said once, before the copy:\n%s", said, out)
			}
		}
	}
	copyRun := RunOptions{Harness: "claude", Copy: true, Name: "copybox", Profile: "open"}
	headless := copyRun
	headless.Detach, headless.Prompt = true, "x"
	runCases(t, []runCase{
		{name: "profile declined", input: "n\n", setup: func(ta *testApp) { ta.daemon.explain.Violations = []sandboxapi.Violation{profile} },
			do: silently(copyRun), want: []string{profileSaid, confirm}, check: nothingMade},
		{name: "profile without a terminal", setup: func(ta *testApp) {
			ta.IO.TTY = false
			ta.daemon.explain.Violations = []sandboxapi.Violation{profile}
			ta.daemon.createViolations = []sandboxapi.Violation{profile}
		}, opts: headless, check: once(profileSaid, true)},
		{name: "cpu declined", input: "n\n", setup: func(ta *testApp) { ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, cpu) },
			do: silently(RunOptions{Harness: "claude", CPU: "4"}), check: nothingMade, want: []string{confirm, "cancelled; no sandbox was created",
				"⚠ limited by your organization's DefenseClaw policy: resources.cpu — your organization caps sandbox cpu at 1 " +
					"(openshell.admin.max_resources); " + cpuSaid}},
		// Accepted, the banner does not repeat the daemon's own clamp.
		{name: "cpu accepted", input: "y\ny\n", setup: func(ta *testApp) {
			ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, cpu)
			ta.daemon.createViolations = []sandboxapi.Violation{{Key: "resources.cpu", Source: "flag", Attempted: "4", Enforced: "1", Admin: true,
				Constraint: "openshell.admin.max_resources", Message: sandboxapi.AdminMessage + ": resources.cpu", Detail: "your organization caps sandbox cpu at 1"}}
		}, opts: RunOptions{Harness: "claude", CPU: "4"}, check: once(cpuSaid, false)},
	})
	// Within the limit, nothing is said.
	if got := resourceClamps(RunOptions{CPU: "500m"}, &sandboxapi.Explain{Settings: []sandboxapi.Setting{cpu}}); len(got) != 0 {
		t.Fatalf("resourceClamps = %+v", got)
	}
}

// `claude --version` through the shell wrapper runs no session: the
// installed harness answers, or the sandbox image's version does (manual
// test L5: it resumed a sandbox for 20 s and then stopped it).
func TestRunAnswersVersionAndHelpWithoutASandbox(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.Environ = func() []string { return []string{"PATH=/usr/bin"} }
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Args: []string{"--version"}}))
	if len(ta.execs) != 1 || !slices.Equal(ta.execs[0], []string{"/usr/bin/claude", "claude", "--version"}) || len(ta.daemon.paths()) != 0 {
		t.Fatalf("execs = %q, daemon calls %v", ta.execs, ta.daemon.paths())
	}
	// Not installed here (or reached again through a command that calls
	// the sandbox): the image answers.
	ta = newTestApp(t, "")
	ta.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	ta.images.recs = []image.Record{
		{Connector: "claudecode", HarnessVersion: "2.1.0", HookFireVerified: true, BuiltAt: time.Now().Add(-time.Hour)},
		{Connector: "claudecode", HarnessVersion: "2.1.4", HookFireVerified: true, BuiltAt: time.Now()},
		{Connector: "codex", HarnessVersion: "0.99.0", HookFireVerified: true, BuiltAt: time.Now()},
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Args: []string{"-v"}}))
	if out := ta.output(); strings.TrimSpace(out) != "2.1.4 (Claude Code, in the DefenseClaw sandbox image)" {
		t.Fatalf("output: %q", out)
	}
	ta.ok(t, ta.fresh().Run(bg, RunOptions{Harness: "claude", Args: []string{"--help"}}))
	has(t, ta.output(), "defenseclaw sandbox run claude [-- Claude Code arguments]")
	ta.images.recs = nil
	wantErr(t, ta.Run(bg, RunOptions{Harness: "claude", Args: []string{"--version"}}), "`defenseclaw sandbox image build claude`")
	if len(ta.execs) != 0 || len(ta.daemon.paths()) != 0 {
		t.Fatal("a version query ran something")
	}
	// Anything else is a session.
	for _, o := range []RunOptions{{Harness: "claude", Args: []string{"--version", "x"}}, {Harness: "claude", Args: []string{"-v"}, Prompt: "x", Detach: true}} {
		if infoArgs(o) {
			t.Errorf("infoArgs(%+v) = true", o)
		}
	}
	ta = newTestApp(t, "")
	ta.env["DEFENSECLAW_NO_SANDBOX"] = "1"
	ta.images.recs = []image.Record{{Connector: "claudecode", HarnessVersion: "2.1.4", HookFireVerified: true, BuiltAt: time.Now()}}
	if err := ta.Run(bg, RunOptions{Harness: "claude", Args: []string{"--version"}}); err != nil || len(ta.execs) != 0 {
		t.Fatalf("Run = %v, execs %q; a command that calls the sandbox again must not loop", err, ta.execs)
	}
}

// `claude mcp add ...` through the shell wrapper manages Claude Code on
// this machine: it runs with the installed harness, with no sandbox (a
// first one would build the image) and no review; `claude mcp serve`, an
// agent, and everything else still run in the sandbox.
func TestRunManagesTheHostHarnessWithoutASandbox(t *testing.T) {
	for _, args := range [][]string{{"mcp", "add", "dc-marker", "--", "echo"}, {"mcp", "list"}, {"mcp"}, {"config", "get", "theme"}, {"update"}} {
		ta := newTestApp(t, "")
		ta.Environ = func() []string { return []string{"PATH=/usr/bin"} }
		ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Args: args}))
		if want := append([]string{"/usr/bin/claude", "claude"}, args...); len(ta.execs) != 1 || !slices.Equal(ta.execs[0], want) || len(ta.daemon.paths()) != 0 {
			t.Fatalf("%q: execs = %q, daemon calls %v", args, ta.execs, ta.daemon.paths())
		}
		has(t, ta.err.String(), "manages Claude Code on this machine, so it runs outside the sandbox")
	}
	if !hostArgs(harnessSpec(t, "codex"), RunOptions{Args: []string{"login", "--with-api-key"}}) {
		t.Fatal("codex login is not a host command")
	}
	for _, o := range []RunOptions{
		{Args: []string{"mcp", "serve"}}, {Args: []string{"-p", "mcp list"}}, {Args: []string{"mcp", "list"}, Prompt: "x"}, {Args: []string{"fix", "the", "tests"}},
	} {
		if hostArgs(harnessSpec(t, "claudecode"), o) {
			t.Errorf("hostArgs(%+v) = true; it must run in the sandbox", o)
		}
	}
	// Not installed here: say where the harness is.
	ta := newTestApp(t, "")
	ta.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	wantErr(t, ta.Run(bg, RunOptions{Harness: "claude", Args: []string{"mcp", "list"}}), "manages Claude Code on this machine, where it is not installed")
	if len(ta.daemon.paths()) != 0 {
		t.Fatal("the host command reached the daemon")
	}
}

// Manual R2-76: an --env name that says it holds a secret is warned about,
// without its value.
func TestSecretLookingEnvIsWarned(t *testing.T) {
	for name, want := range map[string]bool{"KIRO_API_KEY": true, "GITHUB_TOKEN": true, "DB_PASSWORD": true, "OPENAI_KEY": true,
		"ANTHROPIC_BASE_URL": false, "KIRO_MOCK_CHAT_RESPONSE": false, "TOKENIZERS_PARALLELISM": false, "KEYBOARD": false} {
		if got := secretLooking(name); got != want {
			t.Errorf("secretLooking(%s) = %v", name, got)
		}
	}
	ta := newTestApp(t, "")
	ta.warnSecretEnv(map[string]string{"KIRO_API_KEY": "dclive-x", "ANTHROPIC_BASE_URL": "http://h"})
	if out := ta.output(); strings.Count(out, "looks like a secret") != 1 {
		t.Fatalf("output:\n%s", out)
	}
	has(t, ta.output(), "`--credential KIRO_API_KEY=HOST` gives it a placeholder that works only at HOST")
	lacks(t, ta.output(), "dclive-x")
}

// Manual R2-106: a workspace failure on a full disk says so.
func TestDiskFullIsNamed(t *testing.T) {
	ta := newTestApp(t, "")
	for _, err := range []error{fmt.Errorf("write: %w", syscall.ENOSPC), errors.New("git: fatal: sha1 file write error: No space left on device")} {
		has(t, ta.diskFullHint(err), "is full (no space left on device")
	}
	if hint := ta.diskFullHint(errors.New("connection reset")); hint != "" {
		t.Errorf("an unrelated failure got %q", hint)
	}
}

// TestRunOnTheMicroVMDriver: on a gateway whose compute driver mounts no
// host folders (OpenShell's MicroVM driver, which a Mac runs sandboxes
// with) every run works on a copy, said in one line before the copy is
// made, whether the daemon clamped the mode itself or not. A flag the
// driver cannot honour is refused (--context) or named (--no-snapshot,
// --cpu, --memory) before anything is copied or created, and the first
// boot of an image says it takes a while. The docker driver's runs are
// unchanged.
func TestRunOnTheMicroVMDriver(t *testing.T) {
	// Certification OG-U9: the note said the folder got its changes only
	// through `sandbox pull`, while the session's end offers to bring them
	// back itself.
	const note = "copy mode: the OpenShell MicroVM (vm) driver mounts no host folders; the agent works on a copy, " +
		"and your folder changes only when you bring its work back: at the end of the session, or later with `defenseclaw sandbox pull`"
	driver := func(name string, more ...func(*testApp)) func(*testApp) {
		return func(ta *testApp) {
			ta.daemon.status.Gateway.Driver = name
			for _, f := range more {
				f(ta)
			}
		}
	}
	// copied checks the run asked for a copy and said so once, before the
	// copy was made.
	copied := func(said string) func(*testing.T, *testApp) {
		return func(t *testing.T, ta *testApp) {
			t.Helper()
			req := createRequest(t, ta.daemon)
			if !req.Copy {
				t.Fatalf("create request = %+v, want a copy", req)
			}
			out := ta.output()
			if strings.Count(out, said) != 1 || strings.Index(out, said) > strings.Index(out, "Copying") {
				t.Fatalf("%q is not said once, before the copy:\n%s", said, out)
			}
			if got := ta.copy.steps; len(got) < 2 || got[0] != "stage "+req.Name || got[1] != "upload "+req.Name {
				t.Fatalf("copy steps = %v", got)
			}
		}
	}
	// The daemon's own clamp of a mount the user configured, as the
	// resolver gives it: its source is the gateway, not the organization.
	clamped := func(ta *testApp) {
		ta.daemon.explain.Settings[0] = sandboxapi.Setting{Key: "workdir.mode", Value: "copy", Source: string(packs.SourceGateway),
			Origin: packs.ConstraintComputeDriver, Requested: "mount"}
		clamp := sandboxapi.Violation{Key: "workdir.mode", Source: "user", Attempted: "mount", Enforced: "copy", Constraint: packs.ConstraintComputeDriver,
			Message: "the project cannot be mounted live on this gateway; the agent works on a copy", Detail: "the OpenShell MicroVM (vm) driver mounts no host folders"}
		ta.daemon.explain.Violations = []sandboxapi.Violation{clamp}
		ta.daemon.createViolations = []sandboxapi.Violation{clamp}
	}
	// An organization's cap on --cpu, which a MicroVM does not take.
	capped := func(ta *testApp) {
		ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
			sandboxapi.Setting{Key: "resources.cpu", Value: "1", Source: "admin", Origin: "openshell.admin.max_resources"})
		ta.daemon.createWarnings = []string{limitsIgnoredText}
	}
	firstBoot := func(ta *testApp) { ta.daemon.explain.VMFirstBoot = true }
	missing := func(ta *testApp) { ta.images.missing = map[string]bool{"claudecode": true} }
	refused := func(o RunOptions, want string) func(*testApp) error {
		return func(ta *testApp) error {
			err := ta.Run(bg, o)
			if err == nil || !strings.Contains(err.Error(), want) {
				return fmt.Errorf("Run = %v, want %q", err, want)
			}
			if ta.creates() != 0 || len(ta.copy.steps) != 0 {
				return fmt.Errorf("a refused run created %d sandboxes and staged %v", ta.creates(), ta.copy.steps)
			}
			return nil
		}
	}
	run := RunOptions{Harness: "claude"}
	runCases(t, []runCase{
		{name: "every run works on a copy", input: "a\n", setup: driver("vm"), opts: run, check: copied(note),
			want: []string{"Project   ~/proj → /sandbox/work/proj (copy)", "applied 1 change to ~/proj"}},
		{name: "--copy needs no note", input: "a\n", setup: driver("vm"), opts: RunOptions{Harness: "claude", Copy: true}, not: []string{note}},
		// The clamp is the gateway's, not the organization's.
		{name: "the daemon's own clamp", input: "a\n", setup: driver("vm", clamped), opts: run, check: copied(note),
			not: []string{"organization", "Run with its setting?"}},
		{name: "a driver DefenseClaw does not know mounts nothing", input: "a\n", setup: driver("podman"), opts: run,
			check: copied("copy mode: this gateway's compute driver mounts no host folders")},
		{name: "--context is refused before anything is copied", setup: driver("vm"),
			do: refused(RunOptions{Harness: "claude", Context: []string{"/srv/lib"}}, "--context mounts a folder into the sandbox read-only, and "+
				"the OpenShell MicroVM (vm) driver mounts no host folders; run without --context")},
		{name: "--no-snapshot, --cpu and --memory are named", input: "a\n", setup: driver("vm", capped),
			opts: RunOptions{Harness: "claude", CPU: "4", Memory: "8Gi", NoSnapshot: true}, check: copied(limitsIgnoredText),
			want: []string{"--no-snapshot does not apply: the OpenShell MicroVM (vm) driver mounts no host folders, so the run works on a copy, which takes no snapshot"},
			not:  []string{"limited by your organization", "Run with its setting?"}},
		{name: "the first boot of an image", input: "a\n", setup: driver("vm", firstBoot), opts: run,
			want: []string{"Starting a Claude Code sandbox… (the first start prepares its MicroVM disk: about a minute)"}},
		{name: "a new image and its first boot", input: "a\n", setup: driver("vm", firstBoot, missing), opts: run,
			want: []string{"(building its image first, which can take a few minutes; then the first start prepares its MicroVM disk: about a minute)"}},
		// The disk a first boot prepares needs about the image's size and
		// headroom where the driver keeps it: short of the floor the run is
		// refused before anything is copied or created, and short of the
		// recommended space it is warned about (OC-F1).
		{name: "a first boot on a full disk", setup: driver("vm", firstBoot, func(ta *testApp) {
			ta.diskFree, ta.images.sizes = 2<<30, map[string]uint64{"claudecode": 7 << 30}
		}), do: refused(run, "not enough free disk space for this sandbox's first start: the MicroVM driver prepares a disk of about 7.0 GiB from its image in "+
			"~/.local/state/openshell/vm-driver/images, where 2.0 GiB is free and at least 8.0 GiB is needed; free space on that volume first "+
			"(`defenseclaw sandbox image prune` removes superseded harness images and the MicroVM disks prepared from them)")},
		{name: "a first boot of an image to build on a full disk", setup: driver("vm", firstBoot, missing, func(ta *testApp) { ta.diskFree = 5 << 30 }),
			do: refused(run, "a disk of about 5.0 GiB from its image in ~/.local/state/openshell/vm-driver/images, where 5.0 GiB is free and at least 6.0 GiB is needed")},
		{name: "a first boot with little room", input: "a\n", setup: driver("vm", firstBoot, func(ta *testApp) { ta.diskFree = 10 << 30 }), opts: run,
			want: []string{"only 10.0 GiB is free in ~/.local/state/openshell/vm-driver/images, and this sandbox's first start prepares a MicroVM disk of about 5.0 GiB there " +
				"(12.0 GiB or more is recommended; `defenseclaw sandbox image prune` removes superseded harness images and the MicroVM disks prepared from them)"},
			check: func(t *testing.T, ta *testApp) {
				if ta.creates() != 1 || !strings.HasPrefix(ta.diskProbed, ta.home) {
					t.Fatalf("creates %d, disk probed at %q", ta.creates(), ta.diskProbed)
				}
			}},
		// A disk prepared already needs no room, and docker prepares none.
		{name: "no first boot on a full disk", input: "a\n", setup: driver("vm", func(ta *testApp) { ta.diskFree = 1 << 30 }), opts: run,
			not: []string{"free disk space", "is free in"}},
		{name: "docker on a full disk", input: "y\n", setup: driver("docker", firstBoot, func(ta *testApp) { ta.diskFree = 1 << 30 }), opts: run,
			not: []string{"free disk space", "is free in"}},
		// On docker the mount, --context and the limits go to the daemon.
		{name: "the docker driver mounts", input: "y\n", setup: driver("docker"),
			opts: RunOptions{Harness: "claude", Context: []string{"/srv/lib"}, CPU: "2", NoSnapshot: true}, check: func(t *testing.T, ta *testApp) {
				if req := createRequest(t, ta.daemon); req.Copy || !slices.Equal(req.Context, []string{"/srv/lib"}) || req.CPU != "2" || !req.NoSnapshot {
					t.Fatalf("create request = %+v", req)
				}
			}, not: []string{"copy mode:", limitsIgnoredText, "does not apply", "Copying"}},
	})
}

// FIN-A-2: on MicroVMs the run image a run boots, and so whether its first
// start prepares a disk, depends on its --env and credentials, which the
// preflight took from the newest sandbox. The daemon is asked again with
// this run's: the values of the variables the run files read, a value that
// could be a secret by name only, and the credentials by name, never a
// secret. Its answer decides the note. A harness without run files, or a
// docker gateway, is not asked again.
func TestRunAsksAboutTheFirstBootOfItsOwnRunFiles(t *testing.T) {
	const endpoint = "http://host.openshell.internal:39942"
	run := RunOptions{Harness: "claude", Credentials: []string{"STRIPE_API_KEY=api.stripe.com"},
		Env: []string{"ANTHROPIC_BASE_URL=" + endpoint, "ANTHROPIC_CUSTOM_HEADERS=Authorization: Bearer hdr-test-value", "FOO=bar"}}
	setup := func(t *testing.T, driver string) *testApp {
		ta := newTestApp(t, "a\n")
		ta.daemon.status.Gateway.Driver = driver
		ta.env["ANTHROPIC_API_KEY"] = "sk-test-not-a-secret"
		ta.env["STRIPE_API_KEY"] = "stripe-test-value"
		// The newest sandbox's disk is prepared; this run's is not.
		ta.daemon.onExplain = func(req sandboxapi.ExplainRequest, ex *sandboxapi.Explain) {
			ex.VMFirstBoot = req.Run != nil && req.Run.Env["ANTHROPIC_BASE_URL"] == endpoint
		}
		return ta
	}
	// The explains of the run (the end-of-session pull asks for the
	// sandbox's own, for the review globs of its repository policy).
	explains := func(ta *testApp) []call {
		return slices.DeleteFunc(ta.daemon.callsTo("GET", sandboxapi.PathPolicyExplain),
			func(c call) bool { return strings.HasPrefix(c.Query, "sandbox=") })
	}

	ta := setup(t, "vm")
	ta.ok(t, ta.Run(bg, run))
	has(t, ta.output(), "Starting a Claude Code sandbox… (the first start prepares its MicroVM disk: about a minute)")
	calls := explains(ta)
	if len(calls) != 2 || strings.Contains(calls[0].Query, "run=") {
		t.Fatalf("explain calls = %+v", calls)
	}
	for _, secret := range []string{"sk-test-not-a-secret", "stripe-test-value", "hdr-test-value", "FOO"} {
		if strings.Contains(calls[1].Query, secret) {
			t.Fatalf("the explain of the run's files sent %q: %s", secret, calls[1].Query)
		}
	}
	q, err := url.ParseQuery(calls[1].Query)
	if err != nil {
		t.Fatal(err)
	}
	want := &sandboxapi.ExplainRun{Env: map[string]string{"ANTHROPIC_BASE_URL": endpoint}, EnvWithheld: []string{"ANTHROPIC_CUSTOM_HEADERS"},
		Credentials: []string{"ANTHROPIC_API_KEY", "STRIPE_API_KEY"}, LLMProfile: profiles.AnthropicID}
	if got := sandboxapi.ParseExplainQuery(q); got.Harness != "claudecode" || !reflect.DeepEqual(got.Run, want) {
		t.Fatalf("explain of the run's files = %+v, run %+v; want run %+v", got, got.Run, want)
	}

	// The same inputs as a prepared disk's: no note.
	ta = setup(t, "vm")
	ta.daemon.onExplain = func(req sandboxapi.ExplainRequest, ex *sandboxapi.Explain) { ex.VMFirstBoot = req.Run == nil }
	ta.ok(t, ta.Run(bg, run))
	lacks(t, ta.output(), "prepares its MicroVM disk")

	// Hooks-only OpenCode has no run files; docker prepares no disk.
	for name, tc := range map[string]struct{ driver, harness string }{"no run files": {"vm", "opencode"}, "docker": {"docker", "claude"}} {
		ta := setup(t, tc.driver)
		o := run
		o.Harness = tc.harness
		ta.ok(t, ta.Run(bg, o))
		if n := len(explains(ta)); n != 1 {
			t.Fatalf("%s: %d explain calls", name, n)
		}
	}

	// A base URL that carries a credential (a user name and password, a
	// query or a fragment value) goes by name only, as the daemon's check
	// of what would be baked into a run image (manager.CredentialURL) sees
	// it; one without such parts goes as it is.
	for _, base := range []string{"https://user:url-test-value@gw.example/v1", "https://gw.example/v1?key=url-test-value",
		"https://gw.example/v1#url-test-value"} {
		ta := setup(t, "vm")
		o := run
		o.Env = []string{"ANTHROPIC_BASE_URL=" + base, "ANTHROPIC_MODEL=claude-test"}
		ta.ok(t, ta.Run(bg, o))
		calls := explains(ta)
		if len(calls) != 2 || strings.Contains(calls[1].Query, "url-test-value") {
			t.Fatalf("%s: explain calls = %+v", base, calls)
		}
		q, err := url.ParseQuery(calls[1].Query)
		if err != nil {
			t.Fatal(err)
		}
		if got := sandboxapi.ParseExplainQuery(q).Run; got == nil || !slices.Equal(got.EnvWithheld, []string{"ANTHROPIC_BASE_URL"}) ||
			!maps.Equal(got.Env, map[string]string{"ANTHROPIC_MODEL": "claude-test"}) {
			t.Fatalf("%s: explain of the run's files = %+v", base, got)
		}
	}
}

// An upload that openshell reported done but the sandbox does not have
// fails the run, naming the doctor check for the ssh connection sharing
// that can carry it into another sandbox.
func TestCopyUploadThatDidNotArrive(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Gateway.Driver = "vm"
	ta.Workspace = &failingCopy{fakeCopy: ta.copy, uploadErr: &workspace.UploadNotArrivedError{Sandbox: "strayed", Dir: "/sandbox/work/proj", Missing: true}}
	wantErr(t, ta.Run(bg, RunOptions{Harness: "claude", Name: "strayed"}),
		"upload the project copy: the upload to strayed did not arrive: openshell reported it done, but in strayed /sandbox/work/proj is not there; ",
		"; `defenseclaw sandbox doctor` checks the ssh connection sharing that can carry an upload into another sandbox")
}

// failingCopy is a fakeCopy whose stage or upload fails with the error set.
type failingCopy struct {
	*fakeCopy
	stageErr, uploadErr error
}

func (f *failingCopy) Stage(ctx context.Context, o workspace.StageOptions) (*workspace.CopyRecord, error) {
	if f.stageErr != nil {
		f.step("stage " + o.Name)
		return nil, f.stageErr
	}
	return f.fakeCopy.Stage(ctx, o)
}

func (f *failingCopy) Upload(ctx context.Context, dataDir, name string, up workspace.Uploader, ex workspace.Execer) (*workspace.CopyRecord, error) {
	if f.uploadErr != nil {
		return nil, f.uploadErr
	}
	return f.fakeCopy.Upload(ctx, dataDir, name, up, ex)
}

// A copy too large to stage names the setting that raises the cap; on the
// MicroVM driver the refusal also says that a copy is the only way the
// project runs there, and what must hold it (a folder too large to copy
// could be mounted live on Linux). A disk full inside a MicroVM is its
// overlay disk, not this machine's.
func TestCopyLimitsOnTheMicroVMDriver(t *testing.T) {
	large := &workspace.TooLargeError{What: "the copy (files and history)", Size: 612 << 20, Limit: 500 << 20}
	onlyWay := "the OpenShell MicroVM (vm) driver mounts no host folders, so a copy is the only way this project runs on this gateway, " +
		"and the sandbox's own disk must hold it with its git history (overlay_disk_mib under [openshell.drivers.vm]"
	for _, driver := range []string{"docker", "vm"} {
		ta := newTestApp(t, "")
		ta.daemon.status.Gateway.Driver = driver
		ta.Workspace = &failingCopy{fakeCopy: ta.copy, stageErr: large}
		err := ta.Run(bg, RunOptions{Harness: "claude", Copy: true, Name: "bigbox"})
		wantErr(t, err, "stage the project copy: the copy (files and history) is", "above the",
			"; raise openshell.workdir.max_upload_mb (in MB, 500 by default) in "+ta.tildePath(ta.ConfigPath)+" to copy a larger project")
		if strings.Contains(err.Error(), onlyWay) != (driver == "vm") {
			t.Errorf("%s: %v", driver, err)
		}
		if ta.creates() != 0 {
			t.Fatalf("%s: a copy that could not be staged created a sandbox", driver)
		}
	}
	// Too many files is not the size cap.
	ta := newTestApp(t, "")
	if hint := ta.stageHint(&workspace.TooLargeError{What: "the folder", Size: 200001, Limit: 200000, Entries: true}, openshell.Driver{}); hint != "" {
		t.Errorf("an entry limit got %q", hint)
	}

	full := errors.New("openshell sandbox upload failed: tar: ./node_modules/x: Cannot write: No space left on device")
	overlay := "the sandbox's own disk is full (no space left on device): a MicroVM writes to an overlay disk sized by overlay_disk_mib under " +
		"[openshell.drivers.vm] in the OpenShell gateway's gateway.toml; free some space in the sandbox, or raise that size for new sandboxes " +
		"(`defenseclaw sandbox doctor` shows it)"
	ta = newTestApp(t, "")
	ta.daemon.status.Gateway.Driver = "vm"
	if hint := ta.sandboxDiskHint(bg, ta.API, full); hint != overlay {
		t.Errorf("a full MicroVM: %q", hint)
	}
	// This machine's own full disk is still its own.
	has(t, ta.sandboxDiskHint(bg, ta.API, fmt.Errorf("write: %w", syscall.ENOSPC)), "the disk holding")
	if hint := ta.sandboxDiskHint(bg, ta.API, errors.New("connection reset")); hint != "" {
		t.Errorf("an unrelated failure got %q", hint)
	}
	// The upload says it.
	ta.Workspace = &failingCopy{fakeCopy: ta.copy, uploadErr: full}
	wantErr(t, ta.Run(bg, RunOptions{Harness: "claude", Name: "fullbox"}), "upload the project copy: ", overlay)
	// On docker a full disk is named as before.
	ta = newTestApp(t, "")
	ta.daemon.status.Gateway.Driver = "docker"
	has(t, ta.sandboxDiskHint(bg, ta.API, full), "the disk holding")
}

// Cert opencode:OC-2: OpenCode quits on Ctrl-C, also in the middle of a
// turn, which ends the session; an interactive OpenCode session's banner
// names Esc as the key that interrupts a turn. A one-prompt run, a session
// without a terminal and another harness get no such line.
func TestBannerNamesOpenCodesInterruptKey(t *testing.T) {
	const keys = "Keys      Esc interrupts OpenCode's turn; Ctrl-C (with an empty prompt) quits OpenCode, which ends the session"
	for _, c := range []struct {
		name    string
		harness string
		tty     bool
		prompt  string
		want    bool
	}{
		{"interactive OpenCode", "opencode", true, "", true},
		{"one prompt", "opencode", true, "fix the tests", false},
		{"no terminal", "opencode", false, "", false},
		{"Claude Code", "claudecode", true, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = c.tty
			sb := sampleSandbox("box")
			sb.Harness = c.harness
			ta.banner(&sb, bannerInfo{o: RunOptions{Prompt: c.prompt}})
			if got := strings.Contains(ta.output(), keys); got != c.want {
				t.Fatalf("Keys line shown = %v, want %v:\n%s", got, c.want, ta.output())
			}
		})
	}
}

// Cert opencode:OC-10: the OpenCode launcher's refusal of a file in the
// sandbox names this CLI's own commands for removing it from the host.
func TestOpenCodeLauncherRefusalNamesTheSandboxCommands(t *testing.T) {
	script := string(harness.OpenCode.Launcher().Data)
	for _, verb := range []string{"start", "exec", "connect"} {
		if !strings.Contains(script, CommandName+" "+verb+" $dc_sandbox") {
			t.Errorf("the OpenCode launcher's refusal does not name `%s %s`", CommandName, verb)
		}
	}
}
