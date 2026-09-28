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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// --name is checked before anything else happens: OpenShell 0.1.1 creates
// names of at most 19 characters (manual test H3).
func TestRunRefusesNamesOpenShellDoesNotCreate(t *testing.T) {
	for name, want := range map[string]string{
		"dc-claude-m1-calc-7500": `--name "dc-claude-m1-calc-7500" is 22 characters; OpenShell takes at most 19`,
		"Bad_Name":               "use at most 19 lowercase letters, digits and '-'",
		"trailing-":              "starting and ending with a letter or digit",
		"git":                    `--name "git" is reserved`,
	} {
		t.Run(name, func(t *testing.T) {
			ta := newTestApp(t, "")
			err := ta.Run(context.Background(), RunOptions{Harness: "claude", Name: name, Copy: true})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Run = %v, want %q", err, want)
			}
			if paths := ta.daemon.paths(); len(paths) != 0 {
				t.Fatalf("a refused name reached the daemon: %v", paths)
			}
			if len(ta.copy.steps) != 0 {
				t.Fatalf("a refused name was staged: %v", ta.copy.steps)
			}
		})
	}
	ta := newTestApp(t, "")
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Name: strings.Repeat("a", 19)}); err != nil {
		t.Fatalf("a 19-character name: %v", err)
	}
}

// `run --copy --name <existing>` staged the new copy over the existing
// sandbox's copy record before the daemon refused the name, so that
// sandbox's work could no longer be pulled (manual test H6). The name is
// now refused first, with the ways on (M6).
func TestRunRefusesAnExistingNameBeforeStaging(t *testing.T) {
	for _, c := range []struct {
		name string
		opts RunOptions
		tty  bool
		want string
	}{
		{"copy, headless", RunOptions{Harness: "codex", Copy: true, Name: "m2-a", Detach: true, Prompt: "x"}, false,
			"resume it with `defenseclaw sandbox connect m2-a --prompt TEXT`"},
		{"mount, terminal", RunOptions{Harness: "claude", Name: "m2-a"}, true, "resume it with `defenseclaw sandbox connect m2-a`"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = c.tty
			sb := sampleSandbox("m2-a")
			sb.WorkdirMode, sb.Phase = "copy", "stopped"
			ta.daemon.add(sb)
			err := ta.Run(context.Background(), c.opts)
			if err == nil || !strings.Contains(err.Error(), "a sandbox named m2-a already exists") || !strings.Contains(err.Error(), c.want) ||
				!strings.Contains(err.Error(), "delete it with `defenseclaw sandbox delete m2-a`") {
				t.Fatalf("Run = %v", err)
			}
			if len(ta.copy.steps) != 0 {
				t.Fatalf("the existing sandbox's copy was touched: %v", ta.copy.steps)
			}
			if n := len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)); n != 0 {
				t.Fatalf("create calls = %d", n)
			}
		})
	}
}

// A copy-mode stage is this run's own when the daemon refuses the create
// for anything but the name: it is removed. When the daemon refuses the
// name (another run took it meanwhile), the stage is left alone.
func TestRunCopyCleansItsStageWhenTheCreateFails(t *testing.T) {
	for _, c := range []struct {
		name  string
		err   *sandboxapi.Error
		steps []string
		want  string
	}{
		{"refused by policy", &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: "the harness image could not be built"},
			[]string{"stage copybox", "discard copybox"}, "could not be built"},
		{"name taken meanwhile", &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: "a sandbox named copybox already exists"},
			[]string{"stage copybox"}, "resume it with `defenseclaw sandbox connect copybox`"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = c.err
			err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox"})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run = %v, want %q", err, c.want)
			}
			if !slices.Equal(ta.copy.steps, c.steps) {
				t.Fatalf("copy steps = %v, want %v", ta.copy.steps, c.steps)
			}
		})
	}
}

// An --host-port DefenseClaw never opens fails before the banner, like the
// same port in a --credential, instead of the banner calling it reachable
// (manual test M15).
func TestRunRefusesHostPortsBeforeTheBanner(t *testing.T) {
	ta := newTestApp(t, "")
	ingress := ta.Cfg.OpenShellIngressPort()
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", HostPorts: []int{3000, ingress}})
	want := fmt.Sprintf("--host-port %d: DefenseClaw never opens DefenseClaw's sandbox hook ingress (port %d) to a sandbox — choose another port", ingress, ingress)
	if err == nil || err.Error() != want {
		t.Fatalf("Run = %v\nwant %s", err, want)
	}
	if n := len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)); n != 0 || strings.Contains(ta.output(), "reachable") {
		t.Fatalf("create calls = %d, output:\n%s", n, ta.output())
	}
	off := false
	ta = newTestApp(t, "")
	ta.Cfg.OpenShell.Admin.AllowHostPorts = &off
	err = ta.Run(context.Background(), RunOptions{Harness: "claude", HostPorts: []int{3000}})
	if err == nil || !strings.Contains(err.Error(), "--host-port 3000: blocked by your organization's DefenseClaw policy: mcp.host_ports — host ports cannot be opened to sandboxes (openshell.admin.allow_host_ports); run it without --host-port") {
		t.Fatalf("Run = %v", err)
	}
}

// Whatever the daemon refused is not in the banner's Host line.
func TestBannerDropsRefusedHostPorts(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	sb.Violations = []sandboxapi.Violation{{Key: "mcp.host_ports", Attempted: "3000", Constraint: "pack strict", Message: "not allowed by the strict sandbox pack: mcp.host_ports",
		Detail: "the pack does not open host ports"}}
	ta.banner(&sb, bannerInfo{o: RunOptions{HostPorts: []int{3000, 4000}}})
	out := ta.output()
	if !strings.Contains(out, "Host      localhost:4000 (opens when you approve") || strings.Contains(out, "localhost:3000") ||
		!strings.Contains(out, "not allowed by the strict sandbox pack: mcp.host_ports — the pack does not open host ports") {
		t.Fatalf("banner:\n%s", out)
	}
}

// What the organization changed about a run is said before anything is
// copied or created, once; a flag it overrode is confirmed on a terminal
// (manual test M10: `--profile open` under a required strict pack went
// straight to copying).
func TestRunSaysWhatThePolicyOverrodeFirst(t *testing.T) {
	overridden := sandboxapi.Violation{Key: "profile", Source: "flag", Attempted: "open", Enforced: "strict", Admin: true,
		Constraint: "openshell.admin.required_pack", Detail: "your organization requires the strict sandbox pack, whose profile is strict"}
	want := "limited by your organization's DefenseClaw policy: profile — your organization requires the strict sandbox pack, whose profile is strict " +
		"(openshell.admin.required_pack); running with profile strict instead of open"
	t.Run("declined", func(t *testing.T) {
		ta := newTestApp(t, "n\n")
		ta.daemon.explain.Violations = []sandboxapi.Violation{overridden}
		err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox", Profile: "open"})
		var silent *Silent
		if !errors.As(err, &silent) {
			t.Fatalf("Run = %v", err)
		}
		if len(ta.copy.steps) != 0 || len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)) != 0 {
			t.Fatalf("a declined run copied or created: %v", ta.copy.steps)
		}
		if out := ta.output(); !strings.Contains(out, want) || !strings.Contains(out, "overrides a flag you passed. Run with its setting? [Y/n]") {
			t.Fatalf("output:\n%s", out)
		}
	})
	t.Run("no terminal", func(t *testing.T) {
		ta := newTestApp(t, "")
		ta.IO.TTY = false
		ta.daemon.explain.Violations = []sandboxapi.Violation{overridden}
		ta.daemon.createViolations = []sandboxapi.Violation{overridden}
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox", Profile: "open", Detach: true, Prompt: "x"}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := ta.output()
		if strings.Count(out, want) != 1 || strings.Index(out, want) > strings.Index(out, "Copying") {
			t.Fatalf("the override is not said once, before the copy:\n%s", out)
		}
	})
}

// The organization's refusal comes before what the terminal lacks, and
// the image note only when the image is missing (manual test L9).
func TestRunMessagesInOrder(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "harness", Fatal: true, Admin: true, Constraint: "openshell.admin.allowed_harnesses",
		Message: "blocked by your organization's DefenseClaw policy: harness", Detail: "your organization allows only claudecode"}}
	err := ta.Run(context.Background(), RunOptions{Harness: "codex"})
	if err == nil || err.Error() != "blocked by your organization's DefenseClaw policy: harness — your organization allows only claude "+
		"(openshell.admin.allowed_harnesses); ask your administrator if you need it" {
		t.Fatalf("Run = %v", err)
	}
	for _, c := range []struct {
		name    string
		missing bool
		noBuild bool
		note    bool
	}{{"built", false, false, false}, {"missing", true, false, true}, {"missing, --no-build", true, true, false}} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
			if c.missing {
				ta.images.missing = map[string]bool{"claudecode": true}
			}
			if err := ta.Run(context.Background(), RunOptions{Harness: "claude", NoBuild: c.noBuild}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(ta.output(), "building its image first"); got != c.note {
				t.Fatalf("image note = %t, want %t:\n%s", got, c.note, ta.output())
			}
		})
	}
}

func TestBannerSaysTheOrganizationKeepsThePrompts(t *testing.T) {
	ta := newTestApp(t, "")
	off := false
	ta.Cfg.OpenShell.Admin.AllowYolo = &off
	sb := sampleSandbox("box")
	sb.Launch.Yolo = false
	ta.banner(&sb, bannerInfo{})
	if out := ta.output(); !strings.Contains(out, "skip-permissions OFF (your organization disables skip-permissions)") {
		t.Fatalf("banner:\n%s", out)
	}
	ta = newTestApp(t, "")
	ta.banner(&sb, bannerInfo{})
	if out := ta.output(); !strings.Contains(out, "skip-permissions OFF (harness prompts kept)") {
		t.Fatalf("banner:\n%s", out)
	}
}

// `claude --version` through the shell wrapper runs no session: the
// installed harness answers, or the sandbox image's version does (manual
// test L5: it resumed a sandbox for 20 s and then stopped it).
func TestRunAnswersVersionAndHelpWithoutASandbox(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.Environ = func() []string { return []string{"PATH=/usr/bin"} }
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"--version"}}); err != nil {
		t.Fatal(err)
	}
	if len(ta.execs) != 1 || !slices.Equal(ta.execs[0], []string{"/usr/bin/claude", "claude", "--version"}) {
		t.Fatalf("execs = %q", ta.execs)
	}
	if paths := ta.daemon.paths(); len(paths) != 0 {
		t.Fatalf("a version query reached the daemon: %v", paths)
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
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"-v"}}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); strings.TrimSpace(out) != "2.1.4 (Claude Code, in the DefenseClaw sandbox image)" {
		t.Fatalf("output: %q", out)
	}
	ta.out.Reset()
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"--help"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "defenseclaw sandbox run claude [-- Claude Code arguments]") {
		t.Fatalf("output:\n%s", ta.output())
	}
	ta.images.recs = nil
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"--version"}})
	if err == nil || !strings.Contains(err.Error(), "`defenseclaw sandbox image build claude`") {
		t.Fatalf("Run = %v", err)
	}
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
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"--version"}}); err != nil || len(ta.execs) != 0 {
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
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: args}); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		want := append([]string{"/usr/bin/claude", "claude"}, args...)
		if len(ta.execs) != 1 || !slices.Equal(ta.execs[0], want) {
			t.Fatalf("%q: execs = %q", args, ta.execs)
		}
		if paths := ta.daemon.paths(); len(paths) != 0 {
			t.Fatalf("%q reached the daemon: %v", args, paths)
		}
		if !strings.Contains(ta.err.String(), "manages Claude Code on this machine, so it runs outside the sandbox") {
			t.Fatalf("%q: stderr = %q", args, ta.err.String())
		}
	}
	if !hostArgs(harnessSpec(t, "codex"), RunOptions{Args: []string{"login", "--with-api-key"}}) {
		t.Fatal("codex login is not a host command")
	}
	for _, o := range []RunOptions{
		{Args: []string{"mcp", "serve"}}, {Args: []string{"-p", "mcp list"}}, {Args: []string{"mcp", "list"}, Prompt: "x"},
		{Args: []string{"fix", "the", "tests"}},
	} {
		if hostArgs(harnessSpec(t, "claudecode"), o) {
			t.Errorf("hostArgs(%+v) = true; it must run in the sandbox", o)
		}
	}

	// Not installed here: say where the harness is.
	ta := newTestApp(t, "")
	ta.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", Args: []string{"mcp", "list"}})
	if err == nil || !strings.Contains(err.Error(), "manages Claude Code on this machine, where it is not installed") || len(ta.daemon.paths()) != 0 {
		t.Fatalf("Run = %v", err)
	}
}

func harnessSpec(t *testing.T, name string) *harness.Spec {
	t.Helper()
	spec, ok := harness.Get(name)
	if !ok {
		t.Fatalf("no harness %s", name)
	}
	return spec
}

// Detached runs of other harnesses keep their own output (no stream-json).
func TestDetachedCodexKeepsItsArguments(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	if err := ta.Run(context.Background(), RunOptions{Harness: "codex", Detach: true, Prompt: "x"}); err != nil {
		t.Fatal(err)
	}
	last := sandboxCommand(ta.stream.runs[len(ta.stream.runs)-1])
	if slices.Contains(last, "stream-json") || last[4] != harness.CodexLauncherPath {
		t.Fatalf("detached codex argv = %q", last)
	}
}
