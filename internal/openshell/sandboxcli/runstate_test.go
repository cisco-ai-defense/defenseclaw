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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// The run's harness options are the ones a later session passes again: a
// prompt is not, nor anything after one, nor a one-prompt run's arguments.
func TestLaunchOptionsKeepOptionsNotPrompts(t *testing.T) {
	claude, _ := harness.Get("claudecode")
	codex, _ := harness.Get("codex")
	for _, c := range []struct {
		name string
		spec *harness.Spec
		args []string
		want []string
	}{
		{"codex overrides", codex, []string{"-c", "openai_base_url=http://host.openshell.internal:38221/v1", "-m", "mock-model"},
			[]string{"-c", "openai_base_url=http://host.openshell.internal:38221/v1", "-m", "mock-model"}},
		{"a trailing prompt", claude, []string{"--model", "sonnet", "fix the failing tests"}, []string{"--model", "sonnet"}},
		{"a prompt after a switch", claude, []string{"--verbose", "fix the failing tests"}, []string{"--verbose"}},
		{"an option with its value", claude, []string{"--model=sonnet", "--verbose"}, []string{"--model=sonnet", "--verbose"}},
		{"a prompt first", claude, []string{"fix it", "--model", "sonnet"}, nil},
		{"a subcommand", codex, []string{"resume", "--last"}, nil},
		{"print mode", claude, []string{"-p", "fix it", "--model", "sonnet"}, nil},
		{"after --", claude, []string{"--model", "sonnet", "--", "-x"}, []string{"--model", "sonnet"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := launchOptions(c.spec, c.args); !slices.Equal(got, c.want) {
				t.Fatalf("launchOptions(%q) = %q, want %q", c.args, got, c.want)
			}
		})
	}
}

// A later session passes the run's options first, then its own; the run's
// command typed again is not doubled.
func TestSessionArgsPutTheRunsOptionsFirst(t *testing.T) {
	stored := []string{"-m", "mock-model"}
	for _, c := range []struct{ given, want []string }{
		{nil, []string{"-m", "mock-model"}},
		{[]string{"resume", "01a0e644"}, []string{"-m", "mock-model", "resume", "01a0e644"}},
		{[]string{"-m", "mock-model", "resume", "01a0e644"}, []string{"-m", "mock-model", "resume", "01a0e644"}},
	} {
		if got := sessionArgs(stored, c.given); !slices.Equal(got, c.want) {
			t.Errorf("sessionArgs(%q) = %q, want %q", c.given, got, c.want)
		}
	}
	if got := sessionArgs(nil, []string{"--continue"}); !slices.Equal(got, []string{"--continue"}) {
		t.Errorf("sessionArgs without a record = %q", got)
	}
}

// Manual R2-21 and R2-7: `connect` after a run gives the harness the run's
// options again (a Codex endpoint override), before the ones given now,
// and its banner has the run's Model and Secret lines.
func TestConnectPassesTheRunsOptionsAndBanner(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["OPENAI_API_KEY"] = "sk-mock"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	run := RunOptions{Harness: "codex", Name: "r2b-y", LLM: "none", Credentials: []string{"OPENAI_API_KEY=host.openshell.internal:38221"},
		Args: []string{"-c", "openai_base_url=http://host.openshell.internal:38221/v1", "-m", "mock-model"}}
	if err := ta.Run(context.Background(), run); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	ta.out.Reset()
	ta.term.runs = nil
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "r2b-y", Args: []string{"resume", "01a0e644"}}); err != nil {
		t.Fatalf("Connect: %v\n%s", err, ta.output())
	}
	if len(ta.term.runs) != 1 {
		t.Fatalf("terminal runs = %q", ta.term.runs)
	}
	argv := strings.Join(ta.term.runs[0], " ")
	want := "-c openai_base_url=http://host.openshell.internal:38221/v1 -m mock-model resume 01a0e644"
	if !strings.Contains(argv, want) {
		t.Fatalf("connect argv = %s\nwant it to end with %s", argv, want)
	}
	out := ta.output()
	for _, line := range []string{"Model     mock-model", "OPENAI_API_KEY comes from --credential", "Secret    OPENAI_API_KEY → host.openshell.internal:38221 only"} {
		if !strings.Contains(out, line) {
			t.Errorf("connect banner lacks %q:\n%s", line, out)
		}
	}
}

// Manual R2-7: a Bedrock sandbox's connect banner names the variable its
// credential came from, not the provider profile's id, also for a sandbox
// the CLI remembers nothing of.
func TestConnectBannerNamesTheModelVariable(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("r2a-bed")
	sb.Launch.CredentialProfile, sb.Launch.BedrockRegion = profiles.ClaudeBedrockMantleID, "us-east-1"
	ta.daemon.add(sb)
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "r2a-bed"}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "Model     anthropic.claude-sonnet-5 (the default; -- --model MODEL picks another) · AWS_BEARER_TOKEN_BEDROCK → ") || strings.Contains(out, "claude-bedrock-mantle credential") {
		t.Fatalf("connect banner:\n%s", out)
	}
}

// Manual R2-110: the run's command typed again in the folder its kept
// sandbox holds is a resume with nothing ignored, so the default answer
// (Enter) resumes it.
func TestRunAgainResumesWithTheSameFlags(t *testing.T) {
	ta := newTestApp(t, "\n")
	ta.env["ANTHROPIC_API_KEY"] = "sk-mock"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	run := RunOptions{Harness: "claude", LLM: "none", Credentials: []string{"ANTHROPIC_API_KEY=host.openshell.internal:38121"},
		Env: []string{"ANTHROPIC_BASE_URL=http://host.openshell.internal:38121"}, Args: []string{"--model", "mock"}}
	if err := ta.Run(context.Background(), run); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	ta.out.Reset()
	if err := ta.Run(context.Background(), run); err != nil {
		t.Fatalf("second Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if !strings.Contains(out, "already holds this folder. Resume it? [Y/n]") || strings.Contains(out, "ignores") {
		t.Fatalf("the offer called the same flags ignored:\n%s", out)
	}
	if n := len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)); n != 1 {
		t.Fatalf("creates = %d, want the second run to resume", n)
	}
	if n := len(ta.daemon.callsTo("POST", sbPath+"/start")); n != 1 {
		t.Fatalf("starts = %d", n)
	}
	// Different values are still named.
	rec := ta.runLaunchOf(ta.mustGet(t, "dc-claude-proj-1a2b"))
	if rec == nil {
		t.Fatal("the run was not remembered")
	}
	other := run
	other.Env = []string{"ANTHROPIC_BASE_URL=http://elsewhere"}
	other.Credentials = []string{"ANTHROPIC_API_KEY=api.anthropic.com"}
	if got := resumeIgnores(other, ta.mustGet(t, "dc-claude-proj-1a2b"), rec); !slices.Equal(got, []string{"--credential", "--env"}) {
		t.Fatalf("resumeIgnores = %q", got)
	}
}

func (ta *testApp) mustGet(t *testing.T, name string) *sandboxapi.Sandbox {
	t.Helper()
	ta.daemon.mu.Lock()
	defer ta.daemon.mu.Unlock()
	sb, ok := ta.daemon.sandboxes[name]
	if !ok {
		t.Fatalf("no sandbox %s", name)
	}
	cp := *sb
	return &cp
}

// The record belongs to the sandbox that was created: a later sandbox of
// the same name does not inherit it, and it keeps no secret value.
func TestRunLaunchIsTiedToTheSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	claude, _ := harness.Get("claudecode")
	ta.saveRunLaunch(&sb, newRunLaunch(&sb, claude, RunOptions{Env: []string{"DB_URL=postgres://u:hunter2@db"}, Credentials: []string{"K=api.x.com"}},
		llmChoice{Note: "K comes from --credential"}))
	if got := ta.runLaunchOf(&sb); got == nil || !slices.Equal(got.EnvNames, []string{"DB_URL"}) || got.ModelNote != "K comes from --credential" {
		t.Fatalf("record = %+v", got)
	}
	dir, _ := ta.cliStateDir("box")
	data, err := os.ReadFile(filepath.Join(dir, runLaunchFile))
	if err != nil || strings.Contains(string(data), "hunter2") {
		t.Fatalf("record on disk = %s, %v", data, err)
	}
	other := sb
	other.ID = "sb-another"
	if ta.runLaunchOf(&other) != nil {
		t.Fatal("a later sandbox of the name inherited the record")
	}
}

// Manual R2-43: a copy-mode session that found nothing to bring back lets
// `delete` of the stopped sandbox go without the "may hold work" warning,
// until the sandbox runs again.
func TestDeleteKnowsTheSessionChangedNothing(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.env["ANTHROPIC_API_KEY"] = "sk-mock"
	ta.copy.pull = &workspace.PullResult{Name: "copybox"}
	ta.copy.pendingStopped = map[string]workspace.CopyWork{"copybox": workspace.CopyWorkUnknown}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if !strings.Contains(ta.output(), "the sandbox changed nothing") {
		t.Fatalf("output:\n%s", ta.output())
	}
	ta.out.Reset()
	if err := ta.Delete(context.Background(), DeleteOptions{Names: []string{"copybox"}}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); strings.Contains(out, "may hold work") || !strings.Contains(out, "Delete sandbox copybox (its providers, credentials and, unless --keep-snapshot, its undo point)?") {
		t.Fatalf("delete:\n%s", out)
	}

	// Once it ran again, it is not known to be clean.
	ta = newTestApp(t, "n\n")
	sb := copySandbox("copybox")
	ta.daemon.add(sb)
	ta.copy.pendingStopped = map[string]workspace.CopyWork{"copybox": workspace.CopyWorkUnknown}
	ta.markCleanCopy(&sb)
	sb.StartedAt = ta.Now().Add(time.Minute)
	ta.daemon.add(sb)
	if err := ta.Delete(context.Background(), DeleteOptions{Names: []string{"copybox"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "may hold work that was never pulled back") {
		t.Fatalf("delete after a later start:\n%s", ta.output())
	}
}
