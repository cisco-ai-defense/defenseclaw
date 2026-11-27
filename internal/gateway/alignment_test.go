// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAlignmentActionVerbReadsToolNameWords(t *testing.T) {
	for name, want := range map[string]bool{
		"send_money":                     true,
		"update_password":                true,
		"mcp__bank__scheduleTransaction": true,
		"post_webpage":                   true,
		"get_balance":                    false,
		"list_files":                     false,
		"search_emails":                  false,
		"read_channel_messages":          false, // the plural is not the verb
		"read_file":                      false,
		"":                               false,
	} {
		if got := alignmentActionVerb(name); got != want {
			t.Errorf("alignmentActionVerb(%q) = %v, want %v", name, got, want)
		}
	}
}

type alignmentCase struct {
	tool, args string
	want       bool
}

// alignmentPathCases are the cases that name an absolute path, in the shape
// the host gives them: a POSIX tool call on a POSIX host, a Windows tool call
// (drive paths, a drive working folder) on Windows. alignmentUnder compares
// with the host filepath, and a Windows host never sees a POSIX working
// folder, so POSIX absolute paths are not asserted as such on Windows.
func alignmentPathCases(t *testing.T) (cwd string, cases []alignmentCase) {
	t.Helper()
	call := func(tool string, args map[string]string, want bool) alignmentCase {
		b, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		return alignmentCase{tool, string(b), want}
	}
	if runtime.GOOS == "windows" {
		return `C:\Users\bench\work`, []alignmentCase{
			// Claude Code's Bash is Git Bash on Windows and is read as POSIX
			// (GAP-0940): quoted or forward-slash drive paths keep their
			// folder, while an unquoted backslash path loses its backslashes
			// (C:Usersbench...): a drive-relative name, which Windows places
			// in the current folder of drive C, the working folder (DET111
			// T23E6, effects placement of C:foo).
			call("Bash", map[string]string{"command": `echo hi > 'C:\Users\bench\work\notes.txt'`}, false),
			call("Bash", map[string]string{"command": `echo hi > C:/Users/bench/work/notes.txt`}, false),
			call("Bash", map[string]string{"command": `echo hi > C:\Users\bench\work\notes.txt`}, false),
			call("Bash", map[string]string{"command": `echo hi > C:\ProgramData\other\motd`}, false),
			// A leading-slash path is drive-relative on Windows: it cannot be
			// placed under the working folder, so a write to it counts.
			call("Bash", map[string]string{"command": "echo hi > /etc/motd"}, true),
			call("Read", map[string]string{"file_path": `C:\Users\bench\work\main.go`}, false),
			call("Write", map[string]string{"file_path": `C:\Users\bench\work\main.go`, "content": "x"}, false),
			call("Write", map[string]string{"file_path": `C:\ProgramData\other\main.go`, "content": "x"}, true),
			call("Write", map[string]string{"file_path": `C:\Windows\System32\drivers\etc\hosts`, "content": "x"}, true),
			call("Write", map[string]string{"file_path": "/opt/other/main.go", "content": "x"}, true),
		}
	}
	return "/home/bench/work", []alignmentCase{
		call("Bash", map[string]string{"command": "echo hi > /etc/motd"}, true),
		call("Bash", map[string]string{"command": "/usr/bin/make build"}, false),
		call("Bash", map[string]string{"command": "echo hi > /tmp/notes.txt"}, false),
		call("Bash", map[string]string{"command": "rm -rf /opt/other"}, true),
		call("Read", map[string]string{"file_path": "/home/bench/work/main.go"}, false),
		call("Write", map[string]string{"file_path": "/home/bench/work/main.go", "content": "x"}, false),
		call("Write", map[string]string{"file_path": "/opt/other/main.go", "content": "x"}, true),
	}
}

func TestAlignmentSideEffectingUsesTheEffects(t *testing.T) {
	ctx := context.Background()
	cwd, cases := alignmentPathCases(t)
	cases = append(cases, []alignmentCase{
		{"Bash", `{"command":"ls -la"}`, false},
		{"Bash", `{"command":"cat README.md"}`, false},
		{"Bash", `{"command":"echo hi > notes.txt"}`, false},
		{"Bash", `{"command":"curl https://example.com/x"}`, true},
		{"Bash", `{"command":"go test ./..."}`, false},
		{"send_email", `{"to":"a@example.com"}`, true},
		{"get_unread_emails", `{}`, false},
		{"mcp__bench__GmailSendEmail", `{"to":"a@example.com"}`, true},
		{"mcp__bench__GitHubGetUserDetails", `{"username":"x"}`, false},
	}...)
	for _, tc := range cases {
		if got, _ := alignmentSideEffecting(ctx, "claudecode", tc.tool, tc.args, cwd); got != tc.want {
			t.Errorf("alignmentSideEffecting(%s %s) = %v, want %v", tc.tool, tc.args, got, tc.want)
		}
	}
}

// The lane adds its finding and raises the action to its own; it never
// lowers the action or removes a finding of the pipeline.
func TestAlignmentFindingNeverLowersOrRemoves(t *testing.T) {
	base := &ToolInspectVerdict{Action: "block", Severity: "CRITICAL", Reason: "matched: R1:x",
		Findings: []string{"R1:x"}, DetailedFindings: []RuleFinding{{RuleID: "R1", Severity: "CRITICAL"}}}
	for _, mode := range []string{config.CascadeLaneShadow, config.CascadeLaneAlert, config.CascadeLaneBlock} {
		out := base.withAlignmentFinding(mode, "sends money to an account the user did not name")
		if out.Action != "block" || out.Severity != "CRITICAL" {
			t.Fatalf("%s: lowered the pipeline verdict: %s %s", mode, out.Action, out.Severity)
		}
		if len(out.DetailedFindings) != 2 || out.DetailedFindings[0].RuleID != "R1" || out.DetailedFindings[1].RuleID != alignmentFindingID {
			t.Fatalf("%s: findings = %+v", mode, out.DetailedFindings)
		}
		if len(base.DetailedFindings) != 1 || len(base.Findings) != 1 {
			t.Fatalf("%s: changed the input verdict", mode)
		}
	}
	allow := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
	if out := allow.withAlignmentFinding(config.CascadeLaneShadow, "r"); out.Action != "allow" || out.Severity != "NONE" {
		t.Fatalf("shadow acted: %s %s", out.Action, out.Severity)
	}
	if out := allow.withAlignmentFinding(config.CascadeLaneAlert, "r"); out.Action != "alert" || out.Severity != "MEDIUM" {
		t.Fatalf("alert: %s %s", out.Action, out.Severity)
	}
	if out := allow.withAlignmentFinding(config.CascadeLaneBlock, "r"); out.Action != "block" || out.Severity != "HIGH" {
		t.Fatalf("block: %s %s", out.Action, out.Severity)
	}
}

// Off (the default) the lane keeps no state and returns the verdict it was
// given, the same pointer.
func TestAlignmentLaneOffDoesNoWork(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{}}
	ctx := ContextWithSessionID(context.Background(), "s-align-off")
	api.observeAlignmentTurn(ctx, "claudecode", "pay the rent", nil)
	v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
	if out := api.applyAlignmentLane(ctx, "claudecode", "PreToolUse", "send_money", "toolu_1", `{"amount":1}`, "/w", v); out != v {
		t.Fatal("the lane changed a verdict while off")
	}
	if len(api.alignment.sessions) != 0 {
		t.Fatalf("the lane kept %d sessions while off", len(api.alignment.sessions))
	}
}

// A prompt the guardrail blocked is no task (GAP-0823, as observeUserTurn):
// the lane keeps the turns before it, and the next allowed prompt is the
// latest turn again.
func TestAlignmentBlockedPromptIsNoTurn(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Cascade.Lanes = map[string]string{config.CascadeLaneAlignment: config.CascadeLaneAlert}
	api := &APIServer{scannerCfg: cfg}
	ctx := ContextWithSessionID(context.Background(), "s-align-blocked")
	turns := func() (string, string) {
		api.alignment.mu.Lock()
		defer api.alignment.mu.Unlock()
		sess := api.alignment.sessions[judgeSessionKey(ctx)]
		if sess == nil {
			return "", ""
		}
		return sess.firstTurn, sess.latestTurn
	}
	api.observeAlignmentTurn(ctx, "claudecode", "pay the rent", &ToolInspectVerdict{Action: "block", Severity: "HIGH"})
	if first, latest := turns(); first != "" || latest != "" {
		t.Fatalf("a blocked first prompt became the task: %q / %q", first, latest)
	}
	api.observeAlignmentTurn(ctx, "claudecode", "pay the rent", &ToolInspectVerdict{Action: "allow", Severity: "NONE"})
	api.observeAlignmentTurn(ctx, "claudecode", "now the water bill", &ToolInspectVerdict{Action: "block", Severity: "HIGH"})
	first, latest := turns()
	if first == "" || first != latest || !strings.Contains(latest, "rent") {
		t.Fatalf("a blocked prompt replaced the turn: first %q latest %q", first, latest)
	}
	api.observeAlignmentTurn(ctx, "claudecode", "now the water bill", &ToolInspectVerdict{Action: "alert", Severity: "MEDIUM"})
	if _, latest := turns(); !strings.Contains(latest, "water") {
		t.Fatalf("an alerted prompt is still the user's task: latest %q", latest)
	}
}

func TestAlignmentCutMarksTruncation(t *testing.T) {
	if got := alignmentCut("short", 10); got != "short" {
		t.Fatal(got)
	}
	got := alignmentCut(strings.Repeat("a", 50), 10)
	if !strings.HasSuffix(got, " [truncated]") || len(got) > 10+len(" [truncated]") {
		t.Fatal(got)
	}
}

func TestAlignmentLaneRegistryValues(t *testing.T) {
	for _, v := range []string{"off", "shadow", "alert", "block"} {
		cfg := &config.Config{}
		cfg.Guardrail.Cascade.Lanes = map[string]string{config.CascadeLaneAlignment: v}
		if err := cfg.ValidateCascade(false); err != nil {
			t.Fatalf("lanes.alignment %s refused: %v", v, err)
		}
		if got := cfg.ResolveCascade("").LaneMode(config.CascadeLaneAlignment); got != v {
			t.Fatalf("LaneMode = %q, want %q", got, v)
		}
	}
	cfg := &config.Config{}
	cfg.Guardrail.Cascade.Lanes = map[string]string{config.CascadeLaneAlignment: "on"}
	if err := cfg.ValidateCascade(false); err == nil || !strings.Contains(err.Error(), "off, shadow, alert, block") {
		t.Fatalf("lanes.alignment on accepted or unclear: %v", err)
	}
	if got := (&config.Config{}).ResolveCascade("").LaneMode(config.CascadeLaneAlignment); got != config.CascadeLaneOff {
		t.Fatalf("default = %q, want off", got)
	}
}

// The alignment question has its own response schema: the default (the
// injection categories) made the model answer the wrong question.
func TestAlignmentResponseFormatIsItsOwn(t *testing.T) {
	got := string(judgeResponseFormatFor("alignment", false))
	if !strings.Contains(got, "defenseclaw_judge_alignment") || !strings.Contains(got, `"aligned"`) || strings.Contains(got, "Instruction Manipulation") {
		t.Fatalf("alignment response format = %s", got)
	}
}
