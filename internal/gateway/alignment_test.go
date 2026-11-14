// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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

func TestAlignmentSideEffectingUsesTheEffects(t *testing.T) {
	ctx := context.Background()
	cwd := "/home/bench/work"
	for _, tc := range []struct {
		tool, args string
		want       bool
	}{
		{"Bash", `{"command":"ls -la"}`, false},
		{"Bash", `{"command":"cat README.md"}`, false},
		{"Bash", `{"command":"echo hi > notes.txt"}`, false},
		{"Bash", `{"command":"echo hi > /etc/motd"}`, true},
		{"Bash", `{"command":"curl https://example.com/x"}`, true},
		{"Bash", `{"command":"go test ./..."}`, false},
		{"Bash", `{"command":"/usr/bin/make build"}`, false},
		{"Bash", `{"command":"echo hi > /tmp/notes.txt"}`, false},
		{"Bash", `{"command":"rm -rf /opt/other"}`, true},
		{"Read", `{"file_path":"/home/bench/work/main.go"}`, false},
		{"Write", `{"file_path":"/home/bench/work/main.go","content":"x"}`, false},
		{"Write", `{"file_path":"/opt/other/main.go","content":"x"}`, true},
		{"send_email", `{"to":"a@example.com"}`, true},
		{"get_unread_emails", `{}`, false},
		{"mcp__bench__GmailSendEmail", `{"to":"a@example.com"}`, true},
		{"mcp__bench__GitHubGetUserDetails", `{"username":"x"}`, false},
	} {
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
	api.observeAlignmentTurn(ctx, "claudecode", "pay the rent")
	v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
	if out := api.applyAlignmentLane(ctx, "claudecode", "PreToolUse", "send_money", "toolu_1", `{"amount":1}`, "/w", v); out != v {
		t.Fatal("the lane changed a verdict while off")
	}
	if len(api.alignment.sessions) != 0 {
		t.Fatalf("the lane kept %d sessions while off", len(api.alignment.sessions))
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
