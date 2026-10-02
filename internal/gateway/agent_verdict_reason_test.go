// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func useAgentVerdictProfile(t *testing.T, standalone, secureClient bool) {
	t.Helper()
	previousStandalone, previousManaged := standaloneEnterpriseActive.Load(), managedEnterpriseActive.Load()
	setStandaloneEnterpriseActive(standalone)
	SetManagedEnterpriseActive(secureClient)
	t.Cleanup(func() {
		setStandaloneEnterpriseActive(previousStandalone)
		SetManagedEnterpriseActive(previousManaged)
	})
}

// A rule-pack rule, whose title the agent surface redacts.
const markerRuleReason = "matched: TEST-MARKER-BLOCK:Test marker (block)"

// The organization's block sentence is pinned exactly; the other wordings
// are checked by the phrase that differs.
const (
	orgBlockWording     = "DefenseClaw blocked this action under your organization's policy (rule TEST-MARKER-BLOCK). Do not retry it in another form. Contact your administrator if you need it allowed."
	redactedTokenPrefix = "<redacted"
)

func TestAgentVerdictReasonNamesDefenseClawPolicyAndTheRule(t *testing.T) {
	display := agentDisplayReason(markerRuleReason, redaction.SinkPolicyDefault)
	if !strings.Contains(display, redactedTokenPrefix) {
		t.Fatalf("precondition: a rule-pack title is redacted on the agent surface, got %q", display)
	}
	for _, test := range []struct {
		name       string
		standalone bool
		action     string
		want       string
	}{
		{"standalone block", true, "block", orgBlockWording},
		{"standalone confirm", true, "confirm", "needs your confirmation for this action under your organization's policy (rule TEST-MARKER-BLOCK)."},
		{"per-user block", false, "block", "DefenseClaw policy blocked this action (rule TEST-MARKER-BLOCK)."},
		{"per-user confirm", false, "confirm", "DefenseClaw policy needs your confirmation for this action (rule TEST-MARKER-BLOCK)."},
	} {
		t.Run(test.name, func(t *testing.T) {
			useAgentVerdictProfile(t, test.standalone, false)
			if got := agentVerdictReason(test.action, markerRuleReason, display, redaction.SinkPolicyDefault); !strings.Contains(got, test.want) {
				t.Fatalf("got %q\nwant it to contain %q", got, test.want)
			}
		})
	}

	useAgentVerdictProfile(t, true, false)
	for _, action := range []string{"allow", "alert"} {
		if got := agentVerdictReason(action, markerRuleReason, display, redaction.SinkPolicyDefault); got != display {
			t.Fatalf("%s reason rewritten to %q", action, got)
		}
	}
	for _, reason := range []string{
		"enterprise_foreign_hook_blocked: your organization blocks copilot hooks it has not approved",
		"Blocked by the security team",
		"",
	} {
		if got := agentVerdictReason("block", reason, reason, redaction.SinkPolicyDefault); got != reason {
			t.Fatalf("non-rule reason %q rewritten to %q", reason, got)
		}
	}

	// A local rule merged with an AI Defense or judge verdict: the merged
	// reason names the other lane's reason too, so the rule-only wording
	// would drop the reason that decided (and could blame an alert-only
	// rule). Such a reason keeps its display text.
	for _, source := range []string{
		markerRuleReason + "; Cisco AI Defense: prompt injection detected",
		markerRuleReason + "; judge-injection: instruction override",
		"matched ordered safety rule: CHAIN-1; judge-exfil: upload of a credential",
	} {
		display := agentDisplayReason(source, redaction.SinkPolicyDefault)
		if got := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault); got != display {
			t.Fatalf("merged reason %q rewritten to %q", source, got)
		}
	}
	// The approval fallback's note is not another verdict: the rule decided.
	source := markerRuleReason + "; " + approvalUnsupportedNote
	if got := agentVerdictReason("block", source, agentDisplayReason(source, redaction.SinkPolicyDefault), redaction.SinkPolicyDefault); got != orgBlockWording {
		t.Fatalf("approval fallback reason = %q, want %q", got, orgBlockWording)
	}
}

// A rule from a loaded rule pack keeps its title: the pack author wrote it,
// unlike a scanner title that can carry matched text.
func TestAgentVerdictReasonNamesALoadedRulePackTitle(t *testing.T) {
	applyMarkerRulePack(t, "agent-verdict-title-pack")

	useAgentVerdictProfile(t, true, false)
	display := agentDisplayReason(markerRuleReason, redaction.SinkPolicyDefault)
	want := "DefenseClaw blocked this action under your organization's policy (rule TEST-MARKER-BLOCK: Test marker (block)). Do not retry it in another form. Contact your administrator if you need it allowed."
	if got := agentVerdictReason("block", markerRuleReason, display, redaction.SinkPolicyDefault); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// A title the pack does not have stays in the audit only.
	other := "matched: TEST-MARKER-BLOCK:secret value 1234"
	if got := agentVerdictReason("block", other, agentDisplayReason(other, redaction.SinkPolicyDefault), redaction.SinkPolicyDefault); strings.Contains(got, "secret value") {
		t.Fatalf("a title outside the loaded pack reached the agent: %q", got)
	}
}

// The observe-mode notice names the rule the way the action-mode block does,
// not as "matched: TEST-MARKER-BLOCK:<redacted len=N sha=...>" (GAP-1187).
func TestObserveNoticeNamesTheRuleLikeTheBlock(t *testing.T) {
	applyMarkerRulePack(t, "agent-observe-title-pack")
	useAgentVerdictProfile(t, false, false)
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"}
	resp := claudeCodeResponseFor(req, "allow", "block", "CRITICAL", markerRuleReason, nil, "observe", true)
	want := "DefenseClaw would block this in action mode: CRITICAL Claude Code hook finding: rule TEST-MARKER-BLOCK: Test marker (block)"
	if resp.AdditionalContext != want {
		t.Fatalf("observe notice = %q\nwant %q", resp.AdditionalContext, want)
	}
	generic := agentHookResponseForProfile(connector.HookProfile{Name: "hermes"}, agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call"},
		"allow", "block", "HIGH", markerRuleReason, nil, "observe", true, connector.HookCapability{})
	if !strings.HasSuffix(generic.AdditionalContext, ": rule TEST-MARKER-BLOCK: Test marker (block)") {
		t.Fatalf("generic observe notice = %q", generic.AdditionalContext)
	}
	// Secure Client keeps its pinned (redacted) wording.
	useAgentVerdictProfile(t, false, true)
	resp = claudeCodeResponseFor(req, "allow", "block", "CRITICAL", markerRuleReason, nil, "observe", true)
	if !strings.Contains(resp.AdditionalContext, redactedTokenPrefix) {
		t.Fatalf("managed observe notice = %q, want the redacted reason", resp.AdditionalContext)
	}
}

func applyMarkerRulePack(t *testing.T, connectorName string) {
	t.Helper()
	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "default"))
	added := false
	for index := range pack.RuleFiles {
		if pack.RuleFiles[index].Category != "command" {
			continue
		}
		pack.RuleFiles[index].Rules = append(pack.RuleFiles[index].Rules, guardrail.RuleDefYAML{
			ID:         "TEST-MARKER-BLOCK",
			Pattern:    `(?i)\btest-marker-block\b`,
			Title:      "Test marker (block)",
			Severity:   "HIGH",
			Confidence: 0.99,
		})
		added = true
		break
	}
	if !added {
		t.Fatal("the default pack has no command rule file")
	}
	if err := ApplyConnectorRulePackOverrides(connectorName, pack); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connectorName) })
}

func TestAgentVerdictReasonKeepsSecureClientWording(t *testing.T) {
	useAgentVerdictProfile(t, false, true)
	display := agentDisplayReason(markerRuleReason, redaction.SinkPolicyRedact)
	if got := agentVerdictReason("block", markerRuleReason, display, redaction.SinkPolicyRedact); got != display {
		t.Fatalf("Secure Client block reason changed to %q", got)
	}
	// An explicit managed directive or the raw carve-out also keep the text.
	SetManagedEnterpriseActive(false)
	if got := agentVerdictReason("block", markerRuleReason, display, redaction.SinkPolicyRedact); got != display {
		t.Fatalf("managed redaction directive reason changed to %q", got)
	}
	if got := agentVerdictReason("block", markerRuleReason, markerRuleReason, redaction.SinkPolicyDefault); got != markerRuleReason {
		t.Fatalf("carve-out raw reason changed to %q", got)
	}
}

func TestAgentMatchedRulesNamesRulesByID(t *testing.T) {
	var builtIn string
	var builtInID, builtInTitle string
	for _, category := range defaultRuleCategories {
		for _, rule := range category.Rules {
			if rule.ID != "" && rule.Title != "" && agentRuleIDPattern.MatchString(rule.ID) && !strings.Contains(rule.Title, ", ") {
				builtInID, builtInTitle = rule.ID, rule.Title
				builtIn = rule.ID + ":" + rule.Title
				break
			}
		}
		if builtIn != "" {
			break
		}
	}
	if builtIn == "" {
		t.Fatal("no compiled-in rule to test with")
	}
	for _, test := range []struct{ reason, want string }{
		{"matched: " + builtIn, "rule " + builtInID + ": " + builtInTitle},
		{"matched: A-1:first, second part, B.2:other, A-1:again", "rules A-1, B.2"},
		{"matched: A-1:x; matched ordered safety rule: CHAIN-1, CHAIN-2", "rules A-1, CHAIN-1, CHAIN-2"},
		{"matched: A-1:x; Cisco AI Defense: blocked", ""},
	} {
		if got := agentMatchedRules(test.reason); got != test.want {
			t.Fatalf("agentMatchedRules(%q) = %q, want %q", test.reason, got, test.want)
		}
	}
}

// TestHookResponsesCarryTheDefenseClawPolicyWording checks every agent
// surface: Claude Code, Codex, the generic connector hooks and the inspect
// API the plugin connectors use.
func TestHookResponsesCarryTheDefenseClawPolicyWording(t *testing.T) {
	useAgentVerdictProfile(t, true, false)
	assertWording := func(surface string, value any, want string) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, want) || strings.Contains(text, redactedTokenPrefix) {
			t.Fatalf("%s response %s\nwant %q and no redaction token", surface, text, want)
		}
	}

	claude := claudeCodeResponseFor(claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"block", "block", "CRITICAL", markerRuleReason, []string{"TEST-MARKER-BLOCK"}, "action", true)
	if claude.Reason != orgBlockWording {
		t.Fatalf("Claude Code reason = %q", claude.Reason)
	}
	assertWording("Claude Code", claude.ClaudeCodeOutput, orgBlockWording)
	ask := claudeCodeResponseFor(claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"confirm", "confirm", "HIGH", markerRuleReason, nil, "action", false)
	assertWording("Claude Code ask", ask.ClaudeCodeOutput, "needs your confirmation for this action under your organization's policy")

	codex := codexResponseFor("PreToolUse", "block", "block", "CRITICAL", markerRuleReason, nil, "action", true)
	if codex.Reason != orgBlockWording {
		t.Fatalf("Codex reason = %q", codex.Reason)
	}
	assertWording("Codex", codex.CodexOutput, orgBlockWording)

	copilot := agentHookResponseFor(agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", ToolName: "bash"},
		"block", "block", "CRITICAL", markerRuleReason, nil, "action", true, connector.HookCapability{})
	if copilot.Reason != orgBlockWording {
		t.Fatalf("generic hook reason = %q", copilot.Reason)
	}
	// OpenCode cannot ask: the confirmation runs as an alert, flagged for review.
	review := agentHookResponseFor(agentHookRequest{ConnectorName: "opencode", HookEventName: "tool.execute.before", ToolName: "bash"},
		"alert", "confirm", "HIGH", markerRuleReason, nil, "action", false, connector.HookCapability{})
	if !strings.Contains(review.Reason, "flagged this action for review under your organization's policy (rule TEST-MARKER-BLOCK).") {
		t.Fatalf("unaskable confirm reason = %q", review.Reason)
	}

	inspect := (&ToolInspectVerdict{Action: "block", Severity: "CRITICAL", Reason: markerRuleReason}).sanitizeForResponse(false)
	if inspect.Reason != orgBlockWording {
		t.Fatalf("inspect API reason = %q", inspect.Reason)
	}
	// The source reason stays intact for the audit record.
	if claude.SourceReason != markerRuleReason || codex.SourceReason != markerRuleReason {
		t.Fatalf("source reasons changed: %q %q", claude.SourceReason, codex.SourceReason)
	}
}

// On Hermes and OpenHands a confirmation became an alert and the tool call
// ran with nothing on screen, since neither hook can ask or show a notice.
// The standalone enterprise profile blocks it and says the rule wanted the
// user's confirmation; per-user installs keep the alert.
func TestStandaloneBlocksAConfirmationHermesAndOpenHandsCannotAsk(t *testing.T) {
	opts := connector.SetupOpts{APIAddr: "127.0.0.1:18970"}
	for _, c := range []struct {
		profile      connector.HookProfile
		event, agent string
	}{
		{connector.NewHermesConnector().HookProfile(opts), "pre_tool_call", "Hermes"},
		{connector.NewOpenHandsConnector().HookProfile(opts), "PreToolUse", "OpenHands"},
	} {
		useAgentVerdictProfile(t, false, false)
		if action, _ := mapHookActionForProfile("confirm", "action", c.event, c.profile.Capabilities, c.profile, nil); action != "alert" {
			t.Fatalf("%s per-user confirm = %q, want alert", c.agent, action)
		}
		useAgentVerdictProfile(t, true, false)
		action, _ := mapHookActionForProfile("confirm", "action", c.event, c.profile.Capabilities, c.profile, nil)
		if action != "block" {
			t.Fatalf("%s standalone confirm = %q, want block", c.agent, action)
		}
		req := agentHookRequest{ConnectorName: c.profile.Name, HookEventName: c.event, ToolName: "terminal"}
		resp := agentHookResponseForProfile(c.profile, req, action, "confirm", "HIGH", markerRuleReason, nil, "action", false, c.profile.Capabilities)
		data, err := json.Marshal(resp.HookOutput)
		if err != nil {
			t.Fatal(err)
		}
		if want := "needs your confirmation for it (rule TEST-MARKER-BLOCK), and " + c.agent + " cannot ask for it."; !strings.Contains(string(data), want) {
			t.Fatalf("%s hook output %s\nwant %q", c.agent, data, want)
		}
	}
}
