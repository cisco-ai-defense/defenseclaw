// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func enableSkillRuntimeDetection(cfg *config.Config) {
	cfg.AssetPolicy.Skill.RuntimeDetection.Enabled = true
}

func enablePluginRuntimeDetection(cfg *config.Config) {
	cfg.AssetPolicy.Plugin.RuntimeDetection.Enabled = true
}

func TestEvaluateRuntimeSkillAssetPolicyRespectsRuntimeDetectionDisabled(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.Default = "deny"
	api := &APIServer{scannerCfg: cfg}

	decision, matched := api.evaluateRuntimeSkillAssetPolicy(context.Background(), "codex", "PermissionRequest", skillRuntimeProbe{
		SkillName: "rogue-skill",
		ToolName:  "Skill",
		Surface:   "hook",
		Matched:   true,
	})

	if matched {
		t.Fatalf("matched=%v decision=%+v, want runtime detection disabled to skip skill policy", matched, decision)
	}
}

func TestEvaluateRuntimeSkillAssetPolicyRuntimeDisableWinsOverAllow(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "disabled-skill"}}
	store, _ := testStoreAndLogger(t)
	if err := store.SetActionFieldForConnector("skill", "disabled-skill", "codex", "runtime", "disable", "manual"); err != nil {
		t.Fatalf("seed disable: %v", err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}

	decision, matched := api.evaluateRuntimeSkillAssetPolicy(context.Background(), "codex", "PermissionRequest", skillRuntimeProbe{
		SkillName: "disabled-skill",
		ToolName:  "Skill",
		Surface:   "hook",
		Matched:   true,
	})

	if !matched {
		t.Fatalf("matched=false decision=%+v, want runtime-disable block", decision)
	}
	if decision.Action != "block" || decision.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", decision.Action, decision.RawAction)
	}
	if !decision.WouldBlock {
		t.Fatal("runtime-disable decision should carry WouldBlock=true for telemetry")
	}
	if decision.Source != "runtime-disable" {
		t.Fatalf("source=%q, want runtime-disable", decision.Source)
	}
}

func TestEvaluateRuntimeSkillAssetPolicyRuntimeDisableScope(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	store, _ := testStoreAndLogger(t)
	if err := store.SetActionFieldForConnector("skill", "scoped-skill", "codex", "runtime", "disable", "manual"); err != nil {
		t.Fatalf("seed scoped disable: %v", err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}

	decision, matched := api.evaluateRuntimeSkillAssetPolicy(context.Background(), "claudecode", "PermissionRequest", skillRuntimeProbe{
		SkillName: "scoped-skill",
		ToolName:  "Skill",
		Surface:   "hook",
		Matched:   true,
	})
	if matched {
		t.Fatalf("matched=%v decision=%+v, connector-scoped disable leaked to another connector", matched, decision)
	}

	if err := store.SetActionField("skill", "global-skill", "runtime", "disable", "manual"); err != nil {
		t.Fatalf("seed global disable: %v", err)
	}
	decision, matched = api.evaluateRuntimeSkillAssetPolicy(context.Background(), "claudecode", "PermissionRequest", skillRuntimeProbe{
		SkillName: "global-skill",
		ToolName:  "Skill",
		Surface:   "hook",
		Matched:   true,
	})
	if !matched || decision.Action != "block" {
		t.Fatalf("global disable decision=%+v matched=%v, want block", decision, matched)
	}
}

func TestEvaluateRuntimeSkillAssetPolicyDisableLookupErrorFailsClosed(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	store, _ := testStoreAndLogger(t)
	store.Close()
	api := &APIServer{scannerCfg: cfg, store: store}

	decision, matched := api.evaluateRuntimeSkillAssetPolicy(context.Background(), "codex", "PermissionRequest", skillRuntimeProbe{
		SkillName: "maybe-disabled",
		ToolName:  "Skill",
		Surface:   "hook",
		Matched:   true,
	})

	if !matched {
		t.Fatal("lookup error should fail closed with a matched block decision")
	}
	if decision.Action != "block" || decision.Source != "runtime-disable-error" {
		t.Fatalf("decision=%+v, want runtime-disable-error block", decision)
	}
}

func TestClaudeCodeSlashCommandPluginRuntimeDisableUsesCanonicalIDAndPreservesAuditDetails(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	enablePluginRuntimeDetection(cfg)
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatalf("open in-memory audit store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("initialize in-memory audit store: %v", err)
	}
	if err := store.SetActionFieldForConnector("plugin", "disabled-plugin", "claudecode", "runtime", "disable", "manual"); err != nil {
		t.Fatalf("seed plugin disable: %v", err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}
	const namespacedCommand = "disabled-plugin:run-diagnostics"

	decisions := api.claudeCodeSlashCommandAssetDecisions(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "slash_command",
		CommandName:   namespacedCommand,
		CommandSource: "plugin",
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions=%v, want one plugin runtime-disable decision", decisions)
	}
	got := decisions[0]
	if got.targetType != "plugin" {
		t.Fatalf("targetType=%q, want plugin", got.targetType)
	}
	if got.decision.TargetType != "plugin" || got.decision.TargetName != "disabled-plugin" || got.decision.Action != "block" || got.decision.Source != "runtime-disable" {
		t.Fatalf("decision=%+v, want plugin runtime-disable block", got.decision)
	}

	canonicalName, rawName := claudeCodeSlashCommandAssetName("plugin", namespacedCommand)
	if canonicalName != "disabled-plugin" || rawName != namespacedCommand {
		t.Fatalf("canonical name=%q raw=%q, want disabled-plugin and full command", canonicalName, rawName)
	}
	details := runtimeSkillAssetPolicyAuditDetails(got.decision, "claudecode", "UserPromptExpansion", skillRuntimeProbe{
		TargetType: "plugin",
		SkillName:  canonicalName,
		ToolName:   namespacedCommand,
		RawName:    rawName,
		SourcePath: "plugin",
		Surface:    "prompt_expansion",
		Matched:    true,
	})
	if !strings.Contains(details, "tool="+namespacedCommand) {
		t.Fatalf("asset-policy details %q missing full namespaced tool", details)
	}
	if !strings.Contains(details, `name_raw="`+namespacedCommand+`"`) {
		t.Fatalf("asset-policy details %q missing full raw command", details)
	}
}

func TestClaudeCodeNamespacedPluginCommandAssetPolicyLookup(t *testing.T) {
	tests := []struct {
		name        string
		commandName string
		configure   func(*config.Config)
		wantMatched bool
		wantSource  string
		wantTarget  string
	}{
		{
			name:        "admin allow matches bare plugin id",
			commandName: "release-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.Default = "deny"
				cfg.AssetPolicy.Plugin.Allowed = []config.AssetPolicyRule{{Name: "release-tools"}}
			},
		},
		{
			name:        "admin deny matches bare plugin id",
			commandName: "release-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.Denied = []config.AssetPolicyRule{{Name: "release-tools"}}
			},
			wantMatched: true,
			wantSource:  "admin-deny",
			wantTarget:  "release-tools",
		},
		{
			name:        "registered bare plugin id is accepted",
			commandName: "release-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.RegistryRequired = true
				cfg.AssetPolicy.Plugin.Registry = []config.AssetPolicyRule{{Name: "release-tools", Reason: "registry:internal"}}
			},
		},
		{
			name:        "unregistered bare plugin id is denied",
			commandName: "rogue-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.RegistryRequired = true
				cfg.AssetPolicy.Plugin.Registry = []config.AssetPolicyRule{{Name: "release-tools", Reason: "registry:internal"}}
			},
			wantMatched: true,
			wantSource:  "registry-required",
			wantTarget:  "rogue-tools",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.AssetPolicy.Enabled = true
			cfg.AssetPolicy.Mode = "action"
			enablePluginRuntimeDetection(cfg)
			tc.configure(cfg)
			api := &APIServer{scannerCfg: cfg}

			decisions := api.claudeCodeSlashCommandAssetDecisions(context.Background(), claudeCodeHookRequest{
				HookEventName: "UserPromptExpansion",
				ExpansionType: "slash_command",
				CommandName:   tc.commandName,
				CommandSource: "plugin",
			})

			if !tc.wantMatched {
				if len(decisions) != 0 {
					t.Fatalf("decisions=%+v, want policy allow", decisions)
				}
				return
			}
			if len(decisions) != 1 {
				t.Fatalf("decisions=%+v, want one policy block", decisions)
			}
			decision := decisions[0].decision
			if decision.Action != "block" || decision.Source != tc.wantSource || decision.TargetName != tc.wantTarget {
				t.Fatalf("decision=%+v, want block source=%q target=%q", decision, tc.wantSource, tc.wantTarget)
			}
		})
	}
}

// TestFirstMapStringRejectsNonStringValues pins the strict-string
// semantics the helper relies on. Earlier versions used fmt.Sprint
// which silently coerced bools/numbers/nested maps into strings like
// "false" / "0" / "map[a:b]" — this widened the registry-match surface
// because an agent could plant a non-string skill_name and have it
// stringified into a recognized identifier.
func TestFirstMapStringRejectsNonStringValues(t *testing.T) {
	cases := []struct {
		name   string
		values map[string]interface{}
		keys   []string
		want   string
	}{
		{
			name:   "string value passes through and is trimmed",
			values: map[string]interface{}{"k": "  hello  "},
			keys:   []string{"k"},
			want:   "hello",
		},
		{
			name:   "boolean value is rejected (not coerced to \"false\")",
			values: map[string]interface{}{"k": false},
			keys:   []string{"k"},
			want:   "",
		},
		{
			name:   "numeric value is rejected (not coerced to \"0\")",
			values: map[string]interface{}{"k": 0},
			keys:   []string{"k"},
			want:   "",
		},
		{
			name:   "nested map is rejected (not coerced to map[...] string)",
			values: map[string]interface{}{"k": map[string]interface{}{"a": "b"}},
			keys:   []string{"k"},
			want:   "",
		},
		{
			name:   "slice value is rejected (not joined into a fake command)",
			values: map[string]interface{}{"command": []interface{}{"bash", "-c", "rm -rf /"}},
			keys:   []string{"command"},
			want:   "",
		},
		{
			name:   "nil value is rejected (not coerced to \"<nil>\")",
			values: map[string]interface{}{"k": nil},
			keys:   []string{"k"},
			want:   "",
		},
		{
			name:   "empty string skips to next key",
			values: map[string]interface{}{"a": "", "b": "found"},
			keys:   []string{"a", "b"},
			want:   "found",
		},
		{
			name:   "missing keys return empty",
			values: map[string]interface{}{},
			keys:   []string{"a"},
			want:   "",
		},
		{
			name:   "nil map returns empty",
			values: nil,
			keys:   []string{"a"},
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstMapString(tc.values, tc.keys...); got != tc.want {
				t.Errorf("firstMapString(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMCPServerNameFromPromptFieldParsing pins the parsing semantics
// for the "command_source" / "command_name" prompt-expansion fields.
// These are agent-controlled, so any drift in this parser changes the
// asset-policy match surface (e.g. whether "/mcp/rogue/foo" maps to
// the registry name "rogue").
func TestMCPServerNameFromPromptFieldParsing(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"   ", ""},
		{"mcp", ""},
		{"MCP", ""},
		{"mcp_prompt", ""},
		{"prompt", ""},

		// Bare server name (Claude Code's common shape).
		{"github", "github"},
		{"  github  ", "github"},
		{`"github"`, "github"},
		{"'github'", "github"},

		// Standard prefixed shapes.
		{"mcp:rogue:foo", "rogue"},
		{"mcp__rogue__foo", "rogue"},
		{"mcp/rogue/foo", "rogue"},
		{"MCP:rogue:foo", "rogue"},
		{"Mcp__Rogue__Foo", "Rogue"},

		// Single segment after stripping prefix.
		{"mcp:rogue", "rogue"},
		{"mcp__rogue", "rogue"},

		// Pathological doubled prefixes — must collapse all the way,
		// not just one prefix worth, otherwise these would falsely
		// resolve to the literal "mcp" placeholder.
		{"mcp:mcp:server", "server"},
		{"mcp__mcp__server", "server"},
		{"mcp/mcp/server", "server"},

		// Hyphenated names without a recognized separator should
		// return the entire bare value, not be split arbitrarily.
		{"my-org-server", "my-org-server"},

		// Dotted names (Claude Code occasionally emits these).
		{"rogue.search", "rogue"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := mcpServerNameFromPromptField(tc.input); got != tc.want {
				t.Errorf("mcpServerNameFromPromptField(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestNormalizeSkillRuntimeNameDocumentsPathBehavior documents and
// pins the asset-policy-relevant behavior of skill name normalization:
// when an agent supplies a path-shaped value, normalization collapses
// to the basename. This is by design (the registry matches by name,
// not path), but it also means an agent CAN match an approved name
// using a crafted path. Any audit-detection effort relies on the raw
// input being preserved (see RawName / SourcePath), so this test
// pins the normalization contract.
func TestNormalizeSkillRuntimeNameDocumentsPathBehavior(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"   ", ""},
		{"foo", "foo"},
		{"@foo", "foo"},
		{`"foo"`, "foo"},
		{"'foo'", "foo"},

		// SKILL.md trailing component is stripped to expose the
		// directory name as the skill identifier.
		{"/path/to/foo/SKILL.md", "foo"},
		{"/path/to/foo/skill.md", "foo"},
		{"path/to/foo", "foo"},

		// Path traversal segments collapse via filepath.Base. This
		// is the behavior to flag/audit — it means an agent passing
		// "/tmp/x/<approved>/SKILL.md" matches "<approved>" if it
		// is in the registry. Operators must rely on RawName /
		// SourcePath in telemetry to detect crafted-path bypass.
		{"../../../trusted-skill", "trusted-skill"},
		{"/tmp/attacker/trusted-skill/SKILL.md", "trusted-skill"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := normalizeSkillRuntimeName(tc.input); got != tc.want {
				t.Errorf("normalizeSkillRuntimeName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestSkillProbePreservesRawNameWhenPathStripped is the audit-trail
// pin: when path normalization changed the agent's literal input
// into a different registry-matching name, the probe must still carry
// the original input so OTel/logs can show the discrepancy. Without
// this, a "trusted-skill" allow decision in the audit log is
// indistinguishable from one triggered by "/tmp/attacker/trusted-skill/SKILL.md".
func TestSkillProbePreservesRawNameWhenPathStripped(t *testing.T) {
	probe := skillProbeFromFields("Skill", map[string]interface{}{
		"skill_name": "/tmp/attacker/trusted-skill/SKILL.md",
	}, nil)
	if probe.SkillName != "trusted-skill" {
		t.Fatalf("SkillName = %q, want trusted-skill", probe.SkillName)
	}
	if probe.RawName != "/tmp/attacker/trusted-skill/SKILL.md" {
		t.Fatalf("RawName = %q, want full agent-supplied path", probe.RawName)
	}

	// When the agent supplies a literal name that already matches the
	// registry-canonical form, RawName must be empty so we don't spam
	// every legitimate request with a noisy "raw differs" annotation.
	probe = skillProbeFromFields("Skill", map[string]interface{}{
		"skill_name": "trusted-skill",
	}, nil)
	if probe.SkillName != "trusted-skill" {
		t.Fatalf("SkillName = %q, want trusted-skill", probe.SkillName)
	}
	if probe.RawName != "" {
		t.Fatalf("RawName = %q, want empty (no normalization happened)", probe.RawName)
	}
}

// TestAssetPolicyResponseReasonEmitsAllStructuredFields pins the
// structured-field layout of the response reason. The downstream
// redaction layer (internal/redaction.ForSinkReason) parses these as
// "key=value" tokens and applies its own value safety policy — that
// is why we deliberately do NOT quote values here, and why the
// decision.Reason free-form string is intentionally NOT appended:
// quoting or appending free-form prose would defeat the redactor's
// allow-list and replace every routine asset_name with a
// "<redacted len=N sha=...>" placeholder.
func TestAssetPolicyResponseReasonEmitsAllStructuredFields(t *testing.T) {
	decision := config.AssetPolicyDecision{
		Source:             "registry-required",
		TargetType:         "mcp",
		TargetName:         "rogue",
		Connector:          "claudecode",
		RegistryStatus:     "unregistered",
		RegistryConfigured: true,
		RuntimeSurface:     "hook",
		Reason:             "intentionally ignored — see doc comment on assetPolicyResponseReason",
	}
	got := assetPolicyResponseReason(decision)
	for _, want := range []string{
		"reason_code=not-in-approved-registry",
		"source=registry-required",
		"asset_type=mcp",
		"asset_name=rogue",
		"connector=claudecode",
		"registry_status=not-registered",
		"registry_configured=true",
		"surface=hook",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("response reason %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "detail=") {
		t.Errorf("response reason should NOT include detail= field; redactor would scrub it anyway: %q", got)
	}
}

// TestAssetPolicyResponseReasonRegistryRequiredEmptyHasOwnReasonCode
// pins the new "registry-required-but-empty" reason code so that
// dashboards / alerting filtering on reason_code can distinguish
// "you used an unapproved asset" (registry populated, target not in it)
// from "fail-closed because the registry itself was empty" (operator
// forgot to populate it). Same family of failure, different remediation.
func TestAssetPolicyResponseReasonRegistryRequiredEmptyHasOwnReasonCode(t *testing.T) {
	decision := config.AssetPolicyDecision{
		Source:             "registry-required-empty",
		TargetType:         "skill",
		TargetName:         "rogue-skill",
		Connector:          "codex",
		RegistryStatus:     "unregistered",
		RegistryConfigured: false,
	}
	got := assetPolicyResponseReason(decision)
	if !strings.Contains(got, "reason_code=registry-required-but-empty") {
		t.Errorf("response reason %q missing reason_code=registry-required-but-empty", got)
	}
	if !strings.Contains(got, "registry_configured=false") {
		t.Errorf("response reason %q missing registry_configured=false", got)
	}
}

// TestMergeAssetDecisionNonBlockingDecisionIsNoop ensures the merge
// function handles the (defensive) case where a non-blocking decision
// reaches it — earlier code shapes risked appending a finding even
// though no policy violation actually occurred.
func TestMergeAssetDecisionNonBlockingDecisionIsNoop(t *testing.T) {
	decision := config.AssetPolicyDecision{
		Action:    "allow",
		RawAction: "allow",
	}
	action, raw, sev, reason, findings, wouldBlock := mergeAssetDecision(
		decision, true, "mcp", "PreToolUse",
		"allow", "allow", "NONE", "ok", []string{"PRE-EXISTING"},
	)
	if action != "allow" || raw != "allow" || sev != "NONE" || reason != "ok" {
		t.Fatalf("merge mutated verdict on non-blocking decision: action=%q raw=%q sev=%q reason=%q",
			action, raw, sev, reason)
	}
	if wouldBlock {
		t.Fatal("wouldBlock=true on non-blocking decision")
	}
	if len(findings) != 1 || findings[0] != "PRE-EXISTING" {
		t.Fatalf("findings mutated: %v", findings)
	}
}

// TestMergeAssetDecisionDefaultsTargetTypeToASSET prevents the merge
// from emitting a malformed finding ID like "ASSET-POLICY-" when the
// caller forgot to populate targetType. Downstream SIEMs filter on
// "ASSET-POLICY-MCP" / "ASSET-POLICY-SKILL"; the empty form would
// silently disappear.
func TestMergeAssetDecisionDefaultsTargetTypeToASSET(t *testing.T) {
	decision := config.AssetPolicyDecision{
		Action:    "block",
		RawAction: "block",
		Reason:    "blocked",
		Source:    "default-deny",
	}
	_, _, _, _, findings, _ := mergeAssetDecision(
		decision, true, "  ", "PreToolUse",
		"allow", "allow", "NONE", "", nil,
	)
	if len(findings) == 0 || findings[len(findings)-1] != "ASSET-POLICY-ASSET" {
		t.Fatalf("findings = %v, want trailing ASSET-POLICY-ASSET fallback", findings)
	}
}
