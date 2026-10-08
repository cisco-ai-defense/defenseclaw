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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func enableSkillRuntimeDetection(cfg *config.Config) {
	cfg.AssetPolicy.Skill.RuntimeDetection.Enabled = true
}

func enablePluginRuntimeDetection(cfg *config.Config) {
	cfg.AssetPolicy.Plugin.RuntimeDetection.Enabled = true
}

func TestCursorMCPProbePreservesEndpointAndAvoidsToolNameCollisions(t *testing.T) {
	first := cursorMCPProbeFromPayload(map[string]interface{}{
		"url": "https://alpha.example.test/mcp",
	}, "lookup")
	second := cursorMCPProbeFromPayload(map[string]interface{}{
		"url": "https://beta.example.test/mcp",
	}, "lookup")
	if !first.Matched || !second.Matched || first.ServerName == second.ServerName {
		t.Fatalf("endpoint identities collided: first=%+v second=%+v", first, second)
	}
	framed := cursorMCPProbeFromPayload(map[string]interface{}{
		"url":     "a",
		"command": "b",
	}, "lookup")
	injectedDelimiter := cursorMCPProbeFromPayload(map[string]interface{}{
		"url": "a\x00command\x00b",
	}, "lookup")
	if framed.ServerName == injectedDelimiter.ServerName {
		t.Fatalf("framing collision: both=%+v injected=%+v", framed, injectedDelimiter)
	}
	if first.URL != "https://alpha.example.test/mcp" || first.Transport != "http" {
		t.Fatalf("endpoint probe lost authoritative fields: %+v", first)
	}
	command := cursorMCPProbeFromPayload(map[string]interface{}{
		"command": `node server.js --tenant alpha`,
	}, "lookup")
	if command.Command != "node" || !reflect.DeepEqual(command.Args, []string{"server.js", "--tenant", "alpha"}) || command.Transport != "stdio" {
		t.Fatalf("command probe=%+v", command)
	}
}

func TestCursorMCPProbeFeedsEndpointAwareAssetPolicy(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{
		Connector: "cursor",
		URL:       "https://blocked.example.test/mcp",
		Transport: "http",
	}}
	api := &APIServer{scannerCfg: cfg}
	blocked := cursorMCPProbeFromPayload(map[string]interface{}{
		"url": "https://blocked.example.test/mcp",
	}, "lookup")
	decision, matched := api.evaluateRuntimeMCPAssetPolicy(context.Background(), "cursor", "beforeMCPExecution", blocked)
	if !matched || decision.RawAction != "block" || decision.TargetName != blocked.ServerName {
		t.Fatalf("endpoint policy decision=%+v matched=%v probe=%+v", decision, matched, blocked)
	}
	allowed := cursorMCPProbeFromPayload(map[string]interface{}{
		"url": "https://allowed.example.test/mcp",
	}, "lookup")
	if decision, matched := api.evaluateRuntimeMCPAssetPolicy(context.Background(), "cursor", "beforeMCPExecution", allowed); matched {
		t.Fatalf("collision fixture matched wrong endpoint: %+v", decision)
	}
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

	// GAP-0566: an explicit denied entry applies whatever runtime_detection
	// says, for skills and for plugin commands.
	cfg.AssetPolicy.Enabled = false
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "epa-deny"}}
	cfg.AssetPolicy.Plugin.Denied = []config.AssetPolicyRule{{Name: "epa-plug-deny"}}
	for _, probe := range []skillRuntimeProbe{
		{SkillName: "epa-deny", ToolName: "Skill", Surface: "hook", Matched: true},
		{TargetType: "plugin", SkillName: "epa-plug-deny", Surface: "prompt_expansion", Matched: true},
	} {
		decision, matched := api.runtimeSkillAssetPolicyDecision("claudecode", probe)
		if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
			t.Fatalf("%s %s: matched=%v decision=%+v, want an admin-deny block", probe.TargetType, probe.SkillName, matched, decision)
		}
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
			store, logger := newNativeSkillRuntimeTestStore(t)
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}

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
		// The decision vocabulary, as the asset-policy audit row has it
		// (GAP-2516).
		"registry_status=unregistered",
		"registry_configured=true",
		"surface=hook",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("response reason %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "not-registered") {
		t.Errorf("response reason %q renames registry_status; the asset-policy row says unregistered", got)
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

// TestHookResponseRuleIDsCarriesAssetPolicyRule pins GAP-2489: an asset
// policy block names its rule on the hook response (and so on the tool
// span's defenseclaw.guardrail.rule_id); a hook-rule block keeps its own
// rule first.
func TestHookResponseRuleIDsCarriesAssetPolicyRule(t *testing.T) {
	assets := []runtimeAssetDecision{
		{targetType: "mcp", decision: config.AssetPolicyDecision{RawAction: "block", Source: "registry-required"}},
		{targetType: "skill", decision: config.AssetPolicyDecision{RawAction: "allow", Source: "admin-allow"}},
	}
	if got := hookResponseRuleIDs(nil, "allow", assets); len(got) != 1 || got[0] != "asset_policy.mcp.registry-required" {
		t.Fatalf("asset block rule IDs = %v", got)
	}
	if got := hookResponseRuleIDs([]string{"CMD-1"}, "block", assets); len(got) != 2 || got[0] != "CMD-1" {
		t.Fatalf("hook block rule IDs = %v, want CMD-1 first", got)
	}
	if got := hookResponseRuleIDs([]string{"CMD-1"}, "allow", nil); len(got) != 1 || got[0] != "CMD-1" {
		t.Fatalf("no-asset rule IDs = %v", got)
	}
}

// GAP-0577: an asset-policy audit row names the verified caller under the
// keys the hook_decision row of the same event uses.
func TestAssetPolicyAuditRowNamesTheCaller(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "dcr-epa1"})
	api.logAssetPolicyAudit(ctx, "claudecode", "skill:epa-deny", "action=block source=admin-deny")
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action != string(audit.ActionAssetPolicy) {
			continue
		}
		if event.Structured[auditUserIDKey] != "1001" || event.Structured[auditUserNameKey] != "dcr-epa1" || event.Connector != "claudecode" {
			t.Fatalf("asset-policy row connector=%q structured=%v, want the caller", event.Connector, event.Structured)
		}
		return
	}
	t.Fatal("no asset-policy audit row")
}

// GAP-0570: a skill folder whose SKILL.md declares a denied name is denied
// under its own folder name, and a declared name never admits a skill.
func TestClaudeCodeSkillDeniedByDeclaredName(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "epa-alias")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: epa-deny\n---\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "epa-deny"}}
	api := &APIServer{scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1003, Home: home})
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Skill", ToolInput: map[string]interface{}{"skill": "epa-alias"}}
	if decision, matched := api.claudeCodeSkillAssetDecision(ctx, req); !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("matched=%v decision=%+v, want an admin-deny block", matched, decision)
	}

	cfg.AssetPolicy.Skill.Denied = nil
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "epa-deny"}}
	cfg.AssetPolicy.Enabled, cfg.AssetPolicy.Mode, cfg.AssetPolicy.Skill.Default = true, "action", "deny"
	enableSkillRuntimeDetection(cfg)
	if decision, matched := api.claudeCodeSkillAssetDecision(ctx, req); !matched || decision.Source != "default-deny" {
		t.Fatalf("matched=%v decision=%+v, want the declared name not to admit epa-alias", matched, decision)
	}
}

// GAP-0569: Codex asked for a denied skill in plain words reads its SKILL.md
// with a shell command; the read is refused, other skill folders are not.
func TestCodexReadOfDeniedSkillFolderIsBlocked(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "epa-two", Connector: "codex"}}
	api := &APIServer{scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: t.TempDir()})
	read := func(command string) (config.AssetPolicyDecision, bool) {
		return api.codexSkillAssetDecision(ctx, codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash",
			ToolInput: map[string]interface{}{"command": []interface{}{"bash", "-lc", command}},
		})
	}
	if decision, matched := read("sed -n 1,200p ~/.codex/skills/epa-two/SKILL.md"); !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("matched=%v decision=%+v, want the denied skill folder refused", matched, decision)
	}
	if decision, matched := read("cat ~/.codex/skills/epa-ok/SKILL.md"); matched {
		t.Fatalf("an allowed skill folder was refused: %+v", decision)
	}
}

// GAP-0798: project skill folders (<project>\.claude\skills,
// <project>\.agents\skills) get no install admission, inside or outside the
// profile; a denied name is refused at the hook there too, with
// runtime_detection off: Claude Code's Skill call in the project and Codex
// reading the project skill's SKILL.md.
func TestDeniedSkillInAProjectFolderIsRefused(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "epa-two-e"}}
	api := &APIServer{scannerCfg: cfg}
	project := filepath.Join(t.TempDir(), "p3")
	if err := os.MkdirAll(filepath.Join(project, ".claude", "skills", "epa-two-e"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: t.TempDir()})
	claude := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
		ToolInput: map[string]interface{}{"skill": "epa-two-e"}}
	if decision, matched := api.claudeCodeSkillAssetDecision(ctx, claude); !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("claude: matched=%v decision=%+v, want an admin-deny block", matched, decision)
	}
	for _, command := range []string{`Get-Content .agents\skills\epa-two-e\SKILL.md`, `type C:\work\pw1\p3\.claude\skills\epa-two-e\SKILL.md`} {
		decision, matched := api.codexSkillAssetDecision(ctx, codexHookRequest{HookEventName: "PreToolUse", ToolName: "Bash", CWD: project,
			ToolInput: map[string]interface{}{"command": command}})
		if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
			t.Fatalf("codex %q: matched=%v decision=%+v, want an admin-deny block", command, matched, decision)
		}
	}
}

// GAP-0576: on a standalone gateway a url rule matches the server the
// caller's agent configures: read in the caller's home, or, where the
// gateway may not read it, as the standalone hook reported it.
func TestMCPURLRuleMatchesTheCallersServer(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: "http://127.0.0.1:28561/mcp"}}
	api := &APIServer{scannerCfg: cfg}
	home, project := t.TempDir(), t.TempDir()
	state := `{"projects":{"` + filepath.ToSlash(project) + `":{"mcpServers":{"notes":{"type":"http","url":"http://127.0.0.1:28561/mcp"}}}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	call := func(ctx context.Context) bool {
		_, matched := api.claudeCodeMCPAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "mcp__notes__count_words", CWD: project,
		})
		return matched
	}
	if !call(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})) {
		t.Fatal("url deny did not match the server in the caller's home")
	}
	reported := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001}),
		claimedAssetFactsContextKey{}, assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "notes", URL: "http://127.0.0.1:28561/mcp"}})
	if !call(reported) {
		t.Fatal("url deny did not match the server the hook reported")
	}
	other := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1003}),
		claimedAssetFactsContextKey{}, assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "notes", URL: "http://127.0.0.1:28562/mcp"}})
	if call(other) {
		t.Fatal("url deny matched another user's server")
	}
}

// Every source path for a skill name must be checked before the tool runs.
func TestCodexReadChecksEverySameNameSkillFolder(t *testing.T) {
	home := t.TempDir()
	benign := filepath.Join(t.TempDir(), "skills", "blocked")
	denied := filepath.Join(home, ".agents", "skills", "blocked")
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{
		Name: "blocked", Connector: "codex", SourcePathContains: []string{denied},
	}}
	api := &APIServer{scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: home})
	decision, matched := api.codexSkillAssetDecision(ctx, codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": "cat " + benign + "/SKILL.md " + denied + "/SKILL.md"},
	})
	if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("same-name folder decision = %+v, matched=%v; want denied path block", decision, matched)
	}
}
