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
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestLexCodexSkillSelectionsStrictGrammar(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
		want   []codexSkillSelection
	}{
		{
			name:   "beginning end punctuation and multiple",
			prompt: "$alpha, then ($beta-two) and $plugin:review! End with $omega",
			want: []codexSkillSelection{
				{Name: "alpha", Raw: "$alpha"},
				{Name: "beta-two", Raw: "$beta-two"},
				{Name: "plugin:review", Raw: "$plugin:review"},
				{Name: "omega", Raw: "$omega"},
			},
		},
		{
			name:   "duplicates preserve first raw selection only",
			prompt: "$alpha $alpha",
			want:   []codexSkillSelection{{Name: "alpha", Raw: "$alpha"}},
		},
		{
			name:   "escaped dollar forms",
			prompt: "\\$alpha\n`$beta\n`literal $gamma`\n$delta",
			want:   []codexSkillSelection{{Name: "delta", Raw: "$delta"}},
		},
		{
			name:   "fenced and indented code",
			prompt: "before $allowed\n```powershell\n$blocked\n```\n~~~\n$also-blocked\n~~~\n    $indented\nafter $visible",
			want: []codexSkillSelection{
				{Name: "allowed", Raw: "$allowed"},
				{Name: "visible", Raw: "$visible"},
			},
		},
		{
			name:   "multiline CommonMark inline code spans",
			prompt: "before $first and `inline\n$hidden` after $second\nthen ``more code\n$also-hidden`` and $third",
			want: []codexSkillSelection{
				{Name: "first", Raw: "$first"},
				{Name: "second", Raw: "$second"},
				{Name: "third", Raw: "$third"},
			},
		},
		{
			name:   "matched dollar-leading inline span wins over PowerShell escape",
			prompt: "`$allowed $disabled` then $visible",
			want:   []codexSkillSelection{{Name: "visible", Raw: "$visible"}},
		},
		{
			name:   "multiline dollar-leading inline span wins over PowerShell escape",
			prompt: "`$allowed\n$disabled` then $visible",
			want:   []codexSkillSelection{{Name: "visible", Raw: "$visible"}},
		},
		{
			name:   "unmatched backtick runs do not hide selections",
			prompt: "unmatched `` code $first\nstill $second\n` another unmatched run before $third",
			want: []codexSkillSelection{
				{Name: "first", Raw: "$first"},
				{Name: "second", Raw: "$second"},
				{Name: "third", Raw: "$third"},
			},
		},
		{
			name:   "escaped backticks do not create code spans",
			prompt: "\\`literal delimiter before $first \\` and $second",
			want: []codexSkillSelection{
				{Name: "first", Raw: "$first"},
				{Name: "second", Raw: "$second"},
			},
		},
		{
			name: "fences inside block quote and list containers",
			prompt: "> ```powershell\n> $quote-hidden\n> ```\n> $quote-visible\n" +
				"- ~~~\n  $list-hidden\n  ~~~\n- $list-visible\n" +
				"1. ```text\n   $ordered-hidden\n   ```\n2. $ordered-visible\n" +
				"> - ```\n>   $nested-hidden\n>   ```\n> - $nested-visible",
			want: []codexSkillSelection{
				{Name: "quote-visible", Raw: "$quote-visible"},
				{Name: "list-visible", Raw: "$list-visible"},
				{Name: "ordered-visible", Raw: "$ordered-visible"},
				{Name: "nested-visible", Raw: "$nested-visible"},
			},
		},
		{
			name: "indented code inside CommonMark containers",
			prompt: ">     $quote-hidden\n> $quote-visible\n" +
				"-     $list-hidden\n- $list-visible\n" +
				"1.     $ordered-hidden\n2. $ordered-visible\n" +
				"> -     $nested-hidden\n> - $nested-visible",
			want: []codexSkillSelection{
				{Name: "quote-visible", Raw: "$quote-visible"},
				{Name: "list-visible", Raw: "$list-visible"},
				{Name: "ordered-visible", Raw: "$ordered-visible"},
				{Name: "nested-visible", Raw: "$nested-visible"},
			},
		},
		{
			name:   "unterminated container fence ends with its container",
			prompt: "> ```\n> $quote-hidden\n$outside-quote\n- ~~~\n  $list-hidden\n- $outside-list",
			want: []codexSkillSelection{
				{Name: "outside-quote", Raw: "$outside-quote"},
				{Name: "outside-list", Raw: "$outside-list"},
			},
		},
		{
			name:   "shell and currency shapes remain exact-lookup candidates",
			prompt: "$HOME $Path $env:HOME $global:name $script:name $local:name $private:name $using:name ${HOME} $PID costs $5 or $100.00; use $real-skill",
			want: []codexSkillSelection{
				{Name: "HOME", Raw: "$HOME"},
				{Name: "Path", Raw: "$Path"},
				{Name: "env:HOME", Raw: "$env:HOME"},
				{Name: "global:name", Raw: "$global:name"},
				{Name: "script:name", Raw: "$script:name"},
				{Name: "local:name", Raw: "$local:name"},
				{Name: "private:name", Raw: "$private:name"},
				{Name: "using:name", Raw: "$using:name"},
				{Name: "PID", Raw: "$PID"},
				{Name: "5", Raw: "$5"},
				{Name: "real-skill", Raw: "$real-skill"},
			},
		},
		{
			name:   "unicode and path shapes excluded while source grammar starts remain candidates",
			prompt: "$álpha $alphaβ $alpha/child $alpha\\child $alpha.md $_alpha $-alpha $1alpha $valid.",
			want: []codexSkillSelection{
				{Name: "_alpha", Raw: "$_alpha"},
				{Name: "-alpha", Raw: "$-alpha"},
				{Name: "1alpha", Raw: "$1alpha"},
				{Name: "valid", Raw: "$valid"},
			},
		},
		{
			name:   "Codex namespace grammar and markdown link",
			prompt: "Use $ns:1skill or [$linked-label](skill://actual-skill)",
			want: []codexSkillSelection{
				{Name: "ns:1skill", Raw: "$ns:1skill"},
				{
					Name:       "linked-label",
					Raw:        "$linked-label",
					LinkedPath: "skill://actual-skill",
				},
			},
		},
		{
			name:   "linked mention preserves mismatched label path but bounds raw audit token",
			prompt: "Use [$allowed-label]  ( C:\\skills\\$path-decoy\\disabled-skill\\SKILL.md ) then $visible",
			want: []codexSkillSelection{
				{
					Name:       "allowed-label",
					Raw:        "$allowed-label",
					LinkedPath: "C:\\skills\\$path-decoy\\disabled-skill\\SKILL.md",
				},
				{Name: "visible", Raw: "$visible"},
			},
		},
		{
			name:   "linked mention consumes documented multiline whitespace",
			prompt: "[$alias]\n  ( skill://actual-skill ) then $visible",
			want: []codexSkillSelection{
				{Name: "alias", Raw: "$alias", LinkedPath: "skill://actual-skill"},
				{Name: "visible", Raw: "$visible"},
			},
		},
		{
			name:   "same linked label retains distinct exact paths",
			prompt: "[$alias](skill://first) and [$alias](skill://second)",
			want: []codexSkillSelection{
				{Name: "alias", Raw: "$alias", LinkedPath: "skill://first"},
				{Name: "alias", Raw: "$alias", LinkedPath: "skill://second"},
			},
		},
		{
			name:   "code between link label and destination does not form a link",
			prompt: "[$alias] `not link whitespace` (skill://disabled) then $visible",
			want: []codexSkillSelection{
				{Name: "alias", Raw: "$alias"},
				{Name: "visible", Raw: "$visible"},
			},
		},
		{
			name:   "linked non-skill resource is consumed and marked by path",
			prompt: "[$friendly](app://connector-id/with-$path-decoy) then $visible",
			want: []codexSkillSelection{
				{Name: "friendly", Raw: "$friendly", LinkedPath: "app://connector-id/with-$path-decoy"},
				{Name: "visible", Raw: "$visible"},
			},
		},
		{
			name:   "identifier substrings are not selections",
			prompt: "prefix$alpha snake_$beta $$gamma but [$delta]",
			want:   []codexSkillSelection{{Name: "delta", Raw: "$delta"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lexCodexSkillSelections(tc.prompt); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("lexCodexSkillSelections() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestLexCodexSkillSelectionsAdversarialInputRemainsBounded(t *testing.T) {
	const repetitions = 8192
	var prompt strings.Builder
	prompt.Grow(repetitions * 24)
	for range repetitions {
		prompt.WriteString("`$hidden` ")
	}
	for range repetitions {
		prompt.WriteString("[$broken]( ")
	}
	prompt.WriteString("$final-real")

	want := []codexSkillSelection{
		{Name: "broken", Raw: "$broken"},
		{Name: "final-real", Raw: "$final-real"},
	}
	if got := lexCodexSkillSelections(prompt.String()); !reflect.DeepEqual(got, want) {
		t.Fatalf("adversarial lex result = %#v, want %#v", got, want)
	}
}

func TestCodexPromptUnknownSelectionVolumeDoesNotHideKnownTail(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "action")
	if err := store.SetActionFieldForConnector(
		"skill", "disabled-tail", "codex", "runtime", "disable", "test",
	); err != nil {
		t.Fatal(err)
	}
	var prompt strings.Builder
	for i := 0; i <= codexMaxPromptSkillSelections; i++ {
		fmt.Fprintf(&prompt, "$unknown-%d ", i)
	}
	prompt.WriteString("$disabled-tail tail prompt secret")

	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        prompt.String(),
	})
	if resp.Action != "block" || !strings.Contains(resp.Reason, "asset_name=disabled-tail") {
		t.Fatalf("known tail selection was not enforced: action=%q reason=%q", resp.Action, resp.Reason)
	}
	if strings.Contains(resp.Reason, "unknown-") || strings.Contains(resp.Reason, "tail prompt secret") {
		t.Fatalf("selection overflow leaked prompt material: %q", resp.Reason)
	}

	var resources strings.Builder
	for i := 0; i <= codexMaxPromptSkillSelections; i++ {
		fmt.Fprintf(&resources, "[$app-%d](app://fixture-%d) ", i, i)
	}
	allowed := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        resources.String(),
	})
	if allowed.Action != "allow" || allowed.RawAction != "allow" {
		t.Fatalf("non-skill linked resources counted as skill overflow: action=%q reason=%q", allowed.Action, allowed.Reason)
	}

	var unknownOnly strings.Builder
	for i := 0; i <= codexMaxPromptSkillSelections; i++ {
		fmt.Fprintf(&unknownOnly, "$ordinary-%d ", i)
	}
	allowed = api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        unknownOnly.String(),
	})
	if allowed.Action != "allow" || allowed.RawAction != "allow" {
		t.Fatalf("unknown prose counted as skill overflow: action=%q reason=%q", allowed.Action, allowed.Reason)
	}
}

func TestCodexPromptKnownSelectionVolumeFailsClosed(t *testing.T) {
	api, _ := newCodexPromptSkillTestAPI(t, "action")
	api.scannerCfg.AssetPolicy.Enabled = true
	api.scannerCfg.AssetPolicy.Mode = config.AssetPolicyModeAction
	api.scannerCfg.AssetPolicy.Skill.RuntimeDetection.Enabled = true
	var prompt strings.Builder
	for i := 0; i <= codexMaxPromptSkillSelections; i++ {
		name := fmt.Sprintf("known-%d", i)
		api.scannerCfg.AssetPolicy.Skill.Allowed = append(
			api.scannerCfg.AssetPolicy.Skill.Allowed,
			config.AssetPolicyRule{Name: name, Connector: "codex"},
		)
		fmt.Fprintf(&prompt, "$%s ", name)
	}

	decisions := api.codexPromptSkillAssetDecisions(context.Background(), prompt.String())
	if len(decisions) == 0 || decisions[len(decisions)-1].decision.Source != "runtime-disable-error" {
		t.Fatalf("known selection overflow did not fail closed: %#v", decisions)
	}
}

func TestCodexUserPromptSubmitReal01440PayloadRuntimeDisabledSkill(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "action")
	dispatcher, notifications := newWiringDispatcher()
	api.SetNotifier(dispatcher)
	const disabledSkill = "dc-win-scope-0715194921"
	expectedRuntimeReason := fmt.Sprintf("skill %q is runtime-disabled for connector %q", disabledSkill, "codex")
	expectedSinkReason := string(redaction.ForSinkReason(expectedRuntimeReason))
	if err := store.SetActionFieldForConnector("skill", disabledSkill, "codex", "runtime", "disable", "Runtime-disable acceptance"); err != nil {
		t.Fatalf("disable Codex skill: %v", err)
	}

	// Captured field-for-field from the packaged Codex CLI 0.144.0
	// UserPromptSubmit hook. The raw capture was 382 UTF-8 bytes and
	// intentionally had no structured skill_name.
	payload := []byte(`{"session_id":"019f684e-282e-7ee0-b22a-8daf7ebeb30d","turn_id":"019f684e-2c11-71f1-b400-d11112b3c7fa","transcript_path":null,"cwd":"C:\\Users\\kevin\\.codex\\worktrees\\778f\\defenseclaw","hook_event_name":"UserPromptSubmit","model":"gpt-5.6-sol","permission_mode":"bypassPermissions","prompt":"Use $dc-win-scope-0715194921 to greet Kevin. Do not run any tools or write any files."}`)
	if len(payload) != 382 {
		t.Fatalf("captured payload length = %d, want 382 UTF-8 bytes", len(payload))
	}
	var req codexHookRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("decode captured payload: %v", err)
	}
	if req.ToolName != "" || req.ToolInput != nil {
		t.Fatalf("captured prompt unexpectedly had structured skill identity: tool=%q input=%v", req.ToolName, req.ToolInput)
	}

	resp := api.evaluateCodexHook(context.Background(), req)
	if resp.Action != "block" || resp.RawAction != "block" || resp.Severity != "HIGH" || resp.WouldBlock {
		t.Fatalf("runtime-disabled selection verdict = action=%q raw=%q severity=%q would_block=%v", resp.Action, resp.RawAction, resp.Severity, resp.WouldBlock)
	}
	if got := resp.CodexOutput["decision"]; got != "block" {
		t.Fatalf("Codex output decision = %v, want block", got)
	}
	for _, want := range []string{"reason_code=runtime-disable", "source=runtime-disable", "asset_type=skill", "asset_name=", "connector=codex", "surface=" + codexPromptSkillSurface} {
		if !strings.Contains(resp.Reason, want) {
			t.Errorf("response reason %q missing %q", resp.Reason, want)
		}
	}
	if strings.Contains(resp.Reason, "greet Kevin") || strings.Contains(resp.Reason, "Do not run") {
		t.Fatalf("response leaked prompt body: %q", resp.Reason)
	}

	toasts := notifications.WaitFor(t, 1)
	toast := toasts[0]
	if !strings.Contains(toast.Title, "skill:"+disabledSkill) {
		t.Errorf("runtime-disable notification title %q missing typed skill identity", toast.Title)
	}
	if !strings.Contains(toast.Subtitle, "codex") {
		t.Errorf("runtime-disable notification subtitle %q missing connector", toast.Subtitle)
	}
	if toast.Body != expectedSinkReason {
		t.Errorf("runtime-disable notification body = %q, want sink-safe enforcement reason %q", toast.Body, expectedSinkReason)
	}
	for _, field := range []string{toast.Title, toast.Subtitle, toast.Body} {
		if strings.Contains(field, "greet Kevin") || strings.Contains(field, "Do not run") {
			t.Errorf("runtime-disable notification leaked prompt body: title=%q subtitle=%q body=%q", toast.Title, toast.Subtitle, toast.Body)
			break
		}
	}

	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Target != "skill:"+disabledSkill {
			continue
		}
		found = true
		if event.Connector != "codex" || !strings.Contains(event.Details, "source=runtime-disable") ||
			!strings.Contains(event.Details, "reason="+expectedSinkReason) ||
			!strings.Contains(event.Details, "surface="+codexPromptSkillSurface) || !strings.Contains(event.Details, "name_raw=") {
			t.Errorf("incomplete connector-tagged audit event: connector=%q details=%q", event.Connector, event.Details)
		}
		if strings.Contains(event.Details, "greet Kevin") || strings.Contains(event.Details, "Do not run") {
			t.Errorf("audit event leaked prompt body: %q", event.Details)
		}
	}
	if !found {
		t.Fatal("runtime-disabled prompt selection did not generate an asset-policy audit event")
	}
}

func TestCodexUserPromptSubmitAllowedUnknownAndSimilarPrefixContinue(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "action")
	if err := store.SetActionFieldForConnector("skill", "review-danger", "codex", "runtime", "disable", "test"); err != nil {
		t.Fatalf("disable similar-prefix skill: %v", err)
	}

	for _, prompt := range []string{
		"Use $review to summarize this change.",
		"Use $ordinary-prose if it exists.",
		"This costs $5 or $100.00.",
		"Use `$review-danger` as an example only.",
	} {
		resp := api.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: prompt})
		if resp.Action != "allow" || resp.RawAction != "allow" {
			t.Errorf("prompt %q = action=%q raw=%q, want allow", prompt, resp.Action, resp.RawAction)
		}
	}
}

func TestCodexUserPromptSubmitBlocksExactKnownIdentitiesAcrossSourceGrammar(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "action")
	for _, skill := range []string{"1skill", "_skill", "-skill", "ns:1skill", "5", "home"} {
		if err := store.SetActionFieldForConnector("skill", skill, "codex", "runtime", "disable", "test"); err != nil {
			t.Fatalf("disable %q: %v", skill, err)
		}
	}
	for _, prompt := range []string{
		"Use $1skill",
		"Use $_skill",
		"Use $-skill",
		"Use $ns:1skill",
		"Use $5",
		"Use $home",
	} {
		resp := api.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: prompt})
		if resp.Action != "block" {
			t.Errorf("known source-grammar selection %q = action=%q reason=%q, want block", prompt, resp.Action, resp.Reason)
		}
	}
}

func TestCodexLinkedMentionResolvesExactProvenancePathBeforeLabel(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "action")
	root := t.TempDir()
	disabledSource := filepath.Join(root, "codex", "disabled-skill")
	allowedSource := filepath.Join(root, "codex", "allowed-skill")
	linkedUnicodeAllowedSource := filepath.Join(root, "codex", "linked-unicode-allowed")
	linkedUnicodeDisabledSource := filepath.Join(root, "codex", "linked-unicode-disabled")
	peerSource := filepath.Join(root, "claude", "disabled-skill")
	if err := store.SetActionForConnector(
		"skill",
		"disabled-skill",
		"codex",
		disabledSource,
		audit.ActionState{Runtime: "disable"},
		"runtime isolation",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(
		"skill",
		"allowed-skill",
		"codex",
		allowedSource,
		audit.ActionState{Runtime: "enable"},
		"explicitly enabled",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(
		"skill",
		"Allowed Δ.skill",
		"codex",
		linkedUnicodeAllowedSource,
		audit.ActionState{Runtime: "enable"},
		"linked metadata fixture",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(
		"skill",
		"Disabled Δ.skill",
		"codex",
		linkedUnicodeDisabledSource,
		audit.ActionState{Runtime: "disable"},
		"linked metadata fixture",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(
		"skill",
		"peer-disabled-skill",
		"claudecode",
		peerSource,
		audit.ActionState{Runtime: "disable"},
		"peer-only runtime policy",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector(
		"skill", "disabled-label", "codex", "runtime", "disable", "label fixture",
	); err != nil {
		t.Fatal(err)
	}

	disabledManifest := filepath.Join(disabledSource, "SKILL.md")
	for _, prompt := range []string{
		"Use [$allowed-label](" + disabledManifest + ") now.",
		"Use [$another-label](skill://" + disabledManifest + ") now.",
		"Use [$metadata-label](" + filepath.Join(linkedUnicodeDisabledSource, "SKILL.md") + ") now.",
	} {
		resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
			HookEventName: "UserPromptSubmit",
			Prompt:        prompt,
		})
		if resp.Action != "block" ||
			!strings.Contains(resp.Reason, "asset_type=skill") ||
			!strings.Contains(resp.Reason, "source=runtime-disable") {
			t.Fatalf("exact disabled linked path was not blocked: action=%q reason=%q", resp.Action, resp.Reason)
		}
		if strings.Contains(resp.Reason, "Use [") || strings.Contains(resp.Reason, disabledManifest) {
			t.Fatalf("response leaked linked prompt material: %q", resp.Reason)
		}
	}
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	foundSafeAudit := false
	for _, event := range events {
		if event.Target != "skill:disabled-skill" {
			continue
		}
		foundSafeAudit = true
		if !strings.Contains(event.Details, "name_raw=") ||
			strings.Contains(event.Details, "Use [") || strings.Contains(event.Details, " now.") {
			t.Fatalf("linked audit did not retain only bounded selection evidence: %q", event.Details)
		}
	}
	if !foundSafeAudit {
		t.Fatal("disabled linked mention emitted no connector-tagged audit event")
	}

	for _, prompt := range []string{
		"[$disabled-label](" + filepath.Join(allowedSource, "SKILL.md") + ")",
		"[$metadata-label](" + filepath.Join(linkedUnicodeAllowedSource, "SKILL.md") + ")",
		"[$disabled-label](" + filepath.Join(root, "missing", "SKILL.md") + ")",
		"[$disabled-label](app://calendar)",
		"[$disabled-label](mcp://server/tool)",
		"[$disabled-label](plugin://fixture)",
		"[$disabled-label](" + filepath.Join(peerSource, "SKILL.md") + ")",
	} {
		resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
			HookEventName: "UserPromptSubmit",
			Prompt:        prompt,
		})
		if resp.Action != "allow" || resp.RawAction != "allow" {
			t.Errorf("non-disabled linked resource %q = action=%q reason=%q", prompt, resp.Action, resp.Reason)
		}
	}
}

func TestCodexLinkedMentionAmbiguousTrustedPathFailsClosed(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "action")
	source := filepath.Join(t.TempDir(), "codex", "ambiguous")
	for _, name := range []string{"first-identity", "second-identity"} {
		if err := store.SetActionForConnector(
			"skill",
			name,
			"codex",
			source,
			audit.ActionState{Runtime: "enable"},
			"ambiguous provenance fixture",
		); err != nil {
			t.Fatal(err)
		}
	}
	prompt := "[$label](" + filepath.Join(source, "SKILL.md") + ")"
	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        prompt,
	})
	if resp.Action != "block" || !strings.Contains(resp.Reason, "source=runtime-disable-error") {
		t.Fatalf("ambiguous linked identity did not fail closed: action=%q reason=%q", resp.Action, resp.Reason)
	}
	if strings.Contains(resp.Reason, source) {
		t.Fatalf("ambiguous linked prompt path leaked into response: %q", resp.Reason)
	}

	invalidSource := filepath.Join(t.TempDir(), "codex", "invalid")
	if err := store.SetActionForConnector(
		"skill",
		"",
		"codex",
		invalidSource,
		audit.ActionState{Runtime: "enable"},
		"invalid provenance fixture",
	); err != nil {
		t.Fatal(err)
	}
	invalid := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        "[$label](" + filepath.Join(invalidSource, "SKILL.md") + ")",
	})
	if invalid.Action != "block" || !strings.Contains(invalid.Reason, "source=runtime-disable-error") {
		t.Fatalf("non-canonical linked provenance did not fail closed: action=%q reason=%q", invalid.Action, invalid.Reason)
	}
}

func TestCodexUserPromptSubmitRuntimeDisableScopeAndGlobalPrecedence(t *testing.T) {
	const skill = "same-skill-name"
	t.Run("Claude scoped disable does not affect Codex", func(t *testing.T) {
		api, store := newCodexPromptSkillTestAPI(t, "action")
		if err := store.SetActionFieldForConnector("skill", skill, "claudecode", "runtime", "disable", "test"); err != nil {
			t.Fatal(err)
		}
		resp := api.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: "Use $" + skill})
		if resp.Action != "allow" {
			t.Fatalf("Claude-scoped state changed Codex: action=%q reason=%q", resp.Action, resp.Reason)
		}
	})

	t.Run("global disable applies and scoped enable overrides it", func(t *testing.T) {
		api, store := newCodexPromptSkillTestAPI(t, "action")
		if err := store.SetActionField("skill", skill, "runtime", "disable", "test"); err != nil {
			t.Fatal(err)
		}
		req := codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: "Use $" + skill}
		if resp := api.evaluateCodexHook(context.Background(), req); resp.Action != "block" {
			t.Fatalf("global runtime disable action=%q, want block", resp.Action)
		}
		if err := store.SetActionFieldForConnector("skill", skill, "codex", "runtime", "enable", "test"); err != nil {
			t.Fatal(err)
		}
		if resp := api.evaluateCodexHook(context.Background(), req); resp.Action != "allow" {
			t.Fatalf("scoped runtime enable action=%q, want allow", resp.Action)
		}
	})
}

func TestCodexUserPromptSubmitRuntimeDisableRemainsHardInHookObserveMode(t *testing.T) {
	api, store := newCodexPromptSkillTestAPI(t, "observe")
	if err := store.SetActionFieldForConnector("skill", "disabled-in-observe", "codex", "runtime", "disable", "test"); err != nil {
		t.Fatal(err)
	}
	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        "Use $disabled-in-observe",
	})
	if resp.Action != "block" || resp.RawAction != "block" || resp.WouldBlock {
		t.Fatalf("runtime disable became advisory in hook observe mode: action=%q raw=%q would_block=%v", resp.Action, resp.RawAction, resp.WouldBlock)
	}
}

func TestCodexPromptPolicyOnlyEvaluatesExactKnownIdentity(t *testing.T) {
	api, _ := newCodexPromptSkillTestAPI(t, "action")
	api.scannerCfg.AssetPolicy.Enabled = true
	api.scannerCfg.AssetPolicy.Mode = config.AssetPolicyModeAction
	api.scannerCfg.AssetPolicy.Skill.RuntimeDetection.Enabled = true
	api.scannerCfg.AssetPolicy.Skill.Default = "deny"
	api.scannerCfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "known-denied", Connector: "codex"}}

	unknown := api.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: "Use $unknown"})
	if unknown.Action != "allow" {
		t.Fatalf("unknown dollar word inherited default deny: action=%q reason=%q", unknown.Action, unknown.Reason)
	}
	known := api.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: "Use $known-denied"})
	if known.Action != "block" || !strings.Contains(known.Reason, "asset_name=known-denied") {
		t.Fatalf("known denied skill was not blocked: action=%q reason=%q", known.Action, known.Reason)
	}
}

func newCodexPromptSkillTestAPI(t *testing.T, mode string) (*APIServer, *audit.Store) {
	t.Helper()
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("audit store Init: %v", err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Mode = mode
	return &APIServer{scannerCfg: cfg, store: store, logger: audit.NewLogger(store)}, store
}
