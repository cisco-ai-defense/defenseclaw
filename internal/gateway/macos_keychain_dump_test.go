// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const macOSLoginKeychainDumpRuleID = "credential.macos_login_keychain_dump"

func TestMacOSLoginKeychainDumpProfilePosture(t *testing.T) {
	for _, profile := range []struct {
		name, action, severity string
	}{
		{name: "default", action: "alert", severity: "HIGH"},
		{name: "permissive", action: "alert", severity: "HIGH"},
		{name: "strict", action: "alert", severity: "LOW"},
	} {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			command := `sudo security dump-keychain -d login.keychain`
			input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX}
			facts := actionfacts.Analyze(input)
			if !actionfacts.ExactMacOSLoginKeychainDump(facts) {
				t.Fatalf("exact ActionFacts proof did not match: %+v", facts)
			}
			proof, owned := trustedSemanticOwnerFindingProof(macOSLoginKeychainDumpRuleID, input, facts)
			if !owned || !proof.authorizes(macOSLoginKeychainDumpRuleID) {
				t.Fatalf("exact owner did not authorize proof=%+v facts=%+v", proof, facts)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: "/repo",
				ToolInput: map[string]interface{}{"command": command},
			})
			if response.Action != profile.action || response.Severity != profile.severity ||
				!findingStringHasRuleID(response.Findings, macOSLoginKeychainDumpRuleID) {
				t.Fatalf("response=%+v want %s/%s with %s", response, profile.action, profile.severity, macOSLoginKeychainDumpRuleID)
			}
		})
	}
}

func TestMacOSLoginKeychainDumpOwnerRejectsNearMisses(t *testing.T) {
	for _, command := range []string{
		`security dump-keychain login.keychain`,
		`security dump-keychain -d build.keychain`,
		`security find-certificate -a -p`,
		`security dump-keychain -d "$KEYCHAIN"`,
		`security dump-keychain -d login.keychain | grep acct`,
		`echo 'security dump-keychain -d login.keychain'`,
	} {
		input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX}
		facts := actionfacts.Analyze(input)
		proof, _ := trustedSemanticOwnerFindingProof(macOSLoginKeychainDumpRuleID, input, facts)
		if proof.authorizes(macOSLoginKeychainDumpRuleID) {
			t.Fatalf("negative escaped exact owner: command=%q proof=%+v facts=%+v", command, proof, facts)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: "codex", EnforcementCapable: true,
		})
		if findingStringHasRuleID(FindingStrings(findings), macOSLoginKeychainDumpRuleID) {
			t.Fatalf("negative produced owner finding: command=%q findings=%v", command, FindingStrings(findings))
		}
	}
}
