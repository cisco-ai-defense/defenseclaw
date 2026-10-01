// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestHomeRelativeRulesMatchWhenTheCallersHomeIsUnresolved: a standalone
// gateway resolves "~" against the verified caller's home. When that home
// cannot be resolved (a failed directory lookup, a home of "/", a request
// with no per-user credential) the home-relative credential rules must still
// match, as they did when "~" resolved against the gateway's own home.
func TestHomeRelativeRulesMatchWhenTheCallersHomeIsUnresolved(t *testing.T) {
	const connectorName = "codex"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg}

	restoreHome := userScopedIdentityHome
	userScopedIdentityHome = func(string) string { return "" }
	t.Cleanup(func() { userScopedIdentityHome = restoreHome })
	standalone := withServiceAccountGateway(context.Background())
	contexts := map[string]context.Context{
		"hook-socket caller without a home": withManagedHookPeer(standalone, managedHookPeer{UID: 1002}),
		// Control: a resolved caller home.
		"hook-socket caller with a home": withManagedHookPeer(standalone, managedHookPeer{UID: 1001, Home: "/home/alice"}),
	}
	commands := map[string]string{
		"cat ~/.aws/credentials": "PATH-AWS-CREDS",
		"cat ~/.kube/config":     "PATH-KUBE",
	}
	for name, ctx := range contexts {
		for command, rule := range commands {
			response := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "Bash", CWD: "/repo",
				ToolInput: map[string]interface{}{"command": command},
			})
			if !findingStringHasRuleID(response.Findings, rule) {
				t.Errorf("%s: %q findings=%v, want %s", name, command, response.Findings, rule)
			}
		}
	}
}
