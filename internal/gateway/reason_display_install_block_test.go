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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// GAP-1141: a rejected Claude plugin reaches the user's agent with a plain
// reason that names the plugin and says install admission blocked it.
func TestClaudePluginInstallAdmissionRefusalNamesPlugin(t *testing.T) {
	oldManaged, oldStandalone := managedEnterpriseActive.Load(), standaloneEnterpriseActive.Load()
	t.Cleanup(func() {
		managedEnterpriseActive.Store(oldManaged)
		standaloneEnterpriseActive.Store(oldStandalone)
	})
	source := assetPolicyResponseReason(config.AssetPolicyDecision{
		Source: "install-block", TargetType: "plugin", TargetName: "rv17-llm",
		Connector: "claudecode", RegistryStatus: "disabled", RuntimeSurface: "prompt_expansion",
	})
	display := agentDisplayReason(source, redaction.SinkPolicyDefault)
	for _, standalone := range []bool{true, false} {
		managedEnterpriseActive.Store(false)
		standaloneEnterpriseActive.Store(standalone)
		got := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault)
		if !strings.Contains(got, "plugin rv17-llm was blocked by install admission") ||
			!strings.Contains(got, agentBlockNoRetry) || strings.Contains(got, "<redacted") {
			t.Fatalf("standalone=%v: Claude plugin refusal = %q", standalone, got)
		}
	}
	managedEnterpriseActive.Store(true)
	if got := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault); got != display {
		t.Fatalf("Secure Client reason changed: got %q, want %q", got, display)
	}
	managedEnterpriseActive.Store(false)
	standaloneEnterpriseActive.Store(true)
	unsafe := strings.Replace(source, "asset_name=rv17-llm", "asset_name=rv17;llm", 1)
	unsafeDisplay := agentDisplayReason(unsafe, redaction.SinkPolicyDefault)
	if got := agentVerdictReason("block", unsafe, unsafeDisplay, redaction.SinkPolicyDefault); got != unsafeDisplay || strings.Contains(got, "rv17;llm") {
		t.Fatalf("unsafe plugin name escaped redaction: %q", got)
	}
}
