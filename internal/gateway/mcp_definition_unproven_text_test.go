// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func unprovenMCPDefinitionReason(name string) string {
	return assetPolicyResponseReason(config.AssetPolicyDecision{
		Source: "mcp-definition-unproven", TargetType: "mcp", TargetName: name,
		Connector: "claudecode", RegistryStatus: "unknown", RuntimeSurface: "hook",
	})
}

// A call to an MCP server whose definition DefenseClaw cannot prove reaches the
// agent as a sentence with the next step, in the block and in the observe
// notice, not as the redacted key=value reason (GAP-0938). The audit reason
// stays structured.
func TestUnprovenMCPDefinitionReadsAsASentenceForTheAgent(t *testing.T) {
	source := unprovenMCPDefinitionReason("wiki-rogue")
	display := agentDisplayReason(source, redaction.SinkPolicyDefault)
	block := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault)
	observed := agentObservedReason("allow", source, display, redaction.SinkPolicyDefault)
	for name, got := range map[string]string{"block": block, "observe": observed} {
		for _, want := range []string{"wiki-rogue", "definition", "new agent session", "administrator"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s text = %q, want it to contain %q", name, got, want)
			}
		}
		if strings.Contains(got, "reason_code=") || strings.Contains(got, "<redacted") {
			t.Errorf("%s text = %q, want a sentence, not the structured reason", name, got)
		}
	}
	if !strings.Contains(source, "reason_code=mcp-definition-unproven") {
		t.Fatalf("the audit reason = %q, want it to stay structured", source)
	}
}

// Benign twins: a plugin with that reason code, or a name the agent may not be
// shown, keeps the redacted form.
func TestUnprovenMCPDefinitionWordingNeedsAnMCPServerWithAPlainName(t *testing.T) {
	for name, source := range map[string]string{
		"plugin type": strings.Replace(unprovenMCPDefinitionReason("wiki"), "asset_type=mcp", "asset_type=plugin", 1),
		"odd name":    unprovenMCPDefinitionReason("wiki rogue"),
	} {
		display := agentDisplayReason(source, redaction.SinkPolicyDefault)
		got := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault)
		if strings.Contains(got, "new agent session") {
			t.Errorf("%s: %q, want the unworded form", name, got)
		}
	}
}
