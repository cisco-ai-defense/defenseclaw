// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-2295: a blocked OpenClaw prompt matched by a local rule-pack rule
// (R7-PROMPT-MARKER) wrote scan-finding rows named UNKNOWN-R7-PROMPT-MARKER
// with no connector, so alerts --connector openclaw hid them.
func TestScanFindingsKeepLoadedRulePackIDAndConnector(t *testing.T) {
	resetConnectorRuleCategories(t)
	if err := ApplyRulePackOverrides(&guardrail.RulePack{
		RuleFiles: []*guardrail.RulesFileYAML{{
			Version:  1,
			Category: "secret",
			Rules: []guardrail.RuleDefYAML{{
				ID: "R7-PROMPT-MARKER", Title: "Test marker prompt",
				Pattern: `dccert-prompt-marker`, Severity: "CRITICAL", Confidence: 0.99,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	for _, source := range []string{"guardrail-llm", "local-pattern"} {
		nfs := NormalizeScanVerdict(&ScanVerdict{
			Scanner: source, Severity: "CRITICAL",
			Findings: []string{"R7-PROMPT-MARKER:Test marker prompt"},
		})
		if len(nfs) != 1 || nfs[0].CanonicalID != "R7-PROMPT-MARKER" {
			t.Errorf("%s: normalized = %+v, want R7-PROMPT-MARKER", source, nfs)
		}
	}
	if got := canonicalIDFromRuleID("R9-NOT-LOADED"); got != "UNKNOWN-R9-NOT-LOADED" {
		t.Errorf("unloaded rule id = %q, want UNKNOWN-R9-NOT-LOADED", got)
	}

	store, logger := testStoreAndLogger(t)
	router := NewEventRouter(nil, store, logger, false)
	router.SetDefaultAgentName("openclaw")
	if got := router.streamScanCorrelation("agent:main:s1").Connector; got != "openclaw" {
		t.Errorf("stream scan connector = %q, want openclaw", got)
	}

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.connector = connector.NewOpenClawConnector()
	eval := proxy.emitGuardrailScanVerdictFindings(t.Context(), "guardrail-llm", "prompt:m", "prompt",
		&ScanVerdict{Action: "block", Severity: "CRITICAL", Findings: []string{"R7-PROMPT-MARKER:Test marker prompt"}},
		0, "test")
	if len(eval.RuleIDs) != 1 || eval.RuleIDs[0] != "R7-PROMPT-MARKER" {
		t.Errorf("proxy rule ids = %v, want [R7-PROMPT-MARKER]", eval.RuleIDs)
	}
	events, err := proxy.store.ListAlerts(20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "scan-finding" {
			found = true
			if e.Connector != "openclaw" {
				t.Errorf("proxy scan-finding connector = %q, want openclaw", e.Connector)
			}
		}
	}
	if !found {
		t.Fatalf("no scan-finding alert row; events=%+v", events)
	}
}
