// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func requireSourceDetectionOnlyVerdict(t *testing.T, verdict *ToolInspectVerdict) {
	t.Helper()
	if verdict == nil || verdict.Action != "allow" || verdict.Severity != "LOW" ||
		verdict.WouldBlock || len(verdict.DetailedFindings) == 0 {
		t.Fatalf("source verdict = %+v, want LOW detection-only allow", verdict)
	}
	for _, finding := range verdict.DetailedFindings {
		if finding.Severity != "LOW" || finding.contributesToEnforcement() {
			t.Fatalf("source finding = %+v, want LOW detection-only", finding)
		}
	}
}

func TestInspectMessageContent_SourceScopeNeverEnforces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = "/profiles/strict"
	api := &APIServer{scannerCfg: cfg}

	source := api.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: trustExploitKeyword(), Direction: "tool_result",
		Connector: "codex", contentScope: ruleContentScopeSource,
	})
	requireSourceDetectionOnlyVerdict(t, source)

	untrusted := api.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: trustExploitKeyword(), Direction: "tool_result",
		Connector: "codex", contentScope: ruleContentScopeUntrusted,
	})
	if untrusted == nil || untrusted.Action == "allow" ||
		guardrailSeverityRank(untrusted.Severity) < severityHigh {
		t.Fatalf("untrusted verdict = %+v, want existing enforcement", untrusted)
	}
}

func TestInspectMessageContent_SourceScopeClampsAID(t *testing.T) {
	api := &APIServer{
		scannerCfg:     &config.Config{},
		ciscoInspector: &stubAIDInspector{verdict: blockVerdict()},
	}
	verdict := api.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "ordinary detector fixture text", Direction: "tool_result",
		Connector: "codex", contentScope: ruleContentScopeSource,
	})
	requireSourceDetectionOnlyVerdict(t, verdict)
}

func TestInspectMessageContent_SourceScopeClampsJudge(t *testing.T) {
	api := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", injectionHitProvider())
	verdict := api.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "ordinary detector fixture text", Direction: "prompt",
		Connector: "hermes", contentScope: ruleContentScopeSource,
	})
	requireSourceDetectionOnlyVerdict(t, verdict)
}

func TestInspectMessageContent_SourceScopeClampsManagedAID(t *testing.T) {
	api := managedHookServer(&stubAIDInspector{verdict: blockVerdict()})
	verdict := api.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "ordinary detector fixture text", Direction: "tool_result",
		Connector: "codex", contentScope: ruleContentScopeSource,
	})
	requireSourceDetectionOnlyVerdict(t, verdict)
}
