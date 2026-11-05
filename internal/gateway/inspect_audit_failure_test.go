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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// inspectTool posts one tool check to /api/v1/inspect/tool and returns the
// verdict it answered.
func (fixture auditFailureHookFixture) inspectTool(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	fixture.api.handleInspectTool(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(raw)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func benignInspectCall() map[string]any {
	return map[string]any{"tool": "exec", "args": map[string]any{"command": "echo ok"}}
}

// GAP-0593: the inspect route (the OpenClaw plugin's tool and prompt checks)
// follows the hook routes' failed-audit tier rule. Strict, managed and
// sandbox calls fail closed; a default or permissive allow stays allowed
// with the degraded-audit warning. It used to discard the audit error.
func TestInspectToolAuditWriteFailureFollowsPolicyTier(t *testing.T) {
	t.Run("healthy store allows", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		if out := fixture.inspectTool(t, benignInspectCall()); out["action"] != "allow" {
			t.Fatalf("healthy store: verdict %v, want allow", out)
		}
	})
	t.Run("default tier allows with the degraded warning", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.emitter.fail = true
		out := fixture.inspectTool(t, benignInspectCall())
		if out["action"] != "allow" || out["raw_action"] != "alert" || out["severity"] != "WARN" {
			t.Fatalf("default tier: verdict %v, want an allowed degraded-audit alert", out)
		}
		if blocks := fixture.api.health.statsFor("claudecode").toolBlocks.Load(); blocks != 0 {
			t.Fatalf("tool blocks = %d after an allowed audit failure, want 0", blocks)
		}
	})
	t.Run("permissive tier allows with the degraded warning", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.api.scannerCfg.Guardrail.RulePack = "permissive"
		fixture.emitter.fail = true
		if out := fixture.inspectTool(t, benignInspectCall()); out["action"] != "allow" || out["raw_action"] != "alert" {
			t.Fatalf("permissive tier: verdict %v, want an allowed alert", out)
		}
	})
	t.Run("strict tier blocks in action mode", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.api.scannerCfg.Guardrail.RulePack = "strict"
		fixture.emitter.fail = true
		out := fixture.inspectTool(t, benignInspectCall())
		if out["action"] != "block" || out["mode"] != "action" || out["raw_action"] != "block" {
			t.Fatalf("strict tier: verdict %v, want an action-mode audit block", out)
		}
	})
	t.Run("strict tier blocks in observe mode too", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.api.scannerCfg.Guardrail.RulePack = "strict"
		fixture.api.scannerCfg.Guardrail.Mode = "observe"
		fixture.emitter.fail = true
		if out := fixture.inspectTool(t, benignInspectCall()); out["action"] != "block" || out["mode"] != "action" {
			t.Fatalf("strict observe: verdict %v, want an action-mode block", out)
		}
	})
	t.Run("managed outage-open still blocks an unaudited call", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "open")
		fixture.api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		fixture.api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
		fixture.emitter.fail = true
		if out := fixture.inspectTool(t, benignInspectCall()); out["action"] != "block" {
			t.Fatalf("managed: verdict %v, want block", out)
		}
	})
	t.Run("strict tier keeps a tool result it cannot refuse", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.api.scannerCfg.Guardrail.RulePack = "strict"
		fixture.emitter.fail = true
		call := benignInspectCall()
		call["direction"] = "tool_result"
		if out := fixture.inspectTool(t, call); out["action"] == "block" {
			t.Fatalf("strict tool result: verdict %v, want the policy verdict kept", out)
		}
	})
	t.Run("Secure Client keeps its verdict", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "open")
		fixture.api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		fixture.api.scannerCfg.Enterprise.Profile = managed.ProfileSecureClient
		fixture.emitter.fail = true
		if out := fixture.inspectTool(t, benignInspectCall()); out["action"] != "allow" {
			t.Fatalf("Secure Client: verdict %v, want allow", out)
		}
	})
}

// The response redacts reasons; the verdict carries the plain sentences.
func TestInspectAuditFailureVerdictReasons(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	allow := &ToolInspectVerdict{Action: "allow", RawAction: "allow", Severity: "NONE"}
	if fixture.api.inspectAuditFailureVerdict(t.Context(), "claudecode", &ToolInspectRequest{Tool: "exec"}, allow) {
		t.Fatal("default tier allow was blocked")
	}
	if !strings.Contains(allow.Reason, "audit is degraded") {
		t.Fatalf("default tier reason = %q", allow.Reason)
	}
	fixture.api.scannerCfg.Guardrail.RulePack = "strict"
	strict := &ToolInspectVerdict{Action: "allow", RawAction: "allow", Severity: "NONE"}
	if !fixture.api.inspectAuditFailureVerdict(t.Context(), "claudecode", &ToolInspectRequest{Tool: "exec"}, strict) {
		t.Fatal("strict tier allow was not blocked")
	}
	if !strings.Contains(strict.Reason, "could not write the audit record") {
		t.Fatalf("strict tier reason = %q", strict.Reason)
	}
}

// A default-tier alert lets the call run with its finding, as the hook
// routes' allow with raw action alert does; strict closes it.
func TestInspectAuditFailureVerdictKeepsADefaultTierAlert(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	alert := &ToolInspectVerdict{Action: "alert", RawAction: "alert", Severity: "MEDIUM", Reason: "matched: rule"}
	if fixture.api.inspectAuditFailureVerdict(t.Context(), "claudecode", &ToolInspectRequest{Tool: "exec"}, alert) {
		t.Fatal("default tier alert was blocked")
	}
	if alert.Action != "alert" || alert.Severity != "MEDIUM" || alert.Reason != "matched: rule" {
		t.Fatalf("default tier alert changed: %+v", alert)
	}
	fixture.api.scannerCfg.Guardrail.RulePack = "strict"
	strict := &ToolInspectVerdict{Action: "alert", RawAction: "alert", Severity: "MEDIUM"}
	if !fixture.api.inspectAuditFailureVerdict(t.Context(), "claudecode", &ToolInspectRequest{Tool: "exec"}, strict) {
		t.Fatal("strict tier alert was not blocked")
	}
}

// A failed audit write never weakens a block.
func TestInspectAuditFailureVerdictKeepsABlock(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	verdict := &ToolInspectVerdict{Action: "block", RawAction: "block", Severity: "CRITICAL", Reason: "matched: rule"}
	if denied := fixture.api.inspectAuditFailureVerdict(t.Context(), "claudecode", &ToolInspectRequest{Tool: "exec"}, verdict); denied {
		t.Fatal("an existing block was reported as a new audit block")
	}
	if verdict.Action != "block" || verdict.Severity != "CRITICAL" || verdict.Reason != "matched: rule" {
		t.Fatalf("block changed: %+v", verdict)
	}
}
