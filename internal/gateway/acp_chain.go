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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// ACP steps in multi-step tool chains (GAP-0305).
//
// An ACP action is judged as the hook path judges the tool call
// (inspectACPFrameAction), and it is also a step of its session's tool
// chains, in the same chain repository the hook path writes. The chain key is
// the one a hook step has: the connector instance and the session. An ACP
// step is correlated as a hook event of the agent's connector, with the ACP
// session id as the session and the frame's tool_call id (session/update,
// session/request_permission) as the tool invocation; a frame with no
// tool_call id (terminal/create, fs/*) gets the gateway-minted event id, as
// a hook event without one does. So the ACP steps of a session form a chain
// with each other, and with the hook steps of the same connector when the
// hook reports the same session id. The repository's bounds (partitions,
// events per window, horizon) are the hook chain's own.
//
// ACP carries no result the gateway can join to a call (the editor's answer
// to the agent is not a tool outcome report), so a step is what a hook
// connector with no result correlation records: its terminal steps are
// judged against the earlier steps, and a credentials read starts the
// secret-read chain at its proposal unless the gateway refused it
// (GAP-0338). No deny receipt is written: the verdict is the frame's, mapped
// by the ACP profile's mode as every other finding of the frame.

// acpChainStep observes one judged ACP tool call (index in its frame) as a
// step of its session's tool chains and returns the chain verdict, or nil
// when the call completes no chain (or there is no chain state: no store, no
// ACP session, a managed host whose local chain lane is off as on the hook
// path).
func (a *APIServer) acpChainStep(
	ctx context.Context,
	req acp.Evaluation,
	connectorName string,
	profile connector.HookProfile,
	index int,
	call acpToolCall,
	cwd string,
	capture *toolChainHookCapture,
	judged *ToolInspectVerdict,
	enforceable bool,
) *ToolInspectVerdict {
	if a == nil || a.store == nil || capture == nil || !capture.recorded || ManagedEnterpriseActive() {
		return nil
	}
	session := acpFrameSessionID(req, false)
	if session == "" {
		return nil
	}
	hookReq := acpChainHookRequest(connectorName, profile, req, session)
	hookReq.ToolName, hookReq.ToolArgs, hookReq.Direction = call.tool, call.args, "tool_call"
	hookReq.CWD, hookReq.ReportedCWD = hookCWDForContext(ctx, cwd), cwd
	hookReq.toolChain = capture

	projection, _ := projectAgentHookToolChains(hookReq, profile.ToolCallLifecycle)
	decision := a.decisionConfig(ctx)
	projection = toolChainProjectionForPolicyPosture(decision, connectorName, projection)
	if a.expectedRemoteDownload(ctx, decision, hookReq) {
		clearToolChainStep(&projection, guardrail.ToolChainDownloadThenExecuteSameArtifact, 1)
	}
	predecessor, observation := splitToolChainProjection(projection)
	if !enforceable || judged == nil || normalizeCodexAction(judged.Action) != guardrailActionBlock {
		// A refused request never runs; a report is of a tool the agent ran.
		observation = withSecretReadStart(observation, predecessor)
	}
	if !toolChainProjectionHasSteps(observation) {
		// Nothing a chain reads: no ledger row, the 1.0.10 path.
		return nil
	}
	body := acpChainStepBody(req.Payload, index)
	_, hookReq, err := a.correlateHookOccurrence(ctx, profile, hookReq, body)
	if err != nil || hookReq.SemanticEventID == "" || hookReq.ConnectorInstanceID == "" {
		return nil
	}
	repository, _, ok := a.toolChainStores(ctx, hookReq)
	if !ok || repository == nil {
		return nil
	}
	ruleset, err := toolChainRulesetFingerprint(ctx, connectorName, profile)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(body)
	result, err := repository.Observe(ctx, audit.ToolChainObserveInput{
		SemanticEventID:     audit.SemanticEventID(hookReq.SemanticEventID),
		ConnectorInstanceID: audit.ConnectorInstanceID(hookReq.ConnectorInstanceID),
		InputFingerprint:    hex.EncodeToString(digest[:]),
		RulesetFingerprint:  ruleset,
		Projection:          observation,
	})
	if err != nil || len(result.DetectedChainIDs) == 0 ||
		(result.Status != audit.ToolChainObserveFresh && result.Status != audit.ToolChainObserveReplay) {
		return nil
	}
	findings := toolChainRuleFindings(result)
	if len(findings) == 0 {
		return nil
	}
	severity := HighestSeverity(findings)
	action := toolChainHookIntent(guardrailActionForConnector(decision, connectorName, severity, true), false, result)
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	reason := "matched ordered safety rule: " + strings.Join(ids, ", ")
	for _, id := range ids {
		if id == guardrail.ToolChainSecretReadThenEgress {
			reason += ". The " + unclearedReadWhy(connectorName) + "."
			break
		}
	}
	return &ToolInspectVerdict{
		Action: action, Severity: severity, Confidence: 0.98, Reason: reason,
		Findings: FindingStrings(findings), DetailedFindings: findings,
	}
}

// acpChainHookRequest is the hook request an ACP step of session is
// correlated as: the agent's connector, the frame's method as its event, and
// the session and tool_call id in the fields the connector's own correlation
// profile reads them from (the profile the hook path uses), so a hook event
// of the same session joins the same chain partition.
func acpChainHookRequest(connectorName string, profile connector.HookProfile, req acp.Evaluation, session string) agentHookRequest {
	spec := profile.Correlation
	if spec.Connector == "" || len(spec.HookBindings) == 0 {
		spec = connector.ExplicitCanonicalCorrelationSpec(connectorName)
	}
	payload := map[string]interface{}{}
	if path := acpCorrelationPath(spec, connector.CorrelationTargetSession); path != "" {
		payload[path] = session
	}
	if id := acpFrameToolCallID(req); id != "" {
		if path := acpCorrelationPath(spec, connector.CorrelationTargetTool); path != "" {
			payload[path] = id
		}
	}
	hookReq := normalizeAgentHookRequestWithCorrelationEvent(connectorName, payload, spec, req.Method, "")
	hookReq.SessionID = session
	return hookReq
}

// acpCorrelationPath is the field a correlation profile reads target from:
// the first path of its last binding of target (connector bindings follow
// the canonical fallbacks and win, correlationValueFromBindings).
func acpCorrelationPath(spec connector.CorrelationSpec, target connector.CorrelationTarget) string {
	path := ""
	for _, binding := range spec.HookBindings {
		if binding.Target == target && len(binding.Paths) != 0 {
			path = binding.Paths[0]
		}
	}
	return path
}

// acpFrameToolCallID is the tool_call id the frame names (session/update,
// session/request_permission), or "".
func acpFrameToolCallID(req acp.Evaluation) string {
	if req.Aggregate {
		return ""
	}
	msg, err := acp.ParseMessageAllowingNullIDErrors(req.Payload)
	if err != nil || len(msg.Params) == 0 {
		return ""
	}
	var params struct {
		Update struct {
			ToolCallID string `json:"toolCallId"`
		} `json:"update"`
		ToolCall struct {
			ToolCallID string `json:"toolCallId"`
		} `json:"toolCall"`
	}
	if json.Unmarshal(msg.Params, &params) != nil {
		return ""
	}
	id := strings.TrimSpace(params.ToolCall.ToolCallID)
	if id == "" {
		id = strings.TrimSpace(params.Update.ToolCallID)
	}
	if !hookModelV8Identifier(id) {
		return ""
	}
	return id
}

// acpChainStepBody is the input an ACP step's correlation event and chain
// observation are fingerprinted over: the frame and the call's place in it,
// so a frame sent again is a replay of the same steps.
func acpChainStepBody(frame json.RawMessage, index int) []byte {
	return append(append([]byte("acp-chain-step\x00"+strconv.Itoa(index)+"\x00"), frame...), 0)
}
