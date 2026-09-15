// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestSQLValueLineageGatewayLifecycleFoundationIsInertAndSuccessBound(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	profile := api.hookProfileForConnector("claudecode")

	pre := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "sql-lineage-success",
		"tool_use_id": "sql-lineage-call", "tool_name": "mcp__sqlite__read_query",
		"mcp_server_name": "sqlite",
		"tool_input": map[string]interface{}{
			"query": "SELECT password FROM credentials LIMIT 1",
		},
	}
	preReq, preResp := runSQLLifecycleGatewayStage(t, api, profile, pre)
	if preResp.Action == guardrailActionBlock || preReq.toolChain == nil ||
		pendingSQLValueSource(preReq.toolChain).DatabaseIdentityDigest == "" {
		t.Fatalf("pre response=%+v capture=%+v", preResp, preReq.toolChain)
	}
	assertNoSQLLineageRule(t, preResp)

	const secret = "synthetic-lifecycle-password-123"
	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = `[{"password":"` + secret + `"}]`
	resultReq, resultResp := runSQLLifecycleGatewayStage(t, api, profile, result)
	if resultReq.toolChain == nil || resultReq.toolChain.successfulSQLResult == nil ||
		len(resultReq.toolChain.successfulSQLResult.valueDigests) != 1 {
		t.Fatalf("authoritative result capture=%+v response=%+v", resultReq.toolChain, resultResp)
	}
	assertNoSQLLineageRule(t, resultResp)
	encoded, err := json.Marshal(resultResp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("result value entered hook response: %s", encoded)
	}

	replayReq, replayResp := runSQLLifecycleGatewayStage(t, api, profile, result)
	if replayReq.toolChain != nil && replayReq.toolChain.successfulSQLResult != nil {
		t.Fatal("terminal replay projected SQL values")
	}
	assertNoSQLLineageRule(t, replayResp)

	for name, terminal := range map[string]map[string]interface{}{
		"missing pending": {
			"hook_event_name": "PostToolUse", "session_id": "sql-lineage-missing",
			"tool_use_id": "missing-call", "tool_name": "mcp__sqlite__read_query",
			"mcp_server_name": "sqlite",
			"tool_input":      map[string]interface{}{"query": "SELECT password FROM credentials LIMIT 1"},
			"tool_response":   `[{"password":"` + secret + `"}]`,
		},
		"failed result": {
			"hook_event_name": "PostToolUseFailure", "session_id": "sql-lineage-failure",
			"tool_use_id": "failure-call", "tool_name": "mcp__sqlite__read_query",
			"mcp_server_name": "sqlite",
			"tool_input":      map[string]interface{}{"query": "SELECT password FROM credentials LIMIT 1"},
			"tool_response":   `[{"password":"` + secret + `"}]`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "failed result" {
				failedPre := cloneStringAnyMap(terminal)
				failedPre["hook_event_name"] = "PreToolUse"
				delete(failedPre, "tool_response")
				runSQLLifecycleGatewayStage(t, api, profile, failedPre)
			}
			req, resp := runSQLLifecycleGatewayStage(t, api, profile, terminal)
			if req.toolChain != nil && req.toolChain.successfulSQLResult != nil {
				t.Fatal("non-authoritative lifecycle projected SQL values")
			}
			assertNoSQLLineageRule(t, resp)
		})
	}

	mismatchPre := cloneStringAnyMap(pre)
	mismatchPre["session_id"] = "sql-lineage-mismatch"
	mismatchPre["tool_use_id"] = "mismatch-call"
	runSQLLifecycleGatewayStage(t, api, profile, mismatchPre)
	mismatchResult := cloneStringAnyMap(mismatchPre)
	mismatchResult["hook_event_name"] = "PostToolUse"
	mismatchResult["tool_input"] = map[string]interface{}{
		"query": "SELECT access_token FROM oauth_tokens LIMIT 1",
	}
	mismatchResult["tool_response"] = `[{"access_token":"` + secret + `"}]`
	mismatchReq, mismatchResp := runSQLLifecycleGatewayStage(
		t, api, profile, mismatchResult,
	)
	if mismatchReq.toolChain != nil && mismatchReq.toolChain.successfulSQLResult != nil {
		t.Fatal("terminal action mismatch projected SQL values")
	}
	assertNoSQLLineageRule(t, mismatchResp)
}

func TestCodexSQLValueLineageGatewayLifecycleBindsMCPResult(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "codex")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	profile := api.hookProfileForConnector("codex")

	pre := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "codex-sql-lineage",
		"tool_use_id": "codex-sql-call", "tool_name": "mcp__sqlite__read_query",
		"mcp_server_name": "sqlite",
		"tool_input": map[string]interface{}{
			"query": "SELECT access_token FROM oauth_tokens LIMIT 1",
		},
	}
	preReq, preResp := runSQLLifecycleGatewayStageForConnector(
		t, api, profile, "codex", pre,
	)
	if preReq.toolChain == nil ||
		pendingSQLValueSource(preReq.toolChain).TableClass != actionfacts.SensitiveSQLTableOAuthTokens {
		t.Fatalf("Codex pre capture=%+v", preReq.toolChain)
	}
	assertNoSQLLineageRule(t, preResp)

	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = map[string]interface{}{
		"content": []interface{}{map[string]interface{}{
			"type": "text",
			"text": `[{"access_token":"synthetic-codex-token-123"}]`,
		}},
	}
	resultReq, resultResp := runSQLLifecycleGatewayStageForConnector(
		t, api, profile, "codex", result,
	)
	if resultReq.toolChain == nil || resultReq.toolChain.successfulSQLResult == nil ||
		len(resultReq.toolChain.successfulSQLResult.valueDigests) != 1 {
		t.Fatalf("Codex result capture=%+v response=%+v", resultReq.toolChain, resultResp)
	}
	assertNoSQLLineageRule(t, resultResp)
}

func TestBoundSuccessfulSQLResultProjectsOnlyAfterExactRebind(t *testing.T) {
	const secret = "synthetic-password-value-123"
	pre, ctx := syntheticSQLLifecycleRequest(
		t, "codex", "PreToolUse", "mcp__sqlite__read_query",
		map[string]interface{}{"query": "SELECT password FROM credentials LIMIT 1"},
		nil,
	)
	actionTool, identity := trustedToolActionFromContext(
		ctx, "codex", pre.ToolName, pre.ToolName,
	)
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: actionTool, Args: pre.ToolArgs,
		ToolResourceIdentity: identity,
	})
	capture := &toolChainHookCapture{facts: facts, recorded: true}
	source := pendingSQLValueSource(capture)
	if source.TableClass != actionfacts.SensitiveSQLTableCredentials ||
		source.DatabaseIdentityDigest == "" {
		t.Fatalf("pending source=%+v", source)
	}

	result, resultCtx := syntheticSQLLifecycleRequest(
		t, "codex", "PostToolUse", "mcp__sqlite__read_query",
		map[string]interface{}{"query": "SELECT password FROM credentials LIMIT 1"},
		map[string]interface{}{
			"content": []interface{}{map[string]interface{}{
				"type": "text", "text": `[{"password":"` + secret + `"}]`,
			}},
		},
	)
	projection, ok := projectBoundSuccessfulSQLResult(resultCtx, result, source)
	if !ok || projection.databaseIdentityDigest != source.DatabaseIdentityDigest ||
		len(projection.valueDigests) != 1 {
		t.Fatalf("projection=%+v ok=%t", projection, ok)
	}
	if strings.Contains(hex.EncodeToString(projection.valueDigests[0][:]), secret) {
		t.Fatal("digest projection retained raw value")
	}
	encoded, err := json.Marshal(struct {
		Capture    *toolChainHookCapture
		Projection toolValueLineageSQLSuccessfulProjection
	}{Capture: capture, Projection: projection})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) ||
		strings.Contains(string(encoded), source.DatabaseIdentityDigest) ||
		strings.Contains(string(encoded), hex.EncodeToString(projection.valueDigests[0][:])) {
		t.Fatalf("private lifecycle state serialized: %s", encoded)
	}

	mismatched := result
	mismatched.Payload = cloneStringAnyMap(result.Payload)
	mismatched.Payload["tool_input"] = map[string]interface{}{
		"query": "SELECT access_token FROM oauth_tokens LIMIT 1",
	}
	if _, ok := projectBoundSuccessfulSQLResult(resultCtx, mismatched, source); ok {
		t.Fatal("terminal SQL mismatch was accepted")
	}
	otherCtx := withAuthenticatedHookConnector(context.Background(), "codex")
	other := result
	other.ConnectorInstanceID = "0198f0c2-7b31-7a42-8c51-abcdef012345"
	rawOther, err := json.Marshal(other.Payload)
	if err != nil {
		t.Fatal(err)
	}
	otherCtx = withAuthenticatedToolResource(otherCtx, other, rawOther)
	if _, ok := projectBoundSuccessfulSQLResult(otherCtx, other, source); ok {
		t.Fatal("terminal resource mismatch was accepted")
	}
}

func TestExactSuccessfulSQLResultBytesClosedEnvelopes(t *testing.T) {
	validCodex := agentHookRequest{
		ConnectorName: "codex", HookEventName: "PostToolUse",
		ToolName: "mcp__sqlite__read_query",
		Payload: map[string]interface{}{"tool_response": map[string]interface{}{
			"content": []interface{}{map[string]interface{}{"type": "text", "text": "[]"}},
		}},
	}
	if got, ok := exactSuccessfulSQLResultBytes(validCodex); !ok || string(got) != "[]" {
		t.Fatalf("valid Codex result=%q ok=%t", got, ok)
	}
	validCodex.Payload["tool_response"].(map[string]interface{})["isError"] = false
	if _, ok := exactSuccessfulSQLResultBytes(validCodex); !ok {
		t.Fatal("explicit false isError was rejected")
	}

	mutations := []func(map[string]interface{}){
		func(response map[string]interface{}) { response["isError"] = true },
		func(response map[string]interface{}) { response["isError"] = "false" },
		func(response map[string]interface{}) { response["structuredContent"] = map[string]interface{}{} },
		func(response map[string]interface{}) { response["content"] = []interface{}{} },
		func(response map[string]interface{}) {
			response["content"] = []interface{}{map[string]interface{}{"type": "text", "text": "[]"}, map[string]interface{}{"type": "text", "text": "[]"}}
		},
		func(response map[string]interface{}) {
			response["content"] = []interface{}{map[string]interface{}{"type": "image", "text": "[]"}}
		},
		func(response map[string]interface{}) {
			response["content"] = []interface{}{map[string]interface{}{"type": "text", "text": "[]", "extra": true}}
		},
	}
	for index, mutate := range mutations {
		request := validCodex
		response := map[string]interface{}{
			"content": []interface{}{map[string]interface{}{"type": "text", "text": "[]"}},
		}
		mutate(response)
		request.Payload = map[string]interface{}{"tool_response": response}
		if _, ok := exactSuccessfulSQLResultBytes(request); ok {
			t.Fatalf("ambiguous Codex result mutation %d accepted", index)
		}
	}

	claude := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PostToolUse",
		ToolName: "mcp__sqlite__read_query",
		Payload:  map[string]interface{}{"tool_response": "[]"},
	}
	if got, ok := exactSuccessfulSQLResultBytes(claude); !ok || string(got) != "[]" {
		t.Fatalf("valid Claude result=%q ok=%t", got, ok)
	}
	for key, value := range map[string]interface{}{
		"tool_calls": []interface{}{}, "error": "failure", "error_details": "failure",
	} {
		request := claude
		request.Payload = cloneStringAnyMap(claude.Payload)
		request.Payload[key] = value
		if _, ok := exactSuccessfulSQLResultBytes(request); ok {
			t.Fatalf("Claude result with %s accepted", key)
		}
	}
	claude.Payload = map[string]interface{}{"tool_response": map[string]interface{}{"content": "[]"}}
	if _, ok := exactSuccessfulSQLResultBytes(claude); ok {
		t.Fatal("structured Claude result was accepted")
	}
}

func syntheticSQLLifecycleRequest(
	t *testing.T,
	connectorName string,
	event string,
	tool string,
	input map[string]interface{},
	response interface{},
) (agentHookRequest, context.Context) {
	t.Helper()
	rawArgs, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]interface{}{
		"mcp_server_name": "sqlite",
		"tool_input":      input,
	}
	if response != nil {
		payload["tool_response"] = response
	}
	req := agentHookRequest{
		ConnectorName:       connectorName,
		ConnectorInstanceID: syntheticToolResourceConnectorID,
		HookEventName:       event,
		ToolName:            tool,
		ToolArgs:            rawArgs,
		Payload:             payload,
	}
	ctx := withAuthenticatedHookConnector(context.Background(), connectorName)
	rawBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	ctx = withAuthenticatedToolResource(ctx, req, rawBody)
	return req, ctx
}

func cloneStringAnyMap(source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func runSQLLifecycleGatewayStage(
	t *testing.T,
	api *APIServer,
	profile connector.HookProfile,
	payload map[string]interface{},
) (agentHookRequest, agentHookResponse) {
	return runSQLLifecycleGatewayStageForConnector(
		t, api, profile, "claudecode", payload,
	)
}

func runSQLLifecycleGatewayStageForConnector(
	t *testing.T,
	api *APIServer,
	profile connector.HookProfile,
	connectorName string,
	payload map[string]interface{},
) (agentHookRequest, agentHookResponse) {
	t.Helper()
	rawBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := normalizeAgentHookRequestWithRawProfileEvent(
		connectorName, payload, rawBody, profile, "",
	)
	ctx := withAuthenticatedHookConnector(context.Background(), connectorName)
	ctx, req, err = api.correlateHookOccurrence(ctx, profile, req, rawBody)
	if err != nil {
		t.Fatal(err)
	}
	ctx = withAuthenticatedToolResource(ctx, req, rawBody)
	req.toolChain = &toolChainHookCapture{}
	ctx = withToolChainHookCapture(ctx, req.toolChain)
	runtime := hookRuntimeForProfile(profile)
	resp := runtime.Evaluate(api, ctx, req, rawBody, payload)
	resp, _ = api.applyAgentHookToolChains(
		ctx, profile, req, rawBody, resp, time.Millisecond, nil,
	)
	return req, resp
}

func assertNoSQLLineageRule(t *testing.T, response agentHookResponse) {
	t.Helper()
	for _, ruleID := range response.RuleIDs {
		if strings.Contains(ruleID, "sql_value") ||
			strings.Contains(ruleID, "sql-value") {
			t.Fatalf("inert foundation emitted SQL value-lineage rule %q", ruleID)
		}
	}
}
