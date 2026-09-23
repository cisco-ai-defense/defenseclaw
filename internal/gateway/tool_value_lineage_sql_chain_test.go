// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestProjectSQLValuePersistenceSinkAcceptsOnlyReviewedTrustedShapes(t *testing.T) {
	for name, test := range map[string]struct {
		server string
		tool   string
		input  map[string]interface{}
		want   bool
	}{
		"write file": {"filesystem", "mcp__filesystem__write_file", map[string]interface{}{
			"path": "/synthetic/out", "content": "credential=Fixture-Pass_Alpha123!",
		}, true},
		"entities": {"memory", "mcp__memory__create_entities", map[string]interface{}{
			"entities": []interface{}{map[string]interface{}{
				"name": "synthetic report", "entityType": "SyntheticReport",
				"observations": []interface{}{"credential=Fixture-Pass_Alpha123!"},
			}},
		}, true},
		"unsupported": {"memory", "mcp__memory__update_entity", map[string]interface{}{
			"value": "credential=Fixture-Pass_Alpha123!",
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			rawInput, err := json.Marshal(test.input)
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]interface{}{
				"mcp_server_name": test.server, "tool_input": test.input,
			}
			rawBody, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			req := agentHookRequest{
				ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
				HookEventName: "PreToolUse", ToolName: test.tool, ToolArgs: rawInput,
				Payload: payload,
			}
			ctx := withAuthenticatedHookConnector(context.Background(), "claudecode")
			ctx = withAuthenticatedToolResource(ctx, req, rawBody)
			actionTool, resourceIdentity := trustedToolActionFromContext(
				ctx, req.ConnectorName, req.ToolName, req.ToolName,
			)
			if test.want {
				if resourceIdentity == "" {
					t.Fatal("trusted MCP resource identity missing")
				}
				if _, ok := toolValueLineageStructuredPersistenceDigests(
					activeToolValueLineageProcessKey.material,
					actionfacts.Input{Tool: actionTool, Args: rawInput,
						ToolResourceIdentity: resourceIdentity},
				); !ok {
					t.Fatalf("reviewed helper rejected action tool %q", actionTool)
				}
			}
			projection := guardrail.ToolChainProjection{}
			projectSQLValuePersistenceSink(ctx, req, &projection)
			definition, _ := guardrail.ToolChainDefinitionByID(
				guardrail.ToolChainSensitiveSQLValueCrossResourcePersist,
			)
			index, _ := guardrail.ToolChainIndexByID(definition.ID)
			got := projection.DetectionStepMask&definition.Step2Bit != 0 &&
				projection.EnforcementStepMask&definition.Step2Bit == 0 &&
				projection.EnforcementJoinDigests[index] != "" &&
				projection.ValueJoinDigests[index] != (guardrail.ToolChainValueJoinDigests{})
			if got != test.want {
				t.Fatalf("projection=%+v want=%t", projection, test.want)
			}
		})
	}
}

func TestTrustedToolResourceEnvelopeBoundsReviewedNestedSink(t *testing.T) {
	accepted := []byte(`{"mcp_server_name":"memory","tool_input":{"entities":[{"name":"synthetic report","entityType":"SyntheticReport","observations":["credential=Fixture-Pass_Alpha123!"]}]}}`)
	if !exactTrustedToolResourceEnvelopeJSON(accepted) {
		t.Fatal("reviewed create_entities envelope rejected")
	}

	rejected := map[string][]byte{
		"case-insensitive duplicate": []byte(`{"mcp_server_name":"memory","tool_input":{"entities":[{"name":"one","Name":"two","entityType":"SyntheticReport","observations":["credential=Fixture-Pass_Alpha123!"]}]}}`),
		"too deep":                   []byte(`{"tool_input":{"entities":[{"observations":[["credential=Fixture-Pass_Alpha123!"]]}]}}`),
		"trailing value":             []byte(`{"tool_input":{}} {}`),
	}
	for name, raw := range rejected {
		t.Run(name, func(t *testing.T) {
			if exactTrustedToolResourceEnvelopeJSON(raw) {
				t.Fatal("ambiguous or out-of-bounds envelope accepted")
			}
		})
	}
}

func TestSQLValuePersistenceRuleIsInertInEveryBuiltInProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			pack := mustLoadRulePack(t, guardrailPoliciesRoot(t)+"/"+profile)
			found := 0
			for _, ruleFile := range pack.RuleFiles {
				for _, rule := range ruleFile.Rules {
					if rule.ID != guardrail.ToolChainSensitiveSQLValueCrossResourcePersist {
						continue
					}
					found++
					if rule.Pattern != "a^" || !rule.ToolCallOnly ||
						rule.Expression != semanticSensitiveSQLValueCrossResourcePersistenceExpression {
						t.Fatalf("non-inert catalog rule: %+v", rule)
					}
				}
			}
			if found != 1 {
				t.Fatalf("catalog rule count=%d want 1", found)
			}
		})
	}

	owner := semanticOwnerForRule(guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "write_file",
		Args: json.RawMessage(`{"path":"/synthetic/out","content":"Fixture-Pass_Alpha123!"}`),
	})
	if owner.eligible(facts) || !owner.detectionOnly || owner.alertOnly {
		t.Fatalf("single-call semantic owner is not inert detection-only: %+v", owner)
	}
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainSensitiveSQLValueCrossResourcePersist,
	)
	if !ok || !definition.DetectionOnly {
		t.Fatalf("bounded chain is not detection-only: %+v", definition)
	}
}

func TestSQLValuePersistenceLifecycleDetectsOnlySuccessfulCrossResourceExactJoins(t *testing.T) {
	for name, sink := range map[string]struct {
		server string
		tool   string
		input  map[string]interface{}
	}{
		"write file content": {
			server: "filesystem", tool: "mcp__filesystem__write_file",
			input: map[string]interface{}{
				"path":    "/synthetic/report.txt",
				"content": "Credential snapshot: Fixture-Pass_Alpha123!",
			},
		},
		"create entity observations": {
			server: "memory", tool: "mcp__memory__create_entities",
			input: map[string]interface{}{
				"entities": []interface{}{map[string]interface{}{
					"name": "synthetic report", "entityType": "SyntheticReport",
					"observations": []interface{}{"credential=Fixture-Pass_Alpha123!"},
				}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			api, profile := newSQLValuePersistenceLifecycleAPI(t, "claudecode")
			const session = "sql-persistence-positive"
			source := sqlValuePersistenceSourcePayload(session, "source-call")
			_, sourcePre := runSQLLifecycleGatewayStage(t, api, profile, source)
			assertRuleAbsent(t, sourcePre, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
			sourceResult := cloneStringAnyMap(source)
			sourceResult["hook_event_name"] = "PostToolUse"
			sourceResult["tool_response"] =
				`[{"password":"Fixture-Pass_Alpha123!"}]`
			_, sourcePost := runSQLLifecycleGatewayStage(t, api, profile, sourceResult)
			assertRuleAbsent(t, sourcePost, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)

			sinkPre := map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": session,
				"tool_use_id": "sink-call", "tool_name": sink.tool,
				"mcp_server_name": sink.server, "tool_input": sink.input,
			}
			_, preResponse := runSQLLifecycleGatewayStage(t, api, profile, sinkPre)
			assertRuleAbsent(t, preResponse, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
			sinkResult := cloneStringAnyMap(sinkPre)
			sinkResult["hook_event_name"] = "PostToolUse"
			sinkResult["tool_response"] = "synthetic success"
			_, response := runSQLLifecycleGatewayStage(t, api, profile, sinkResult)
			assertRulePresent(t, response, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
			if response.Action == guardrailActionBlock || response.WouldBlock {
				t.Fatalf("detection-only chain enforced: %+v", response)
			}

			_, replay := runSQLLifecycleGatewayStage(t, api, profile, sinkResult)
			assertRuleAbsent(t, replay, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
		})
	}
}

func TestSQLValuePersistenceLifecycleRejectsIncompleteProofs(t *testing.T) {
	for name, configure := range map[string]func(source, sink map[string]interface{}){
		"different value": func(source, sink map[string]interface{}) {
			sink["tool_input"] = map[string]interface{}{
				"path":    "/synthetic/report.txt",
				"content": "Credential snapshot: Fixture-Pass_Beta456!",
			}
		},
		"same MCP resource": func(source, sink map[string]interface{}) {
			sink["tool_name"] = "mcp__sqlite__write_file"
			sink["mcp_server_name"] = "sqlite"
		},
		"different session": func(source, sink map[string]interface{}) {
			sink["session_id"] = "sql-persistence-other-session"
		},
		"dynamic sink": func(source, sink map[string]interface{}) {
			sink["tool_input"] = map[string]interface{}{
				"path": "/synthetic/report.txt", "content": "${SQL_PASSWORD}",
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			api, profile := newSQLValuePersistenceLifecycleAPI(t, "claudecode")
			source := sqlValuePersistenceSourcePayload("sql-persistence-negative", "source-call")
			sink := map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": "sql-persistence-negative",
				"tool_use_id": "sink-call", "tool_name": "mcp__filesystem__write_file",
				"mcp_server_name": "filesystem",
				"tool_input": map[string]interface{}{
					"path":    "/synthetic/report.txt",
					"content": "Credential snapshot: Fixture-Pass_Alpha123!",
				},
			}
			configure(source, sink)
			runSQLLifecycleGatewayStage(t, api, profile, source)
			sourceResult := cloneStringAnyMap(source)
			sourceResult["hook_event_name"] = "PostToolUse"
			sourceResult["tool_response"] =
				`[{"password":"Fixture-Pass_Alpha123!"}]`
			runSQLLifecycleGatewayStage(t, api, profile, sourceResult)
			runSQLLifecycleGatewayStage(t, api, profile, sink)
			sink["hook_event_name"] = "PostToolUse"
			sink["tool_response"] = "synthetic success"
			_, response := runSQLLifecycleGatewayStage(t, api, profile, sink)
			assertRuleAbsent(t, response, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
		})
	}
}

func TestSQLValuePersistenceLifecycleRejectsFailedSourceAndSink(t *testing.T) {
	for name, failSource := range map[string]bool{"source failure": true, "sink failure": false} {
		t.Run(name, func(t *testing.T) {
			api, profile := newSQLValuePersistenceLifecycleAPI(t, "claudecode")
			const session = "sql-persistence-failure"
			source := sqlValuePersistenceSourcePayload(session, "source-call")
			runSQLLifecycleGatewayStage(t, api, profile, source)
			source["hook_event_name"] = "PostToolUse"
			if failSource {
				source["hook_event_name"] = "PostToolUseFailure"
			}
			source["tool_response"] =
				`[{"password":"Fixture-Pass_Alpha123!"}]`
			runSQLLifecycleGatewayStage(t, api, profile, source)

			sink := map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": session,
				"tool_use_id": "sink-call", "tool_name": "mcp__filesystem__write_file",
				"mcp_server_name": "filesystem",
				"tool_input": map[string]interface{}{
					"path":    "/synthetic/report.txt",
					"content": "Credential snapshot: Fixture-Pass_Alpha123!",
				},
			}
			runSQLLifecycleGatewayStage(t, api, profile, sink)
			sink["hook_event_name"] = "PostToolUse"
			if !failSource {
				sink["hook_event_name"] = "PostToolUseFailure"
			}
			sink["tool_response"] = "synthetic result"
			_, response := runSQLLifecycleGatewayStage(t, api, profile, sink)
			assertRuleAbsent(t, response, guardrail.ToolChainSensitiveSQLValueCrossResourcePersist)
		})
	}
}

func TestSQLValuePersistencePrivateHandoffsDoNotSerialize(t *testing.T) {
	const privateValue = "Fixture-Pass_Alpha123!"
	_, context := syntheticSQLLifecycleRequest(
		t, "codex", "PostToolUse", "mcp__sqlite__read_query",
		map[string]interface{}{"query": "SELECT password FROM credentials LIMIT 1"},
		map[string]interface{}{"content": []interface{}{map[string]interface{}{
			"type": "text", "text": `[{"password":"` + privateValue + `"}]`,
		}}},
	)
	req, _ := syntheticSQLLifecycleRequest(
		t, "codex", "PostToolUse", "mcp__sqlite__read_query",
		map[string]interface{}{"query": "SELECT password FROM credentials LIMIT 1"},
		map[string]interface{}{"content": []interface{}{map[string]interface{}{
			"type": "text", "text": `[{"password":"` + privateValue + `"}]`,
		}}},
	)
	source, projection, ok := projectSuccessfulSQLResultCandidate(context, req)
	if !ok {
		t.Fatal("candidate projection failed")
	}
	encoded, err := json.Marshal(struct {
		Source     interface{} `json:"source"`
		Projection interface{} `json:"projection"`
	}{Source: source, Projection: projection})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		privateValue, source.DatabaseIdentityDigest,
		projection.resourceIdentityDigest,
	} {
		if forbidden != "" && strings.Contains(string(encoded), forbidden) {
			t.Fatalf("private lineage serialized: %s", encoded)
		}
	}
}

func newSQLValuePersistenceLifecycleAPI(
	t *testing.T,
	connectorName string,
) (*APIServer, connector.HookProfile) {
	t.Helper()
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, connectorName)
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	return api, api.hookProfileForConnector(connectorName)
}

func sqlValuePersistenceSourcePayload(session, callID string) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "mcp__sqlite__read_query",
		"mcp_server_name": "sqlite",
		"tool_input": map[string]interface{}{
			"query": "SELECT password FROM credentials LIMIT 1",
		},
	}
}

func assertRulePresent(t *testing.T, response agentHookResponse, ruleID string) {
	t.Helper()
	for _, candidate := range response.RuleIDs {
		if candidate == ruleID {
			return
		}
	}
	t.Fatalf("response missing rule %q: %+v", ruleID, response)
}

func assertRuleAbsent(t *testing.T, response agentHookResponse, ruleID string) {
	t.Helper()
	for _, candidate := range response.RuleIDs {
		if candidate == ruleID {
			t.Fatalf("response unexpectedly contains rule %q: %+v", ruleID, response)
		}
	}
}
