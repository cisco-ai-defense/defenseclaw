// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

type sqliteReadDeleteConformanceCase struct {
	ID                   string `json:"id"`
	SourceDatabase       string `json:"source_database"`
	SourceQuery          string `json:"source_query"`
	SourceOutcome        string `json:"source_outcome"`
	SinkDatabase         string `json:"sink_database"`
	SinkQuery            string `json:"sink_query"`
	InterveningSuccesses int    `json:"intervening_successes"`
	ProtectedPolicy      bool   `json:"protected_policy"`
	WantDetected         bool   `json:"want_detected"`
	WantEnforcementSafe  bool   `json:"want_enforcement_safe"`
}

func TestSensitiveSQLiteReadDeleteChainConformance(t *testing.T) {
	raw, err := os.ReadFile("testdata/sqlite_sensitive_read_delete_chain.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []sqliteReadDeleteConformanceCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 9 {
		t.Fatalf("conformance cases=%d want 9", len(cases))
	}
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete,
	)
	if !ok || definition.DetectionOnly || !definition.RequiresExactJoin ||
		definition.RequiresTerminalSuccess || definition.EventWindow != 9 {
		t.Fatalf("chain definition=%+v", definition)
	}

	for _, test := range cases {
		t.Run(test.ID, func(t *testing.T) {
			sourceFacts := actionfacts.Analyze(actionfacts.Input{
				Tool:                 "read_query",
				Args:                 sqliteChainJSON(t, map[string]interface{}{"query": test.SourceQuery}),
				ToolResourceIdentity: test.SourceDatabase,
			})
			source := guardrail.ToolChainProjection{ParseStatus: sourceFacts.Parse.Status}
			projectSensitiveSQLiteReadDeleteChainSteps(&source, sourceFacts, false)
			if source.EnforcementStepMask&definition.Step1Bit != 0 {
				t.Fatal("unresolved read proposal was enforcement-capable")
			}
			if test.SourceOutcome == "succeeded" &&
				source.DetectionStepMask&definition.Step1Bit != 0 {
				// Mirrors the authenticated ResolvePending success promotion. Failed
				// and unknown outcomes never make the proposal observable.
				source.EnforcementStepMask |= definition.Step1Bit
			} else {
				source = guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
			}

			sinkFacts := actionfacts.Analyze(actionfacts.Input{
				Tool:                 "write_query",
				Args:                 sqliteChainJSON(t, map[string]interface{}{"query": test.SinkQuery}),
				ToolResourceIdentity: test.SinkDatabase,
			})
			sink := guardrail.ToolChainProjection{ParseStatus: sinkFacts.Parse.Status}
			projectSensitiveSQLiteReadDeleteChainSteps(
				&sink, sinkFacts, test.ProtectedPolicy,
			)
			// The exact write_query DELETE is the current pre-action terminal
			// intent. Its future outcome is neither available nor required: a
			// protected posture must be able to stop it before data loss.

			now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
			prior := []guardrail.ToolChainWindowEvent{{
				SemanticEventID: "source", Sequence: 1, ReceivedAt: now,
				Projection: source,
			}}
			for index := 0; index < test.InterveningSuccesses; index++ {
				prior = append(prior, guardrail.ToolChainWindowEvent{
					SemanticEventID: "success-" + string(rune('a'+index)),
					Sequence:        uint64(index + 2),
					ReceivedAt:      now.Add(time.Duration(index+1) * time.Second),
					Projection: guardrail.ToolChainProjection{
						ParseStatus: actionfacts.StatusComplete,
					},
				})
			}
			sequence := uint64(test.InterveningSuccesses + 2)
			matches, err := guardrail.MatchToolChains(prior, guardrail.ToolChainWindowEvent{
				SemanticEventID: "sink", Sequence: sequence,
				ReceivedAt: now.Add(time.Duration(sequence-1) * time.Second),
				Projection: sink,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := matches.DetectedMask&definition.ResultBit != 0; got != test.WantDetected {
				t.Fatalf("detected=%t masks=%#x/%#x want=%t source=%+v sink=%+v",
					got, matches.DetectedMask, matches.EnforcementSafeMask, test.WantDetected,
					source, sink)
			}
			if got := matches.EnforcementSafeMask&definition.ResultBit != 0; got != test.WantEnforcementSafe {
				t.Fatalf("enforcement_safe=%t masks=%#x/%#x want=%t",
					got, matches.DetectedMask, matches.EnforcementSafeMask,
					test.WantEnforcementSafe)
			}
		})
	}
}

func TestSensitiveSQLiteReadDeletePolicyAnchorIsDetectionOnly(t *testing.T) {
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:                 "write_query",
		Args:                 json.RawMessage(`{"query":"DELETE FROM credentials"}`),
		ToolResourceIdentity: "mcp://sqlite/fixture-protected",
	})
	owner := semanticOwnerForRule(
		guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete,
	)
	if !owner.eligible(facts) || !owner.detectionOnly || owner.alertOnly {
		t.Fatalf("policy anchor owner=%+v", owner)
	}
	for _, query := range []string{
		"DELETE FROM credentials WHERE id = 7",
		"DELETE FROM credentials; SELECT 1",
		"DELETE FROM ${TABLE}",
	} {
		candidate := actionfacts.Analyze(actionfacts.Input{
			Tool:                 "write_query",
			Args:                 sqliteChainJSON(t, map[string]interface{}{"query": query}),
			ToolResourceIdentity: "mcp://sqlite/fixture-protected",
		})
		if owner.eligible(candidate) {
			t.Fatalf("policy anchor admitted hard negative %q", query)
		}
	}
}

func TestAuthenticatedSensitiveSQLiteReadDeletePreActionPosture(t *testing.T) {
	installCorrelationHMACForTest()
	policiesRoot := guardrailPoliciesRoot(t)
	tests := []struct {
		name          string
		rulePackDir   string
		useCasePack   bool
		wantAction    string
		wantRawAction string
	}{
		{
			name: "default alerts without blocking", rulePackDir: filepath.Join(policiesRoot, "default"),
			wantAction: "alert", wantRawAction: "alert",
		},
		{
			name: "strict blocks before execution", rulePackDir: filepath.Join(policiesRoot, "strict"),
			wantAction: "block", wantRawAction: "block",
		},
		{
			name:        "database protection blocks before execution",
			rulePackDir: useCaseProfileDir("database-destruction-protection"),
			useCasePack: true, wantAction: "block", wantRawAction: "block",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.useCasePack {
				installDefaultProfileConnector(t, "claudecode")
				pack, err := guardrail.LoadRulePack(test.rulePackDir)
				if err != nil {
					t.Fatal(err)
				}
				if err := ApplyConnectorRulePackOverrides("claudecode", pack); err != nil {
					t.Fatal(err)
				}
			} else {
				profile := filepath.Base(test.rulePackDir)
				installToolCallCorpusProfileConnector(t, "claudecode", profile)
			}

			store, logger := testStoreAndV8Logger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePackDir = test.rulePackDir
			api := NewAPIServer(
				"127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg,
			)
			profile := api.hookProfileForConnector("claudecode")
			session := "sqlite-read-delete-" + filepath.Base(test.rulePackDir)
			read := map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": session,
				"tool_use_id": "read", "tool_name": "mcp__sqlite__read_query",
				"mcp_server_name": "sqlite",
				"tool_input": map[string]interface{}{
					"query": "SELECT password FROM credentials LIMIT 1",
				},
			}
			runSQLLifecycleGatewayStage(t, api, profile, read)
			readResult := cloneStringAnyMap(read)
			readResult["hook_event_name"] = "PostToolUse"
			readResult["tool_response"] = `[]`
			runSQLLifecycleGatewayStage(t, api, profile, readResult)

			// There is intentionally no PostToolUse for this DELETE. The
			// disposition is asserted on the current pre-execution intent.
			_, got := runSQLLifecycleGatewayStage(t, api, profile, map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": session,
				"tool_use_id": "delete", "tool_name": "mcp__sqlite__write_query",
				"mcp_server_name": "sqlite",
				"tool_input": map[string]interface{}{
					"query": "DELETE FROM credentials",
				},
			})
			if got.Action != test.wantAction || got.RawAction != test.wantRawAction ||
				got.WouldBlock || got.Severity != "CRITICAL" || !slices.Contains(
				got.RuleIDs,
				guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete,
			) {
				t.Fatalf(
					"pre-action response=%+v want action=%q raw=%q chain=%q",
					got, test.wantAction, test.wantRawAction,
					guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete,
				)
			}
		})
	}
}

func sqliteChainJSON(t *testing.T, value interface{}) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
