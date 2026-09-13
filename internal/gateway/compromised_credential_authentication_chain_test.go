// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const compromisedCredentialChainID = "chain.compromised_credential_then_successful_authentication"

func TestCompromisedCredentialAuthenticationLifecycleDetectsWithoutBlocking(t *testing.T) {
	for _, posture := range []string{"default", "permissive", "strict"} {
		t.Run(posture, func(t *testing.T) {
			api, profile := newCompromisedCredentialLifecycleAPI(t, posture)
			const session = "credential-positive"
			record := compromisedCredentialRecordPayload(
				session, "record-call", "fixture.example\\operator", "fixture-secret-alpha",
			)
			runCompromisedCredentialSuccessfulCall(t, api, profile, record)

			auth := compromisedCredentialAuthenticationPayload(
				session, "auth-call", "operator", "fixture-secret-alpha", "fixture.example",
			)
			_, pre := runSQLLifecycleGatewayStage(t, api, profile, auth)
			assertRuleAbsent(t, pre, compromisedCredentialChainID)
			_, response := runSQLLifecycleGatewayStage(
				t, api, profile, successfulToolResult(auth),
			)
			assertRulePresent(t, response, compromisedCredentialChainID)
			if response.Action == guardrailActionBlock || response.WouldBlock {
				t.Fatalf("detection-only chain enforced in %s: %+v", posture, response)
			}
			assertCredentialLineageStateContainsNoPlaintext(t, api)
		})
	}
}

func TestCompromisedCredentialAuthenticationLifecycleRejectsIdentityAndOutcomeMismatch(t *testing.T) {
	for name, run := range map[string]func(
		t *testing.T, api *APIServer, profile connector.HookProfile,
	){
		"mismatch account": func(t *testing.T, api *APIServer, profile connector.HookProfile) {
			runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialRecordPayload("mismatch-account", "record", "operator", "fixture-secret-alpha"))
			response := runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialAuthenticationPayload("mismatch-account", "auth", "auditor", "fixture-secret-alpha", ""))
			assertRuleAbsent(t, response, compromisedCredentialChainID)
		},
		"mismatch credential": func(t *testing.T, api *APIServer, profile connector.HookProfile) {
			runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialRecordPayload("mismatch-credential", "record", "operator", "fixture-secret-alpha"))
			response := runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialAuthenticationPayload("mismatch-credential", "auth", "operator", "fixture-secret-beta", ""))
			assertRuleAbsent(t, response, compromisedCredentialChainID)
		},
		"different session": func(t *testing.T, api *APIServer, profile connector.HookProfile) {
			runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialRecordPayload("session-one", "record", "operator", "fixture-secret-alpha"))
			response := runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialAuthenticationPayload("session-two", "auth", "operator", "fixture-secret-alpha", ""))
			assertRuleAbsent(t, response, compromisedCredentialChainID)
		},
		"failed predecessor": func(t *testing.T, api *APIServer, profile connector.HookProfile) {
			record := compromisedCredentialRecordPayload(
				"failed-predecessor", "record", "operator", "fixture-secret-alpha",
			)
			runSQLLifecycleGatewayStage(t, api, profile, record)
			failed := cloneStringAnyMap(record)
			failed["hook_event_name"] = "PostToolUseFailure"
			failed["tool_response"] = "synthetic failure"
			runSQLLifecycleGatewayStage(t, api, profile, failed)
			response := runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialAuthenticationPayload("failed-predecessor", "auth", "operator", "fixture-secret-alpha", ""))
			assertRuleAbsent(t, response, compromisedCredentialChainID)
		},
		"failed terminal": func(t *testing.T, api *APIServer, profile connector.HookProfile) {
			runCompromisedCredentialSuccessfulCall(t, api, profile,
				compromisedCredentialRecordPayload("failed-terminal", "record", "operator", "fixture-secret-alpha"))
			auth := compromisedCredentialAuthenticationPayload(
				"failed-terminal", "auth", "operator", "fixture-secret-alpha", "",
			)
			runSQLLifecycleGatewayStage(t, api, profile, auth)
			failed := cloneStringAnyMap(auth)
			failed["hook_event_name"] = "PostToolUseFailure"
			failed["tool_response"] = "synthetic failure"
			_, response := runSQLLifecycleGatewayStage(t, api, profile, failed)
			assertRuleAbsent(t, response, compromisedCredentialChainID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			api, profile := newCompromisedCredentialLifecycleAPI(t, "default")
			run(t, api, profile)
		})
	}
}

func TestCompromisedCredentialAuthenticationLifecycleRejectsDistanceReplayAndReplacement(t *testing.T) {
	t.Run("distance greater than eight", func(t *testing.T) {
		api, profile := newCompromisedCredentialLifecycleAPI(t, "default")
		const session = "credential-distance"
		runCompromisedCredentialSuccessfulCall(t, api, profile,
			compromisedCredentialRecordPayload(session, "record", "operator", "fixture-secret-alpha"))
		for index := 0; index < 8; index++ {
			neutral := map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": session,
				"tool_use_id":     "neutral-" + string(rune('a'+index)),
				"tool_name":       "mcp__filesystem__list_directory",
				"mcp_server_name": "filesystem",
				"tool_input":      map[string]interface{}{"path": "/synthetic"},
			}
			runCompromisedCredentialSuccessfulCall(t, api, profile, neutral)
		}
		response := runCompromisedCredentialSuccessfulCall(t, api, profile,
			compromisedCredentialAuthenticationPayload(session, "auth", "operator", "fixture-secret-alpha", ""))
		assertRuleAbsent(t, response, compromisedCredentialChainID)
	})

	t.Run("exact result replay", func(t *testing.T) {
		api, profile := newCompromisedCredentialLifecycleAPI(t, "default")
		const session = "credential-replay"
		runCompromisedCredentialSuccessfulCall(t, api, profile,
			compromisedCredentialRecordPayload(session, "record", "operator", "fixture-secret-alpha"))
		auth := compromisedCredentialAuthenticationPayload(
			session, "auth", "operator", "fixture-secret-alpha", "",
		)
		runSQLLifecycleGatewayStage(t, api, profile, auth)
		result := successfulToolResult(auth)
		_, first := runSQLLifecycleGatewayStage(t, api, profile, result)
		assertRulePresent(t, first, compromisedCredentialChainID)
		_, replay := runSQLLifecycleGatewayStage(t, api, profile, result)
		assertRuleAbsent(t, replay, compromisedCredentialChainID)
	})

	t.Run("intervening same-account replacement", func(t *testing.T) {
		api, profile := newCompromisedCredentialLifecycleAPI(t, "default")
		const session = "credential-replacement"
		runCompromisedCredentialSuccessfulCall(t, api, profile,
			compromisedCredentialRecordPayload(session, "record-a", "operator", "fixture-secret-alpha"))
		replacement := compromisedCredentialRecordPayload(
			session, "record-b", "operator", "fixture-secret-beta",
		)
		replacement["tool_name"] = "update_compromised_account"
		replacement["tool_input"] = map[string]interface{}{
			"key": "operator", "username": "operator", "password": "fixture-secret-beta",
		}
		runCompromisedCredentialSuccessfulCall(t, api, profile, replacement)
		response := runCompromisedCredentialSuccessfulCall(t, api, profile,
			compromisedCredentialAuthenticationPayload(session, "auth", "operator", "fixture-secret-alpha", ""))
		assertRuleAbsent(t, response, compromisedCredentialChainID)
	})
}

func newCompromisedCredentialLifecycleAPI(
	t *testing.T,
	posture string,
) (*APIServer, connector.HookProfile) {
	t.Helper()
	api, profile := newSQLValuePersistenceLifecycleAPI(t, "claudecode")
	api.scannerCfg.Guardrail.RulePackDir = filepath.Join(
		guardrailPoliciesRoot(t), posture,
	)
	return api, profile
}

func compromisedCredentialRecordPayload(
	session, callID, username, credential string,
) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "add_compromised_account",
		"tool_input": map[string]interface{}{
			"username": username, "password": credential,
		},
	}
}

func compromisedCredentialAuthenticationPayload(
	session, callID, username, credential, domain string,
) map[string]interface{} {
	domainArgument := ""
	if domain != "" {
		domainArgument = " -d " + domain
	}
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "execute_command",
		"tool_input": map[string]interface{}{
			"command": "nxc smb host.fixture -u " + username +
				" -p " + credential + domainArgument + " --shares",
		},
	}
}

func successfulToolResult(pre map[string]interface{}) map[string]interface{} {
	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = "synthetic success"
	return result
}

func runCompromisedCredentialSuccessfulCall(
	t *testing.T,
	api *APIServer,
	profile connector.HookProfile,
	pre map[string]interface{},
) agentHookResponse {
	t.Helper()
	runSQLLifecycleGatewayStage(t, api, profile, pre)
	_, response := runSQLLifecycleGatewayStage(
		t, api, profile, successfulToolResult(pre),
	)
	return response
}

func assertCredentialLineageStateContainsNoPlaintext(t *testing.T, api *APIServer) {
	t.Helper()
	database, err := sql.Open("sqlite", api.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT enforcement_join_digests,
		value_join_digests FROM guardrail_chain_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var persisted strings.Builder
	for rows.Next() {
		var identities, values string
		if err := rows.Scan(&identities, &values); err != nil {
			t.Fatal(err)
		}
		persisted.WriteString(identities)
		persisted.WriteString(values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{
		"fixture.example", "operator", "fixture-secret-alpha",
	} {
		if strings.Contains(persisted.String(), plaintext) {
			t.Fatalf("plaintext %q persisted in chain state", plaintext)
		}
	}
}
