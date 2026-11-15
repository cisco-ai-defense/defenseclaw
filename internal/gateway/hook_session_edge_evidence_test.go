// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHookSessionEdgesKeepTheirFirstSourceEvidence sends 30 PreToolUse
// calls of one Claude Code session through the real per-user hook handler:
// the agent and turn membership edges of the session keep the first hook as
// their only evidence row, and every hook still refreshes them (last seen).
// One row per hook made the writer time of each hook grow with the session
// (S8 GW1, rel-1-0-10 GAP-0621).
func TestHookSessionEdgesKeepTheirFirstSourceEvidence(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	// A session start and a prompt give the hooks their agent and turn.
	for _, payload := range []map[string]any{
		{"hook_event_name": "SessionStart", "session_id": "first-source", "cwd": cwd, "source": "startup"},
		{"hook_event_name": "UserPromptSubmit", "session_id": "first-source", "cwd": cwd, "prompt": "list the files"},
	} {
		recorder := httptest.NewRecorder()
		fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(mustBenchJSON(t, payload))))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: status %d body %.200s", payload["hook_event_name"], recorder.Code, recorder.Body.String())
		}
	}
	for index := range 30 {
		sendBudgetClaudeHook(t, fixture, cwd, "first-source", "PreToolUse", index)
	}
	db, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT relationship.rule_id,
		relationship.last_seen_time_unix_nano > relationship.created_time_unix_nano,
		(SELECT COUNT(*) FROM correlation_relationship_evidence AS evidence
			WHERE evidence.relationship_id=relationship.relationship_id)
		FROM correlation_relationships AS relationship
		WHERE relationship.rule_id IN (?, ?)`, "turn-session-membership", "agent-session-membership")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var rule string
		var refreshed bool
		var evidence int
		if err := rows.Scan(&rule, &refreshed, &evidence); err != nil {
			t.Fatal(err)
		}
		if evidence != 1 || !refreshed {
			t.Fatalf("%s: %d evidence rows, refreshed %v after 30 hooks; want 1 row and a refreshed last seen", rule, evidence, refreshed)
		}
		seen[rule] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !seen["agent-session-membership"] || !seen["turn-session-membership"] {
		var stored []string
		if all, err := db.Query(`SELECT DISTINCT from_kind || "->" || to_kind || " " || rule_id FROM correlation_relationships`); err == nil {
			for all.Next() {
				var rule string
				if all.Scan(&rule) == nil {
					stored = append(stored, rule)
				}
			}
			_ = all.Close()
		}
		t.Fatalf("session edges found %v, want the agent and turn membership; stored edges %v", seen, stored)
	}
}
