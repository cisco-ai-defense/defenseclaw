// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainSQLValueSourceMigrationIsValueFreeAndIdempotent(t *testing.T) {
	if got := migrations[len(migrations)-1].description; got !=
		"guardrails: bind pending SQL value sources to authoritative results" {
		t.Fatalf("last migration=%q", got)
	}
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := migrateToolChainSQLValueSourceState(store.db); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}

	want := map[string]bool{
		"sql_value_source_table_class":     false,
		"sql_value_source_resource_digest": false,
	}
	rows, err := store.db.Query(`PRAGMA table_info(guardrail_chain_pending_actions)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if _, ok := want[name]; ok {
			want[name] = true
		}
		for _, forbidden := range []string{
			"query", "result", "row", "password", "token", "ssn", "raw", "content",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("content-bearing pending column %q", name)
			}
		}
	}
	for column, present := range want {
		if !present {
			t.Fatalf("missing migration column %q", column)
		}
	}

	legacy, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	if _, err := legacy.db.Exec(`CREATE TABLE guardrail_chain_pending_actions (
		legacy_marker TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	if err := migrateToolChainSQLValueSourceState(legacy.db); err != nil {
		t.Fatalf("legacy additive migration: %v", err)
	}
	if _, err := legacy.db.Exec(`INSERT INTO guardrail_chain_pending_actions (
		sql_value_source_table_class, sql_value_source_resource_digest
		) VALUES ('employees', ?)`, strings.Repeat("e", 64)); err != nil {
		t.Fatalf("valid legacy descriptor: %v", err)
	}
	if _, err := legacy.db.Exec(`INSERT INTO guardrail_chain_pending_actions (
		sql_value_source_table_class, sql_value_source_resource_digest
		) VALUES ('employees', 'synthetic-raw-ssn')`); err == nil {
		t.Fatal("legacy migration accepted a non-digest resource value")
	}
	if _, err := legacy.db.Exec(`INSERT INTO guardrail_chain_pending_actions (
		sql_value_source_table_class, sql_value_source_resource_digest
		) VALUES ('unreviewed', ?)`, strings.Repeat("f", 64)); err == nil {
		t.Fatal("legacy migration accepted an unreviewed SQL table class")
	}
}

func TestToolChainSQLValueSourceReleasedOnlyByAuthoritativeSuccess(t *testing.T) {
	for _, outcome := range []ToolChainPendingOutcome{
		ToolChainPendingOutcomeSuccess,
		ToolChainPendingOutcomeFailure,
		ToolChainPendingOutcomeDenied,
		ToolChainPendingOutcomeCancelled,
		ToolChainPendingOutcomeUnknown,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			fixture := newToolChainFixture(t, ":memory:")
			pre := fixture.seed(t, "sql-source-"+string(outcome), correlationDigest("sql-pre-"+string(outcome)))
			source := ToolChainPendingSQLValueSource{
				TableClass:             actionfacts.SensitiveSQLTableCredentials,
				DatabaseIdentityDigest: strings.Repeat("a", 64),
			}
			prepare := ToolChainPreparePendingInput{
				ConnectorInstanceID:  pre.ConnectorInstanceID,
				ToolInvocationDigest: correlationDigest("sql-invocation-" + string(outcome)),
				PreSemanticEventID:   pre.SemanticEventID,
				PreInputFingerprint:  pre.InputFingerprint,
				RulesetFingerprint:   pre.RulesetFingerprint,
				Projection:           guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
				SQLValueSource:       source,
			}
			if got, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
				got.Status != ToolChainPendingPrepared {
				t.Fatalf("prepare=%+v err=%v", got, err)
			}
			if got, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
				got.Status != ToolChainPendingReplay {
				t.Fatalf("prepare replay=%+v err=%v", got, err)
			}
			var storedClass, storedDigest string
			if err := fixture.store.db.QueryRow(`SELECT
				sql_value_source_table_class, sql_value_source_resource_digest
				FROM guardrail_chain_pending_actions`).Scan(&storedClass, &storedDigest); err != nil {
				t.Fatal(err)
			}
			if storedClass != string(source.TableClass) || storedDigest != source.DatabaseIdentityDigest {
				t.Fatalf("stored descriptor=%q/%q", storedClass, storedDigest)
			}

			terminal := fixture.seed(t, "sql-source-"+string(outcome), correlationDigest("sql-terminal-"+string(outcome)))
			resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
				ConnectorInstanceID:      terminal.ConnectorInstanceID,
				ToolInvocationDigest:     prepare.ToolInvocationDigest,
				Outcome:                  outcome,
				RulesetFingerprint:       prepare.RulesetFingerprint,
				TerminalSemanticEventID:  terminal.SemanticEventID,
				TerminalInputFingerprint: terminal.InputFingerprint,
			})
			if err != nil || resolved.Status != ToolChainPendingResolved {
				t.Fatalf("resolve=%+v err=%v", resolved, err)
			}
			if outcome == ToolChainPendingOutcomeSuccess {
				if resolved.SQLValueSource != source {
					t.Fatalf("successful source=%+v want=%+v", resolved.SQLValueSource, source)
				}
			} else if resolved.SQLValueSource != (ToolChainPendingSQLValueSource{}) {
				t.Fatalf("unsuccessful outcome released source=%+v", resolved.SQLValueSource)
			}
			encoded, err := json.Marshal(resolved)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), source.DatabaseIdentityDigest) ||
				strings.Contains(string(encoded), string(source.TableClass)) {
				t.Fatalf("private SQL source serialized: %s", encoded)
			}
			if replay, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
				ConnectorInstanceID:      terminal.ConnectorInstanceID,
				ToolInvocationDigest:     prepare.ToolInvocationDigest,
				Outcome:                  ToolChainPendingOutcomeSuccess,
				RulesetFingerprint:       prepare.RulesetFingerprint,
				TerminalSemanticEventID:  terminal.SemanticEventID,
				TerminalInputFingerprint: terminal.InputFingerprint,
			}); err != nil || replay.Status != ToolChainPendingMissing ||
				replay.SQLValueSource != (ToolChainPendingSQLValueSource{}) {
				t.Fatalf("terminal replay=%+v err=%v", replay, err)
			}
		})
	}
}

func TestToolChainSQLValueSourceNotReleasedForMissingOrRulesetDrift(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	terminal := fixture.seed(t, "sql-missing", correlationDigest("sql-missing-terminal"))
	resolve := ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		ToolInvocationDigest:     correlationDigest("sql-missing-invocation"),
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       terminal.RulesetFingerprint,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	}
	missing, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || missing.Status != ToolChainPendingMissing ||
		missing.SQLValueSource != (ToolChainPendingSQLValueSource{}) {
		t.Fatalf("missing resolve=%+v err=%v", missing, err)
	}

	pre := fixture.seed(t, "sql-drift", correlationDigest("sql-drift-pre"))
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:  pre.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("sql-drift-invocation"),
		PreSemanticEventID:   pre.SemanticEventID,
		PreInputFingerprint:  pre.InputFingerprint,
		RulesetFingerprint:   pre.RulesetFingerprint,
		Projection:           guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
		SQLValueSource: ToolChainPendingSQLValueSource{
			TableClass:             actionfacts.SensitiveSQLTableEmployees,
			DatabaseIdentityDigest: strings.Repeat("e", 64),
		},
	}
	if _, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil {
		t.Fatal(err)
	}
	terminal = fixture.seed(t, "sql-drift", correlationDigest("sql-drift-terminal"))
	resolve = ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		ToolInvocationDigest:     prepare.ToolInvocationDigest,
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       strings.Repeat("f", 64),
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	}
	drift, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || drift.Status != ToolChainPendingExpired ||
		drift.SQLValueSource != (ToolChainPendingSQLValueSource{}) {
		t.Fatalf("ruleset drift resolve=%+v err=%v", drift, err)
	}
}

func TestToolChainSQLValueSourceConflictAndValidationFailClosed(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	pre := fixture.seed(t, "sql-conflict", correlationDigest("sql-conflict-pre"))
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:  pre.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("sql-conflict-invocation"),
		PreSemanticEventID:   pre.SemanticEventID,
		PreInputFingerprint:  pre.InputFingerprint,
		RulesetFingerprint:   pre.RulesetFingerprint,
		Projection:           guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
		SQLValueSource: ToolChainPendingSQLValueSource{
			TableClass:             actionfacts.SensitiveSQLTableCredentials,
			DatabaseIdentityDigest: strings.Repeat("b", 64),
		},
	}
	if _, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil {
		t.Fatal(err)
	}
	conflict := prepare
	conflict.SQLValueSource.TableClass = actionfacts.SensitiveSQLTableOAuthTokens
	if _, err := fixture.chain.PreparePending(t.Context(), conflict); !errors.Is(err, ErrToolChainPendingConflict) {
		t.Fatalf("descriptor conflict error=%v", err)
	}
	var count int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_pending_actions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("conflicting invocation retained %d pending rows", count)
	}

	for _, invalid := range []ToolChainPendingSQLValueSource{
		{TableClass: "other", DatabaseIdentityDigest: strings.Repeat("c", 64)},
		{TableClass: actionfacts.SensitiveSQLTableEmployees},
		{DatabaseIdentityDigest: strings.Repeat("d", 64)},
		{TableClass: actionfacts.SensitiveSQLTableEmployees, DatabaseIdentityDigest: "raw-ssn-value"},
	} {
		candidate := prepare
		candidate.ToolInvocationDigest = correlationDigest("invalid-" + string(invalid.TableClass) + invalid.DatabaseIdentityDigest)
		candidate.SQLValueSource = invalid
		if _, err := fixture.chain.PreparePending(t.Context(), candidate); err == nil {
			t.Fatalf("invalid descriptor accepted: %+v", invalid)
		}
	}
}
