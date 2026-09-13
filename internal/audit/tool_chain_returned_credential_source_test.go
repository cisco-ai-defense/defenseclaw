// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainReturnedCredentialSourceMigrationIsValueFreeAndIdempotent(t *testing.T) {
	const migrationIndex = 48
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: bind pending credential sources to authoritative results" {
		t.Fatal("returned credential-source state is not append-only migration 49")
	}
	if actionfacts.ReturnedCredentialSourceNone != 0 ||
		actionfacts.ReturnedCredentialSourceSecretsDump != 1 ||
		actionfacts.ReturnedCredentialSourceKerberoast != 2 ||
		actionfacts.ReturnedCredentialSourceASREPRoast != 3 ||
		actionfacts.ReturnedCredentialSourceFileRead != 4 {
		t.Fatal("returned credential-source enum no longer matches the persisted closed enum")
	}

	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := migrateToolChainReturnedCredentialSourceState(store.db); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}

	rows, err := store.db.Query(`PRAGMA table_info(guardrail_chain_pending_actions)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(
			&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey,
		); err != nil {
			t.Fatal(err)
		}
		if name != "returned_credential_source" {
			continue
		}
		found = true
		if columnType != "INTEGER" || notNull != 1 ||
			!defaultValue.Valid || defaultValue.String != "0" {
			t.Fatalf("unexpected returned credential source column: type=%q notNull=%d default=%q",
				columnType, notNull, defaultValue.String)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("missing returned_credential_source migration column")
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
	if err := migrateToolChainReturnedCredentialSourceState(legacy.db); err != nil {
		t.Fatalf("legacy additive migration: %v", err)
	}
	for source := 0; source <= 4; source++ {
		if _, err := legacy.db.Exec(`INSERT INTO guardrail_chain_pending_actions (
			returned_credential_source) VALUES (?)`, source); err != nil {
			t.Fatalf("valid source %d: %v", source, err)
		}
	}
	for _, invalid := range []int{-1, 5, 255} {
		if _, err := legacy.db.Exec(`INSERT INTO guardrail_chain_pending_actions (
			returned_credential_source) VALUES (?)`, invalid); err == nil {
			t.Fatalf("migration accepted invalid source %d", invalid)
		}
	}
}

func TestToolChainReturnedCredentialSourceReleasedOnlyByAuthoritativeSuccess(t *testing.T) {
	for _, source := range []actionfacts.ReturnedCredentialSource{
		actionfacts.ReturnedCredentialSourceSecretsDump,
		actionfacts.ReturnedCredentialSourceKerberoast,
		actionfacts.ReturnedCredentialSourceASREPRoast,
		actionfacts.ReturnedCredentialSourceFileRead,
	} {
		t.Run(sourceName(source), func(t *testing.T) {
			fixture := newToolChainFixture(t, ":memory:")
			pre := fixture.seed(t, "credential-success", correlationDigest("credential-pre-"+sourceName(source)))
			prepare := ToolChainPreparePendingInput{
				ConnectorInstanceID:      pre.ConnectorInstanceID,
				ToolInvocationDigest:     correlationDigest("credential-invocation-" + sourceName(source)),
				PreSemanticEventID:       pre.SemanticEventID,
				PreInputFingerprint:      pre.InputFingerprint,
				RulesetFingerprint:       pre.RulesetFingerprint,
				Projection:               guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
				ReturnedCredentialSource: source,
			}
			if got, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
				got.Status != ToolChainPendingPrepared {
				t.Fatalf("prepare=%+v err=%v", got, err)
			}
			if got, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
				got.Status != ToolChainPendingReplay {
				t.Fatalf("prepare replay=%+v err=%v", got, err)
			}
			var stored int
			if err := fixture.store.db.QueryRow(`SELECT returned_credential_source
				FROM guardrail_chain_pending_actions`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != int(source) {
				t.Fatalf("stored source=%d want=%d", stored, source)
			}

			terminal := fixture.seed(t, "credential-success", correlationDigest("credential-terminal-"+sourceName(source)))
			resolve := ToolChainResolvePendingInput{
				ConnectorInstanceID:      terminal.ConnectorInstanceID,
				ToolInvocationDigest:     prepare.ToolInvocationDigest,
				Outcome:                  ToolChainPendingOutcomeSuccess,
				RulesetFingerprint:       prepare.RulesetFingerprint,
				TerminalSemanticEventID:  terminal.SemanticEventID,
				TerminalInputFingerprint: terminal.InputFingerprint,
			}
			resolved, err := fixture.chain.ResolvePending(t.Context(), resolve)
			if err != nil || resolved.Status != ToolChainPendingResolved ||
				resolved.Observation.Status != ToolChainObserveFresh {
				t.Fatalf("resolve=%+v err=%v", resolved, err)
			}
			if resolved.ReturnedCredentialSource != source {
				t.Fatalf("released source=%d want=%d", resolved.ReturnedCredentialSource, source)
			}
			encoded, err := json.Marshal(resolved)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "ReturnedCredentialSource") ||
				strings.Contains(string(encoded), "returned_credential_source") {
				t.Fatalf("private credential source serialized: %s", encoded)
			}

			replay, err := fixture.chain.ResolvePending(t.Context(), resolve)
			if err != nil || replay.Status != ToolChainPendingMissing ||
				replay.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
				t.Fatalf("terminal replay=%+v err=%v", replay, err)
			}
		})
	}
}

func TestToolChainReturnedCredentialSourceNeverReleasedByNonSuccess(t *testing.T) {
	for _, outcome := range []ToolChainPendingOutcome{
		ToolChainPendingOutcomeFailure,
		ToolChainPendingOutcomeDenied,
		ToolChainPendingOutcomeCancelled,
		ToolChainPendingOutcomeUnknown,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			fixture := newToolChainFixture(t, ":memory:")
			pre := fixture.seed(t, "credential-"+string(outcome), correlationDigest("credential-pre-"+string(outcome)))
			prepare := ToolChainPreparePendingInput{
				ConnectorInstanceID:      pre.ConnectorInstanceID,
				ToolInvocationDigest:     correlationDigest("credential-invocation-" + string(outcome)),
				PreSemanticEventID:       pre.SemanticEventID,
				PreInputFingerprint:      pre.InputFingerprint,
				RulesetFingerprint:       pre.RulesetFingerprint,
				Projection:               guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
				ReturnedCredentialSource: actionfacts.ReturnedCredentialSourceSecretsDump,
			}
			if _, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil {
				t.Fatal(err)
			}
			terminal := fixture.seed(t, "credential-"+string(outcome), correlationDigest("credential-terminal-"+string(outcome)))
			resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
				ConnectorInstanceID:      terminal.ConnectorInstanceID,
				ToolInvocationDigest:     prepare.ToolInvocationDigest,
				Outcome:                  outcome,
				TerminalSemanticEventID:  terminal.SemanticEventID,
				TerminalInputFingerprint: terminal.InputFingerprint,
			})
			if err != nil || resolved.Status != ToolChainPendingResolved ||
				resolved.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
				t.Fatalf("resolve=%+v err=%v", resolved, err)
			}
		})
	}
}

func TestToolChainReturnedCredentialSourceNotReleasedForMissingDriftOrExpiry(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		fixture := newToolChainFixture(t, ":memory:")
		terminal := fixture.seed(t, "credential-missing", correlationDigest("credential-missing-terminal"))
		resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			ToolInvocationDigest:     correlationDigest("credential-missing-invocation"),
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       terminal.RulesetFingerprint,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		})
		if err != nil || resolved.Status != ToolChainPendingMissing ||
			resolved.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
			t.Fatalf("missing resolve=%+v err=%v", resolved, err)
		}
	})

	t.Run("session-mismatch", func(t *testing.T) {
		fixture, prepare := prepareReturnedCredentialSource(t, "credential-session-a")
		terminal := fixture.seed(t, "credential-session-b", correlationDigest("credential-session-b-terminal"))
		resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			ToolInvocationDigest:     prepare.ToolInvocationDigest,
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       prepare.RulesetFingerprint,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		})
		if err != nil || resolved.Status != ToolChainPendingMissing ||
			resolved.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
			t.Fatalf("session mismatch resolve=%+v err=%v", resolved, err)
		}
		var count int
		if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
			FROM guardrail_chain_pending_actions`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("session mismatch pending=%d err=%v", count, err)
		}
	})

	t.Run("terminal-identity-drift", func(t *testing.T) {
		fixture, prepare := prepareReturnedCredentialSource(t, "credential-identity-drift")
		terminal := fixture.seed(t, "credential-identity-drift", correlationDigest("credential-identity-terminal"))
		resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			ToolInvocationDigest:     prepare.ToolInvocationDigest,
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       prepare.RulesetFingerprint,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: correlationDigest("credential-forged-terminal"),
		})
		if !errors.Is(err, ErrToolChainIntegrity) ||
			resolved.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
			t.Fatalf("terminal identity drift resolve=%+v err=%v", resolved, err)
		}
	})

	t.Run("ruleset-drift", func(t *testing.T) {
		fixture, prepare := prepareReturnedCredentialSource(t, "credential-drift")
		terminal := fixture.seed(t, "credential-drift", correlationDigest("credential-drift-terminal"))
		resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			ToolInvocationDigest:     prepare.ToolInvocationDigest,
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       strings.Repeat("f", 64),
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		})
		if err != nil || resolved.Status != ToolChainPendingExpired ||
			resolved.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
			t.Fatalf("drift resolve=%+v err=%v", resolved, err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		fixture, prepare := prepareReturnedCredentialSource(t, "credential-expired")
		fixture.chain.pendingTTL = time.Minute
		// The pending row was created with the fixture's original default TTL;
		// constrain it directly to test the persisted expiry boundary.
		if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_pending_actions
			SET expires_time_unix_nano=?`, unixNano(fixture.now.Add(time.Minute))); err != nil {
			t.Fatal(err)
		}
		fixture.now = fixture.now.Add(time.Minute)
		terminal := fixture.seed(t, "credential-expired", correlationDigest("credential-expired-terminal"))
		resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			ToolInvocationDigest:     prepare.ToolInvocationDigest,
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       prepare.RulesetFingerprint,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		})
		if err != nil || resolved.Status != ToolChainPendingExpired ||
			resolved.ReturnedCredentialSource != actionfacts.ReturnedCredentialSourceNone {
			t.Fatalf("expired resolve=%+v err=%v", resolved, err)
		}
	})
}

func TestToolChainReturnedCredentialSourceConflictAndValidationFailClosed(t *testing.T) {
	fixture, prepare := prepareReturnedCredentialSource(t, "credential-conflict")
	conflict := prepare
	conflict.ReturnedCredentialSource = actionfacts.ReturnedCredentialSourceKerberoast
	if _, err := fixture.chain.PreparePending(t.Context(), conflict); !errors.Is(err, ErrToolChainPendingConflict) {
		t.Fatalf("source conflict error=%v", err)
	}
	var count int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("conflicting invocation retained %d pending rows", count)
	}

	invalid := prepare
	invalid.ToolInvocationDigest = correlationDigest("credential-invalid-source")
	invalid.ReturnedCredentialSource = actionfacts.ReturnedCredentialSource(5)
	if _, err := fixture.chain.PreparePending(t.Context(), invalid); err == nil {
		t.Fatal("invalid returned credential source accepted")
	}
}

func prepareReturnedCredentialSource(
	t *testing.T,
	session string,
) (*toolChainFixture, ToolChainPreparePendingInput) {
	t.Helper()
	fixture := newToolChainFixture(t, ":memory:")
	pre := fixture.seed(t, session, correlationDigest(session+"-pre"))
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:      pre.ConnectorInstanceID,
		ToolInvocationDigest:     correlationDigest(session + "-invocation"),
		PreSemanticEventID:       pre.SemanticEventID,
		PreInputFingerprint:      pre.InputFingerprint,
		RulesetFingerprint:       pre.RulesetFingerprint,
		Projection:               guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
		ReturnedCredentialSource: actionfacts.ReturnedCredentialSourceSecretsDump,
	}
	if got, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
		got.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare=%+v err=%v", got, err)
	}
	return fixture, prepare
}

func sourceName(source actionfacts.ReturnedCredentialSource) string {
	switch source {
	case actionfacts.ReturnedCredentialSourceSecretsDump:
		return "secrets-dump"
	case actionfacts.ReturnedCredentialSourceKerberoast:
		return "kerberoast"
	case actionfacts.ReturnedCredentialSourceASREPRoast:
		return "asrep-roast"
	case actionfacts.ReturnedCredentialSourceFileRead:
		return "file-read"
	default:
		return "none"
	}
}
