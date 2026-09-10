// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainMigrationIsContentFreeIdempotentAndConstrained(t *testing.T) {
	const toolChainMigrationIndex = 29
	if len(migrations) <= toolChainMigrationIndex ||
		migrations[toolChainMigrationIndex].description !=
			"guardrails: add bounded durable tool-call chain state" {
		t.Fatal("tool-chain state is not append-only migration 30")
	}
	fixture := newToolChainFixture(t, ":memory:")
	if err := migrateToolChainState(fixture.store.db); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
	for _, table := range []string{
		"guardrail_chain_partitions", "guardrail_chain_events",
		"guardrail_chain_deny_receipts",
	} {
		rows, err := fixture.store.db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var (
				cid, notNull, primaryKey int
				name, columnType         string
				defaultValue             sql.NullString
			)
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"command", "argv", "payload", "content", "raw", "normalized_value",
				"path", "endpoint", "url",
			} {
				if strings.Contains(name, forbidden) {
					_ = rows.Close()
					t.Fatalf("%s contains content-bearing column %s", table, name)
				}
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}

	chainID := guardrail.ToolChainGuardrailsOffThenEgress
	first := fixture.seed(t, "constraints", correlationDigest("constraints-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "constraints", correlationDigest("constraints-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	if _, err := fixture.chain.Observe(t.Context(), final); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_events
		SET enforcement_step_mask=8191, detection_step_mask=0
		WHERE semantic_event_id=?`, string(final.SemanticEventID)); err == nil {
		t.Fatal("projection subset constraint accepted invalid masks")
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_events
		SET detected_chain_mask=262143, enforcement_safe_chain_mask=262143
		WHERE semantic_event_id=?`, string(final.SemanticEventID)); err != nil {
		t.Fatalf("eighteen-slot event mask rejected: %v", err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_events
		SET detected_chain_mask=262144
		WHERE semantic_event_id=?`, string(final.SemanticEventID)); err == nil {
		t.Fatal("event result mask accepted a nineteenth slot")
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_deny_receipts
		SET detected_chain_mask=262143, enforcement_safe_chain_mask=262143,
			denied_chain_mask=262143, severity='CRITICAL'`); err != nil {
		t.Fatalf("eighteen-slot critical receipt rejected: %v", err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_deny_receipts
		SET detected_chain_mask=262144`); err == nil {
		t.Fatal("receipt result mask accepted a nineteenth slot")
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_deny_receipts
		SET severity='LOW'`); err == nil {
		t.Fatal("receipt severity constraint accepted LOW")
	}
	if _, err := fixture.store.db.Exec(`DELETE FROM correlation_events
		WHERE semantic_event_id=?`, string(final.SemanticEventID)); err == nil {
		t.Fatal("correlation event deletion bypassed chain-event RESTRICT")
	}
}

func TestToolChainExpandedCatalogMigrationIsAppendOnly(t *testing.T) {
	const expandedCatalogMigrationIndex = 36
	if len(migrations) <= expandedCatalogMigrationIndex ||
		migrations[expandedCatalogMigrationIndex].description !=
			"guardrails: expand bounded chain catalog to nine result slots" {
		t.Fatal("nine-slot chain catalog is not append-only migration 37")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("nine-slot-input"),
		RulesetFingerprint: correlationDigest("nine-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 257); low == high {
		t.Fatal("ninth result bit collided in stable action identity")
	}
}

func TestToolChainTenSlotCatalogMigrationIsAppendOnly(t *testing.T) {
	const tenSlotCatalogMigrationIndex = 37
	if len(migrations) <= tenSlotCatalogMigrationIndex ||
		migrations[tenSlotCatalogMigrationIndex].description !=
			"guardrails: expand bounded chain catalog to ten result slots" {
		t.Fatal("ten-slot chain catalog is not append-only migration 38")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("ten-slot-input"),
		RulesetFingerprint: correlationDigest("ten-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 513); low == high {
		t.Fatal("tenth result bit collided in stable action identity")
	}
}

func TestToolChainElevenSlotCatalogMigrationIsAppendOnly(t *testing.T) {
	const elevenSlotCatalogMigrationIndex = 38
	if len(migrations) <= elevenSlotCatalogMigrationIndex ||
		migrations[elevenSlotCatalogMigrationIndex].description !=
			"guardrails: expand bounded chain catalog to eleven result slots" {
		t.Fatal("eleven-slot chain catalog is not append-only migration 39")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("eleven-slot-input"),
		RulesetFingerprint: correlationDigest("eleven-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 1025); low == high {
		t.Fatal("eleventh result bit collided in stable action identity")
	}
}

func TestToolChainTwelveSlotCatalogMigrationIsAppendOnly(t *testing.T) {
	const twelveSlotCatalogMigrationIndex = 39
	if len(migrations) <= twelveSlotCatalogMigrationIndex ||
		migrations[twelveSlotCatalogMigrationIndex].description !=
			"guardrails: expand bounded chain catalog to twelve result slots" {
		t.Fatal("twelve-slot chain catalog is not append-only migration 40")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("twelve-slot-input"),
		RulesetFingerprint: correlationDigest("twelve-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 2049); low == high {
		t.Fatal("twelfth result bit collided in stable action identity")
	}
}

func TestToolChainThirteenSlotCatalogMigrationIsAppendOnly(t *testing.T) {
	const thirteenSlotCatalogMigrationIndex = 40
	if len(migrations) <= thirteenSlotCatalogMigrationIndex ||
		migrations[thirteenSlotCatalogMigrationIndex].description !=
			"guardrails: expand bounded chain catalog to thirteen result slots" {
		t.Fatal("thirteen-slot chain catalog is not append-only migration 41")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("thirteen-slot-input"),
		RulesetFingerprint: correlationDigest("thirteen-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 4097); low == high {
		t.Fatal("thirteenth result bit collided in stable action identity")
	}
}

func TestToolChainFourteenSlotWideMaskMigrationIsAppendOnly(t *testing.T) {
	const wideMaskMigrationIndex = 41
	if len(migrations) <= wideMaskMigrationIndex ||
		migrations[wideMaskMigrationIndex].description !=
			"guardrails: widen bounded chain masks and add result slots fourteen through seventeen" {
		t.Fatal("fourteen-slot wide-mask catalog is not append-only migration 42")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("fourteen-slot-input"),
		RulesetFingerprint: correlationDigest("fourteen-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 8193); low == high {
		t.Fatal("fourteenth result bit collided in stable action identity")
	}
	const legacyStableAction = "gca_bb8b49f67ea7060974b4fa423810a97cca7f57a8cf3cf880c3d4305f2de2ce07"
	if got := stableToolChainActionID(input, 8193); got != legacyStableAction {
		t.Fatalf("legacy stable action identity=%q want %q", got, legacyStableAction)
	}
}

func TestToolChainEighteenSlotWideMaskMigrationIsAppendOnly(t *testing.T) {
	const migrationIndex = 42
	if len(migrations) <= migrationIndex ||
		migrations[migrationIndex].description !=
			"guardrails: add staged reverse-shell persistence result slot eighteen" {
		t.Fatal("eighteen-slot wide-mask catalog is not append-only migration 43")
	}
	input := ToolChainObserveInput{
		SemanticEventID:    SemanticEventID("0198a730-2210-7e11-8c3f-3d7bdbe3db10"),
		InputFingerprint:   correlationDigest("eighteen-slot-input"),
		RulesetFingerprint: correlationDigest("eighteen-slot-ruleset"),
	}
	if low, high := stableToolChainActionID(input, 1), stableToolChainActionID(input, 131073); low == high {
		t.Fatal("eighteenth result bit collided in stable action identity")
	}
}

func TestToolChainUint32ResultMaskSQLiteCapacityBeyondSixteenChains(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	if _, err := fixture.store.db.Exec(`CREATE TEMP TABLE result_mask_capacity (
		id INTEGER PRIMARY KEY,
		mask INTEGER NOT NULL CHECK (mask BETWEEN 0 AND 2147483647)
	)`); err != nil {
		t.Fatal(err)
	}
	for index, want := range []uint32{1 << 16, 1<<17 - 1, 1 << 30} {
		if _, err := fixture.store.db.Exec(
			`INSERT INTO result_mask_capacity (id, mask) VALUES (?, ?)`, index, want,
		); err != nil {
			t.Fatalf("insert mask %#x: %v", want, err)
		}
		var got uint32
		if err := fixture.store.db.QueryRow(
			`SELECT mask FROM result_mask_capacity WHERE id=?`, index,
		).Scan(&got); err != nil {
			t.Fatalf("scan mask %#x: %v", want, err)
		}
		if got != want {
			t.Fatalf("mask round trip=%#x want %#x", got, want)
		}
	}
	if _, err := fixture.store.db.Exec(
		`INSERT INTO result_mask_capacity (id, mask) VALUES (99, ?)`, uint32(1<<31),
	); err == nil {
		t.Fatal("reserved result sign bit passed the signed SQLite bound")
	}
}

func TestWideMaskMigrationPreservesAndReplaysEveryLegacyChainRow(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definitions := guardrail.ToolChainDefinitions()
	legacyDefinitions := definitions[:guardrail.ToolChainLegacyCount]
	inputs := make([]ToolChainObserveInput, 0, len(legacyDefinitions))
	for index, definition := range legacyDefinitions {
		input := fixture.seed(t,
			"legacy-chain-"+definition.ID,
			correlationDigest("legacy-chain-input-"+definition.ID),
		)
		projection := guardrail.ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: definition.Step1Bit,
		}
		if definition.RequiresExactJoin || definition.RequiresEnforcementJoin {
			chainIndex, _ := guardrail.ToolChainIndexByID(definition.ID)
			projection.EnforcementJoinDigests[chainIndex] =
				correlationDigest("legacy-chain-join-" + definition.ID)
		}
		if definition.OutputJoinFromFirst {
			chainIndex, _ := guardrail.ToolChainIndexByID(definition.ID)
			projection.EnforcementOutputJoinDigests[chainIndex] =
				correlationDigest("legacy-chain-output-" + definition.ID)
		}
		input.Projection = projection
		result, err := fixture.chain.Observe(t.Context(), input)
		if err != nil || result.Status != ToolChainObserveFresh {
			t.Fatalf("seed legacy chain %d %s: result=%+v err=%v",
				index, definition.ID, result, err)
		}
		inputs = append(inputs, input)
		fixture.now = fixture.now.Add(time.Second)
	}

	var preCount int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_events`).Scan(&preCount); err != nil {
		t.Fatal(err)
	}
	if preCount != len(legacyDefinitions) {
		t.Fatalf("legacy rows=%d want %d", preCount, len(legacyDefinitions))
	}
	rows, err := fixture.store.db.Query(`SELECT enforcement_join_digests,
		enforcement_output_join_digests FROM guardrail_chain_events`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var joins, outputs string
		if err := rows.Scan(&joins, &outputs); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		for _, encoded := range []string{joins, outputs} {
			if encoded != "" && strings.Count(encoded, ",") != 12 {
				_ = rows.Close()
				t.Fatalf("row is not in deployed 13-slot encoding: %q", encoded)
			}
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	if err := migrateToolChainFourteenSlotWideMaskState(fixture.store.db); err != nil {
		t.Fatalf("migrate pre-widening rows: %v", err)
	}
	var postCount int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_events`).Scan(&postCount); err != nil {
		t.Fatal(err)
	}
	if postCount != preCount {
		t.Fatalf("migrated rows=%d want %d", postCount, preCount)
	}
	for index, input := range inputs {
		replay, err := fixture.chain.Observe(t.Context(), input)
		if err != nil || replay.Status != ToolChainObserveReplay || !replay.SuppressTelemetry {
			t.Fatalf("replay legacy chain %d %s: result=%+v err=%v",
				index, legacyDefinitions[index].ID, replay, err)
		}
	}

	for index, newDefinition := range definitions[guardrail.ToolChainLegacyCount:] {
		wide := fixture.seed(t,
			fmt.Sprintf("wide-chain-%d", index),
			correlationDigest(fmt.Sprintf("wide-chain-input-%d", index)),
		)
		wide.Projection = guardrail.ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: newDefinition.Step1Bit,
		}
		newIndex, _ := guardrail.ToolChainIndexByID(newDefinition.ID)
		wide.Projection.EnforcementJoinDigests[newIndex] =
			correlationDigest(fmt.Sprintf("wide-chain-join-%d", index))
		if result, err := fixture.chain.Observe(t.Context(), wide); err != nil ||
			result.Status != ToolChainObserveFresh {
			t.Fatalf("persist widened bit %s: result=%+v err=%v",
				newDefinition.ID, result, err)
		}
	}
}

type toolChainFixture struct {
	store    *Store
	chain    *ToolChainRepository
	correl   *CorrelationRepository
	instance ConnectorInstance
	now      time.Time
}

func newToolChainFixture(t *testing.T, path string) *toolChainFixture {
	t.Helper()
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	correl, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := store.ToolChainRepository()
	if err != nil {
		t.Fatal(err)
	}
	fixture := &toolChainFixture{
		store: store, chain: chain, correl: correl,
		instance: mustCorrelationInstance(t, correl, "chain-fixture", ConnectorCustodyHookOnly),
		now:      time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}
	fixture.chain.now = func() time.Time { return fixture.now }
	return fixture
}

func (fixture *toolChainFixture) seed(
	t *testing.T,
	session string,
	inputFingerprint string,
) ToolChainObserveInput {
	t.Helper()
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	event := CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic),
		Connector:           fixture.instance.Connector,
		ConnectorInstanceID: fixture.instance.ConnectorInstanceID,
		Rail:                CorrelationRailHook, EventName: "tool.call",
		ReceivedTime: fixture.now, FingerprintSHA256: inputFingerprint,
		ProfileVersion: fixture.instance.ProfileVersion, Completeness: CorrelationComplete,
	}
	tx, _, err := fixture.correl.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: event})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.PutIdentifier(t.Context(), CorrelationIdentifier{
		SemanticEventID: semantic, ConnectorInstanceID: fixture.instance.ConnectorInstanceID,
		Namespace: "fixture", Kind: CorrelationIdentifierSession,
		ValueDigest: correlationDigest(session), NormalizedValue: session,
		SourceField: "session", Origin: CorrelationOriginReported,
		ProfileVersion: fixture.instance.ProfileVersion, ObservedAt: fixture.now,
	}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ToolChainObserveInput{
		SemanticEventID: semantic, ConnectorInstanceID: fixture.instance.ConnectorInstanceID,
		InputFingerprint:   inputFingerprint,
		RulesetFingerprint: correlationDigest("ruleset-a"),
	}
}

func toolChainProjection(t *testing.T, ids []string, step int, enforce bool) guardrail.ToolChainProjection {
	t.Helper()
	var mask uint64
	for _, id := range ids {
		bit, ok := guardrail.ToolChainStepMask(id, step)
		if !ok {
			t.Fatalf("unknown chain %s", id)
		}
		mask |= bit
	}
	projection := guardrail.ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete, DetectionStepMask: mask,
	}
	if enforce {
		projection.EnforcementStepMask = mask
		for _, id := range ids {
			definition, _ := guardrail.ToolChainDefinitionByID(id)
			if !definition.RequiresEnforcementJoin {
				continue
			}
			index, _ := guardrail.ToolChainIndexByID(id)
			projection.EnforcementJoinDigests[index] =
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}
	}
	return projection
}

func TestToolChainRepositoryPersistsThreeStepDerivedArtifactLineage(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definition, _ := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainDownloadDecodeExecuteSameArtifact,
	)
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	const archive = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const derived = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	projection := func(step uint64, input, output string) guardrail.ToolChainProjection {
		result := guardrail.ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = input
		result.EnforcementOutputJoinDigests[index] = output
		return result
	}

	first := fixture.seed(t, "derived-lineage", correlationDigest("derived-download"))
	first.Projection = projection(definition.Step1Bit, archive, "")
	if result, err := fixture.chain.Observe(t.Context(), first); err != nil || result.DetectedMask != 0 {
		t.Fatalf("download result=%+v err=%v", result, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	middle := fixture.seed(t, "derived-lineage", correlationDigest("derived-decode"))
	middle.Projection = projection(definition.Step2Bit, archive, derived)
	if result, err := fixture.chain.Observe(t.Context(), middle); err != nil || result.DetectedMask != 0 {
		t.Fatalf("decode result=%+v err=%v", result, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "derived-lineage", correlationDigest("derived-execute"))
	final.Projection = projection(definition.Step3Bit, "", derived)
	final.DenyEligible = true
	result, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if result.DetectedMask != definition.ResultBit ||
		result.EnforcementSafeMask != definition.ResultBit ||
		result.DeniedMask != definition.ResultBit || len(result.ReceiptIDs) != 1 {
		t.Fatalf("derived lineage result=%+v", result)
	}

	fixture.now = fixture.now.Add(time.Second)
	failedFinal := fixture.seed(t, "failed-derived-lineage", correlationDigest("failed-execute"))
	failedFinal.Projection = projection(definition.Step3Bit, "", derived)
	failedFinal.DenyEligible = true
	failed, err := fixture.chain.Observe(t.Context(), failedFinal)
	if err != nil {
		t.Fatal(err)
	}
	if failed.DetectedMask != 0 || failed.EnforcementSafeMask != 0 || failed.DeniedMask != 0 {
		t.Fatalf("terminal action without successful predecessors joined: %+v", failed)
	}
}

func TestToolChainObserveRestartReplayRulesetAndFinalization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	fixture := newToolChainFixture(t, path)
	chains := []string{
		guardrail.ToolChainGuardrailsOffThenEgress,
		guardrail.ToolChainSecretReadThenEgress,
	}
	first := fixture.seed(t, "session-a", correlationDigest("first"))
	first.Projection = toolChainProjection(t, chains, 1, true)
	if result, err := fixture.chain.Observe(t.Context(), first); err != nil ||
		result.Status != ToolChainObserveFresh || result.DeniedMask != 0 {
		t.Fatalf("first result=%#v err=%v", result, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "session-a", correlationDigest("final"))
	final.Projection = toolChainProjection(t, chains, 2, true)
	final.DenyEligible = true
	fresh, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != ToolChainObserveFresh || len(fresh.ReceiptIDs) != 2 ||
		fresh.DeniedMask == 0 || fresh.SuppressTelemetry {
		t.Fatalf("fresh result=%#v", fresh)
	}
	if err := fixture.chain.AttachFinalization(
		t.Context(), fresh.ReceiptIDs, "evaluation-1", "audit-1"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.chain.AttachFinalization(
		t.Context(), fresh.ReceiptIDs, "evaluation-1", "audit-1"); err != nil {
		t.Fatalf("idempotent finalization: %v", err)
	}
	if err := fixture.chain.AttachFinalization(
		t.Context(), fresh.ReceiptIDs, "evaluation-2", "audit-1"); !errors.Is(err, ErrToolChainConflict) {
		t.Fatalf("overwrite error=%v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := newToolChainFixture(t, path)
	reopened.now = fixture.now.Add(time.Minute)
	reopened.chain.now = func() time.Time { return reopened.now }
	final.RulesetFingerprint = correlationDigest("ruleset-b")
	replay, err := reopened.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Status != ToolChainObserveReplay || !replay.SuppressTelemetry ||
		replay.StableActionID != fresh.StableActionID || replay.DeniedMask != fresh.DeniedMask ||
		len(replay.ReceiptIDs) != len(fresh.ReceiptIDs) {
		t.Fatalf("restart replay=%#v want stable action %s", replay, fresh.StableActionID)
	}
	for i := range fresh.ReceiptIDs {
		if replay.ReceiptIDs[i] != fresh.ReceiptIDs[i] {
			t.Fatalf("replay receipt IDs=%v want %v", replay.ReceiptIDs, fresh.ReceiptIDs)
		}
	}
}

func TestToolChainObserveReplayModeTransitionsAreMonotonic(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainSecretReadThenEgress
	resultBit, _ := guardrail.ToolChainResultMask(chainID)

	first := fixture.seed(t, "mode-transition", correlationDigest("mode-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "mode-transition", correlationDigest("mode-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)

	observed, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != ToolChainObserveFresh ||
		observed.DetectedMask != resultBit ||
		observed.EnforcementSafeMask != resultBit ||
		observed.DeniedMask != 0 ||
		len(observed.ReceiptIDs) != 0 ||
		observed.SuppressTelemetry {
		t.Fatalf("observe result=%#v", observed)
	}

	final.DenyEligible = true
	upgraded, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Status != ToolChainObserveFresh ||
		upgraded.DeniedMask != resultBit ||
		len(upgraded.ReceiptIDs) != 1 ||
		upgraded.StableActionID == "" ||
		upgraded.SuppressTelemetry {
		t.Fatalf("observe-to-action upgrade=%#v", upgraded)
	}

	final.DenyEligible = false
	replay, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Status != ToolChainObserveReplay ||
		replay.DeniedMask != upgraded.DeniedMask ||
		replay.StableActionID != upgraded.StableActionID ||
		!slices.Equal(replay.ReceiptIDs, upgraded.ReceiptIDs) ||
		!replay.SuppressTelemetry {
		t.Fatalf("action-to-observe replay=%#v want=%#v", replay, upgraded)
	}
	var deliveries int
	if err := fixture.store.db.QueryRow(`SELECT delivery_count
		FROM guardrail_chain_deny_receipts`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 2 {
		t.Fatalf("upgraded receipt deliveries=%d want 2", deliveries)
	}
}

func TestToolChainObserveSerializesDuplicateAndIsolatesPartitions(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainSecretManagerReadThenEgress
	first := fixture.seed(t, "shared", correlationDigest("serial-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	otherGeneration := fixture.seed(t, "shared", correlationDigest("other-generation"))
	otherGeneration.RulesetFingerprint = correlationDigest("ruleset-b")
	otherGeneration.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	otherGeneration.DenyEligible = true
	if result, err := fixture.chain.Observe(t.Context(), otherGeneration); err != nil ||
		result.DetectedMask != 0 || result.DeniedMask != 0 {
		t.Fatalf("ruleset generation isolation=%#v err=%v", result, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "shared", correlationDigest("serial-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true

	const callers = 8
	results := make(chan ToolChainObserveResult, callers)
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := fixture.chain.Observe(t.Context(), final)
			results <- result
			errs <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	fresh, replay := 0, 0
	for result := range results {
		switch result.Status {
		case ToolChainObserveFresh:
			fresh++
		case ToolChainObserveReplay:
			replay++
		}
	}
	if fresh != 1 || replay != callers-1 {
		t.Fatalf("fresh/replay=%d/%d", fresh, replay)
	}
	var deliveries int
	if err := fixture.store.db.QueryRow(`SELECT delivery_count
		FROM guardrail_chain_deny_receipts`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != callers {
		t.Fatalf("delivery count=%d want %d", deliveries, callers)
	}

	fixture.now = fixture.now.Add(time.Second)
	isolated := fixture.seed(t, "isolated", correlationDigest("isolated-final"))
	isolated.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	isolated.DenyEligible = true
	result, err := fixture.chain.Observe(t.Context(), isolated)
	if err != nil || result.DetectedMask != 0 || result.DeniedMask != 0 {
		t.Fatalf("partition isolation=%#v err=%v", result, err)
	}
	fixture.instance = mustCorrelationInstance(
		t, fixture.correl, "chain-fixture-other", ConnectorCustodyHookOnly)
	fixture.now = fixture.now.Add(time.Second)
	otherConnector := fixture.seed(t, "shared", correlationDigest("other-connector-final"))
	otherConnector.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	otherConnector.DenyEligible = true
	result, err = fixture.chain.Observe(t.Context(), otherConnector)
	if err != nil || result.DetectedMask != 0 || result.DeniedMask != 0 {
		t.Fatalf("connector isolation=%#v err=%v", result, err)
	}
}

func TestToolChainObserveNoJoinBoundsExpiryAndClose(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	missing, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	noJoin, err := fixture.chain.Observe(t.Context(), ToolChainObserveInput{
		SemanticEventID: missing, ConnectorInstanceID: fixture.instance.ConnectorInstanceID,
		InputFingerprint:   correlationDigest("missing"),
		RulesetFingerprint: correlationDigest("rules"),
		Projection:         guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusNotApplicable},
	})
	if err != nil || noJoin.Status != ToolChainObserveNoJoin {
		t.Fatalf("no join=%#v err=%v", noJoin, err)
	}
	ambiguous := fixture.seed(t, "ambiguous-a", correlationDigest("ambiguous"))
	tx, _, err := fixture.correl.BeginExistingOccurrence(t.Context(), ambiguous.SemanticEventID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.PutIdentifier(t.Context(), CorrelationIdentifier{
		SemanticEventID:     ambiguous.SemanticEventID,
		ConnectorInstanceID: fixture.instance.ConnectorInstanceID,
		Namespace:           "fixture", Kind: CorrelationIdentifierSession,
		ValueDigest: correlationDigest("ambiguous-b"), NormalizedValue: "ambiguous-b",
		SourceField: "session", Origin: CorrelationOriginReported,
		ProfileVersion: fixture.instance.ProfileVersion, ObservedAt: fixture.now,
	}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	ambiguous.Projection = guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
	if result, err := fixture.chain.Observe(t.Context(), ambiguous); err != nil ||
		result.Status != ToolChainObserveNoJoin {
		t.Fatalf("ambiguous sessions=%#v err=%v", result, err)
	}

	fixture.chain.maxEvents = 2
	fixture.chain.maxPartitions = 1
	fixture.chain.receiptTTL = time.Minute
	fixture.chain.maxHorizon = 2 * time.Minute
	chainID := guardrail.ToolChainWorkloadIdentityThenLateralExec
	first := fixture.seed(t, "bounded", correlationDigest("bounded-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "bounded", correlationDigest("bounded-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	denied, err := fixture.chain.Observe(t.Context(), final)
	if err != nil || denied.DeniedMask == 0 {
		t.Fatalf("bounded deny=%#v err=%v", denied, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	neutral := fixture.seed(t, "evictor", correlationDigest("evictor-first"))
	neutral.Projection = guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
	if _, err := fixture.chain.Observe(t.Context(), neutral); err != nil {
		t.Fatal(err)
	}
	if replay, err := fixture.chain.Observe(t.Context(), final); err != nil ||
		replay.Status != ToolChainObserveReplay || replay.DeniedMask != denied.DeniedMask {
		t.Fatalf("receipt replay after partition eviction=%#v err=%v", replay, err)
	}
	fixture.now = fixture.now.Add(2 * time.Minute)
	for i := 0; i < 2; i++ {
		fixture.now = fixture.now.Add(time.Second)
		neutral = fixture.seed(t, "evictor",
			correlationDigest("evictor-"+string(rune('a'+i))))
		neutral.Projection = guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
		if _, err := fixture.chain.Observe(t.Context(), neutral); err != nil {
			t.Fatal(err)
		}
	}
	var events, receipts int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_events
		WHERE session_value_digest=?`, correlationDigest("evictor")).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(
		`SELECT COUNT(*) FROM guardrail_chain_deny_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 2 || receipts != 0 {
		t.Fatalf("bounded events/receipts=%d/%d want 2/0", events, receipts)
	}
	fixture.chain.maxPartitions = 2
	for i := 0; i < 2; i++ {
		fixture.now = fixture.now.Add(time.Second)
		input := fixture.seed(t, "partition-"+string(rune('a'+i)),
			correlationDigest("partition-"+string(rune('a'+i))))
		input.Projection = guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
		if _, err := fixture.chain.Observe(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	var partitions int
	if err := fixture.store.db.QueryRow(
		`SELECT COUNT(*) FROM guardrail_chain_partitions`).Scan(&partitions); err != nil {
		t.Fatal(err)
	}
	if partitions != 2 {
		t.Fatalf("partition count=%d want 2", partitions)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.chain.Observe(t.Context(), neutral); err == nil {
		t.Fatal("closed store accepted observation")
	}
}

func TestToolChainFinalizationRollsBackAsOneTransaction(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainGuardrailsOffThenEgress
	first := fixture.seed(t, "rollback", correlationDigest("rollback-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "rollback", correlationDigest("rollback-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	result, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	missing := "gcr_" + stringsOf("f", 64)
	if err := fixture.chain.AttachFinalization(t.Context(),
		[]string{result.ReceiptIDs[0], missing}, "evaluation-rollback", ""); !errors.Is(err, ErrToolChainConflict) {
		t.Fatalf("missing-receipt error=%v", err)
	}
	var evaluationID *string
	if err := fixture.store.db.QueryRow(`SELECT evaluation_id
		FROM guardrail_chain_deny_receipts WHERE receipt_id=?`,
		result.ReceiptIDs[0]).Scan(&evaluationID); err != nil {
		t.Fatal(err)
	}
	if evaluationID != nil {
		t.Fatalf("partial finalization committed: %q", *evaluationID)
	}
}

func TestToolChainCorruptWindowResetsWithoutDeny(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainSecretReadThenEgress
	first := fixture.seed(t, "corrupt-window", correlationDigest("corrupt-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_events
		SET projection_fingerprint=? WHERE semantic_event_id=?`,
		correlationDigest("forged-projection"), string(first.SemanticEventID)); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "corrupt-window", correlationDigest("corrupt-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	result, err := fixture.chain.Observe(t.Context(), final)
	if err != nil {
		t.Fatal(err)
	}
	if result.DetectedMask != 0 || result.DeniedMask != 0 {
		t.Fatalf("corrupt window produced a chain outcome: %#v", result)
	}
	var count int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_events
		WHERE session_value_digest=?`, correlationDigest("corrupt-window")).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("reset window rows=%d want current event only", count)
	}
}

func TestToolChainCorruptReceiptCannotReplayDeny(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainGuardrailsOffThenEgress
	first := fixture.seed(t, "corrupt-receipt", correlationDigest("receipt-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "corrupt-receipt", correlationDigest("receipt-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	if result, err := fixture.chain.Observe(t.Context(), final); err != nil ||
		result.DeniedMask == 0 {
		t.Fatalf("fresh deny=%#v err=%v", result, err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE guardrail_chain_deny_receipts
		SET chain_fingerprint=?`, correlationDigest("forged-chain")); err != nil {
		t.Fatal(err)
	}
	replay, err := fixture.chain.Observe(t.Context(), final)
	if !errors.Is(err, ErrToolChainIntegrity) || replay.DeniedMask != 0 {
		t.Fatalf("corrupt receipt replay=%#v err=%v", replay, err)
	}
}

func TestToolChainObserveRetriesWholeTransactionOnBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	fixture := newToolChainFixture(t, path)
	input := fixture.seed(t, "busy", correlationDigest("busy-event"))
	input.Projection = guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
	if _, err := fixture.store.db.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatal(err)
	}
	external, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer external.Close() //nolint:errcheck
	connection, err := external.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close() //nolint:errcheck
	if _, err := connection.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	capture := &sqliteBusyObserverCapture{}
	fixture.store.BindSQLiteBusyObservabilityV8(capture)
	released := make(chan error, 1)
	go func() {
		time.Sleep(40 * time.Millisecond)
		_, err := connection.ExecContext(t.Context(), `COMMIT`)
		released <- err
	}()
	if result, err := fixture.chain.Observe(t.Context(), input); err != nil ||
		result.Status != ToolChainObserveFresh {
		t.Fatalf("busy retry result=%#v err=%v", result, err)
	}
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if len(capture.operations) == 0 {
		t.Fatal("whole-operation retry did not report SQLite contention")
	}
}
