// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func toolChainRootDigestForTest(t *testing.T, fixture *toolChainFixture, person, root string) string {
	t.Helper()
	digest, err := ToolChainRootScopeDigest(fixture.instance.ConnectorInstanceID, "990", person, root)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func rootRepositoryForTest(t *testing.T, fixture *toolChainFixture, digest string) *ToolChainRepository {
	t.Helper()
	repo, err := fixture.store.ToolChainRootRepository(t.Context(), digest)
	if err != nil {
		t.Fatal(err)
	}
	repo.now = func() time.Time { return fixture.now }
	return repo
}

func sqliteTableNames(t *testing.T, db *sql.DB, like string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? ORDER BY name`, like)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

func sqliteColumns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name, type, "notnull", COALESCE(dflt_value, ''), pk FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name, kind, dflt string
		var notNull, pk int
		if err := rows.Scan(&name, &kind, &notNull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, fmt.Sprintf("%s %s %d %s %d", name, kind, notNull, dflt, pk))
	}
	return columns
}

// The root tables are created on first use, never by a migration: the
// schema version does not move, so a 1.0.4 or 1.0.5 binary reads the store.
// They carry no RESTRICT foreign key.
func TestToolChainRootTablesAreCreatedOnFirstUseWithoutMovingTheSchema(t *testing.T) {
	fixture := newToolChainFixture(t, filepath.Join(t.TempDir(), "audit.db"))
	if names := sqliteTableNames(t, fixture.store.db, "guardrail_chain_root_%"); len(names) != 0 {
		t.Fatalf("root tables exist before first use: %v", names)
	}
	before, err := fixture.store.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	digest := toolChainRootDigestForTest(t, fixture, "1001", "root-a")
	repo := rootRepositoryForTest(t, fixture, digest)
	if repo.Scope() != ToolChainScopeRoot || fixture.chain.Scope() != ToolChainScopeSession {
		t.Fatalf("scopes = %s, %s", repo.Scope(), fixture.chain.Scope())
	}
	if _, err := fixture.store.ToolChainRootRepository(t.Context(), digest); err != nil {
		t.Fatalf("second first use: %v", err)
	}
	names := sqliteTableNames(t, fixture.store.db, "guardrail_chain_root_%")
	want := slices.Clone(toolChainRootTableNames)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("root tables = %v, want %v", names, want)
	}
	after, err := fixture.store.SchemaVersion()
	if err != nil || after != before || after != len(migrations) {
		t.Fatalf("schema version %d -> %d (want %d unchanged), err=%v", before, after, len(migrations), err)
	}
	for _, table := range toolChainRootTableNames {
		var ddl string
		if err := fixture.store.db.QueryRow(`SELECT sql FROM sqlite_master WHERE name=?`, table).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ddl, "RESTRICT") {
			t.Errorf("%s keeps a RESTRICT foreign key:\n%s", table, ddl)
		}
		rows, err := fixture.store.db.Query(`SELECT "table", on_delete FROM pragma_foreign_key_list(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var parent, onDelete string
			if err := rows.Scan(&parent, &onDelete); err != nil {
				t.Fatal(err)
			}
			if onDelete != "CASCADE" {
				t.Errorf("%s references %s ON DELETE %s", table, parent, onDelete)
			}
		}
		_ = rows.Close()
	}
	if _, err := fixture.store.ToolChainRootRepository(t.Context(), "not-a-digest"); err == nil {
		t.Fatal("a malformed root digest was accepted")
	}
}

// The root DDL is generated from the session DDL; the two sets stay equal
// column by column (a migration that changes a session table must change an
// existing root table too).
func TestToolChainRootTablesMirrorSessionTables(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1001", "root-a"))
	for _, root := range toolChainRootTableNames {
		session := strings.Replace(root, "guardrail_chain_root_", "guardrail_chain_", 1)
		if got, want := sqliteColumns(t, fixture.store.db, root), sqliteColumns(t, fixture.store.db, session); !slices.Equal(got, want) {
			t.Errorf("%s columns differ from %s:\n got %v\nwant %v", root, session, got, want)
		}
	}
	var sessionIndexes, rootIndexes int
	if err := fixture.store.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND sql IS NOT NULL
			AND tbl_name LIKE 'guardrail_chain_%' AND tbl_name NOT LIKE 'guardrail_chain_root_%'),
		(SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND sql IS NOT NULL
			AND tbl_name LIKE 'guardrail_chain_root_%')`).Scan(&sessionIndexes, &rootIndexes); err != nil {
		t.Fatal(err)
	}
	if sessionIndexes == 0 || rootIndexes != sessionIndexes {
		t.Fatalf("indexes: session %d, root %d", sessionIndexes, rootIndexes)
	}
}

// One piece of work split across two sessions: the session windows never
// complete the chain, the root window does.
func TestToolChainRootScopeFollowsWorkAcrossSessions(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	root := rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1001", "root-a"))
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	first := fixture.seed(t, "sub-agent-a", correlationDigest("root-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	for _, repo := range []*ToolChainRepository{fixture.chain, root} {
		if result, err := repo.Observe(t.Context(), first); err != nil || result.DetectedMask != 0 {
			t.Fatalf("%s step one result=%+v err=%v", repo.Scope(), result, err)
		}
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "parent", correlationDigest("root-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	session, err := fixture.chain.Observe(t.Context(), final)
	if err != nil || session.DetectedMask != 0 {
		t.Fatalf("the session window completed a chain split across sessions: %+v err=%v", session, err)
	}
	result, err := root.Observe(t.Context(), final)
	if err != nil || !slices.Contains(result.DetectedChainIDs, chainID) ||
		!slices.Contains(result.DeniedChainIDs, chainID) || len(result.ReceiptIDs) != 1 {
		t.Fatalf("root window result=%+v err=%v", result, err)
	}
	if err := root.AttachFinalization(t.Context(), result.ReceiptIDs, "eval-root", ""); err != nil {
		t.Fatalf("root receipt finalization: %v", err)
	}
	if err := fixture.chain.AttachFinalization(t.Context(), result.ReceiptIDs, "eval-root", ""); err == nil {
		t.Fatal("the session repository finalized a root receipt")
	}
	// An exact replay reproduces the root denial from the root receipts.
	replay, err := root.Observe(t.Context(), final)
	if err != nil || replay.Status != ToolChainObserveReplay || replay.DeniedMask != result.DeniedMask {
		t.Fatalf("root replay=%+v err=%v", replay, err)
	}
	if countToolChainRows(t, fixture.store.db, "guardrail_chain_deny_receipts") != 0 ||
		countToolChainRows(t, fixture.store.db, "guardrail_chain_root_deny_receipts") != 1 {
		t.Fatal("the root receipt is not kept in the root tables only")
	}
	// Another root id (or another person) is another partition.
	other := rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1002", "root-a"))
	fixture.now = fixture.now.Add(time.Second)
	again := fixture.seed(t, "parent", correlationDigest("root-other"))
	again.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	if result, err := other.Observe(t.Context(), again); err != nil || result.DetectedMask != 0 {
		t.Fatalf("another person's root window completed the chain: %+v err=%v", result, err)
	}
}

// Pending proposals follow the same split: a download proposed and confirmed
// in one session is a predecessor in the root window only.
func TestToolChainRootScopePendingPromotesIntoTheRootWindow(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	root := rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1001", "root-a"))
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	pre := fixture.seed(t, "sub-agent-a", correlationDigest("root-pre"))
	invocation := correlationDigest("root-invocation")
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		PreSemanticEventID: pre.SemanticEventID, PreInputFingerprint: pre.InputFingerprint,
		RulesetFingerprint: pre.RulesetFingerprint,
		Projection:         toolChainProjection(t, []string{chainID}, 1, true),
	}
	if result, err := root.PreparePending(t.Context(), prepare); err != nil || result.Status != ToolChainPendingPrepared {
		t.Fatalf("root prepare=%+v err=%v", result, err)
	}
	if countToolChainRows(t, fixture.store.db, "guardrail_chain_pending_actions") != 0 ||
		countToolChainRows(t, fixture.store.db, "guardrail_chain_root_pending_actions") != 1 {
		t.Fatal("the root proposal is not kept in the root tables only")
	}
	fixture.now = fixture.now.Add(time.Second)
	post := fixture.seed(t, "sub-agent-a", correlationDigest("root-post"))
	resolved, err := root.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID: post.ConnectorInstanceID, ToolInvocationDigest: invocation,
		Outcome: ToolChainPendingOutcomeSuccess, RulesetFingerprint: post.RulesetFingerprint,
		TerminalSemanticEventID: post.SemanticEventID, TerminalInputFingerprint: post.InputFingerprint,
	})
	if err != nil || resolved.Status != ToolChainPendingResolved {
		t.Fatalf("root resolve=%+v err=%v", resolved, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "parent", correlationDigest("root-pending-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	if result, err := root.Observe(t.Context(), final); err != nil || !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("root window after the promoted proposal: %+v err=%v", result, err)
	}
	if result, err := fixture.chain.Observe(t.Context(), final); err != nil || result.DetectedMask != 0 {
		t.Fatalf("the session window saw the root proposal: %+v err=%v", result, err)
	}
}

func TestToolChainRootScopeDigestIsUnambiguousAndScoped(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	instance := fixture.instance.ConnectorInstanceID
	digest := func(account, person, root string) string {
		value, err := ToolChainRootScopeDigest(instance, account, person, root)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	base := digest("990", "1001", "r-1")
	for name, other := range map[string]string{
		"account": digest("991", "1001", "r-1"),
		"person":  digest("990", "1002", "r-1"),
		"root":    digest("990", "1001", "r-2"),
		"shifted": digest("99", "01001", "r-1"),
	} {
		if other == base {
			t.Errorf("%s does not change the root digest", name)
		}
	}
	if digest("ab", "c", "r") == digest("a", "bc", "r") {
		t.Error("the components are not length-prefixed")
	}
	if validateSHA256("root digest", base, true) != nil {
		t.Errorf("digest %q is not a lowercase SHA-256", base)
	}
	for name, args := range map[string][4]string{
		"bad instance": {"x", "990", "1001", "r"},
		"no account":   {string(instance), "", "1001", "r"},
		"no person":    {string(instance), "990", "", "r"},
		"no root":      {string(instance), "990", "1001", ""},
		"control":      {string(instance), "990", "1001", "r\n"},
		"too long":     {string(instance), "990", "1001", strings.Repeat("r", toolChainRootIDMaxBytes+1)},
	} {
		if _, err := ToolChainRootScopeDigest(ConnectorInstanceID(args[0]), args[1], args[2], args[3]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Root partitions have their own LRU: filling the root set never evicts
// session state.
func TestToolChainRootScopeKeepsItsOwnPartitionBound(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	session := fixture.seed(t, "kept-session", correlationDigest("lru-session"))
	session.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.Observe(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		fixture.now = fixture.now.Add(time.Second)
		repo := rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1001", fmt.Sprintf("root-%d", i)))
		repo.maxPartitions = 2
		event := fixture.seed(t, fmt.Sprintf("lru-%d", i), correlationDigest(fmt.Sprintf("lru-root-%d", i)))
		event.Projection = toolChainProjection(t, []string{chainID}, 1, true)
		if _, err := repo.Observe(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	if got := countToolChainRows(t, fixture.store.db, "guardrail_chain_root_partitions"); got != 2 {
		t.Fatalf("root partitions = %d, want the bound 2", got)
	}
	if countToolChainRows(t, fixture.store.db, "guardrail_chain_partitions") != 1 ||
		countToolChainRows(t, fixture.store.db, "guardrail_chain_events") != 1 {
		t.Fatal("root eviction touched the session state")
	}
}

// A 1.0.5 (or 1.0.4) binary after a rollback runs its retention without
// knowing the root tables: it deletes the session chain rows, then the old
// correlation events (the same statements as the session stages here). The
// root rows that name those events go with them; nothing fails.
func TestToolChainRootRowsDoNotBlockOlderRetention(t *testing.T) {
	fixture := newToolChainFixture(t, filepath.Join(t.TempDir(), "audit.db"))
	root := rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1001", "root-a"))
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	for i := range 3 {
		event := fixture.seed(t, fmt.Sprintf("old-%d", i), correlationDigest(fmt.Sprintf("old-root-%d", i)))
		event.Projection = toolChainProjection(t, []string{chainID}, 1, true)
		for _, repo := range []*ToolChainRepository{fixture.chain, root} {
			if _, err := repo.Observe(t.Context(), event); err != nil {
				t.Fatal(err)
			}
		}
		fixture.now = fixture.now.Add(time.Second)
	}
	if countToolChainRows(t, fixture.store.db, "guardrail_chain_root_events") != 3 {
		t.Fatal("root events were not written")
	}
	future := fixture.now.Add(400 * 24 * time.Hour)
	eventsBefore := countRetentionRows(t, fixture.store.db, "correlation_events")
	const batch = 1000
	for _, stage := range []struct {
		class RetentionTableClass
		args  []any
	}{
		{RetentionGuardrailChainReceipts, []any{unixNano(future), batch}},
		{RetentionGuardrailChainEvents, []any{unixNano(future), guardrail.ToolChainMaxEvents, guardrail.ToolChainMaxEvents, batch}},
		{RetentionGuardrailChainPartitions, []any{unixNano(future), batch}},
		{RetentionCorrelationReceipts, []any{unixNano(future), batch}},
		{RetentionCorrelationCursors, []any{unixNano(future), batch}},
		{RetentionCorrelationPending, []any{unixNano(future), batch}},
		{RetentionCorrelationRelationships, []any{unixNano(future), unixNano(future), unixNano(future), batch}},
		{RetentionCorrelationEvents, []any{unixNano(future), unixNano(future), batch}},
	} {
		statement, err := correlationRetentionDeleteStatement(stage.class)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.db.Exec(statement, stage.args...); err != nil {
			t.Fatalf("older retention %s failed over root rows: %v", stage.class, err)
		}
	}
	if countRetentionRows(t, fixture.store.db, "correlation_events") >= eventsBefore {
		t.Fatal("the older retention deleted no correlation event")
	}
	var orphans int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_root_events
		WHERE semantic_event_id NOT IN (SELECT semantic_event_id FROM correlation_events)`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("root rows outlived their events: %d err=%v", orphans, err)
	}
	var violations int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil || violations != 0 {
		t.Fatalf("foreign key violations=%d err=%v", violations, err)
	}
}

// The 1.0.6 reaper bounds the root set like the session set and counts it
// under the session classes.
func TestRetentionBoundsTheRootChainTables(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
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
		instance: mustCorrelationInstance(t, correl, "retention-root-chain", ConnectorCustodyHookOnly),
		now:      now.Add(-2 * 24 * time.Hour),
	}
	chain.now = func() time.Time { return fixture.now }
	root := rootRepositoryForTest(t, fixture, toolChainRootDigestForTest(t, fixture, "1001", "root-a"))
	event := fixture.seed(t, "old-root", correlationDigest("retention-root"))
	event.Projection = toolChainProjection(t, []string{guardrail.ToolChainStagedReverseShellPersistence}, 1, true)
	if _, err := root.Observe(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	reaper := newRetentionReaperAt(t, store, judge, 1, now, RetentionOptions{}, retentionHooks{})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if countToolChainRows(t, store.db, "guardrail_chain_root_events") != 0 ||
		countToolChainRows(t, store.db, "guardrail_chain_root_partitions") != 0 {
		t.Fatal("old root chain state survived retention")
	}
	if result.RowsDeleted[RetentionGuardrailChainEvents] < 1 || result.RowsDeleted[RetentionGuardrailChainPartitions] < 1 {
		t.Fatalf("root deletes not counted: %v", result.RowsDeleted)
	}
}

// Stores written by 1.0.2 and 1.0.3 (36 migrations), 1.0.4 (37) and 1.0.5
// (38) keep their live session chains across the upgrade, and the root set
// starts empty beside them.
func TestToolChainRootScopeUpgradeFromReleasedStores(t *testing.T) {
	for _, released := range []struct {
		name       string
		migrations int
	}{{"1.0.2", 36}, {"1.0.3", 36}, {"1.0.4", 37}, {"1.0.5", 38}} {
		t.Run(released.name, func(t *testing.T) {
			if released.migrations > len(migrations) {
				t.Fatalf("%s has more migrations than this build", released.name)
			}
			path := filepath.Join(t.TempDir(), "audit.db")
			old, err := NewStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := old.db.Exec(`CREATE TABLE schema_version (
				version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < released.migrations; i++ {
				if err := old.applyMigration(i+1, migrations[i]); err != nil {
					t.Fatalf("%s migration %d: %v", released.name, i+1, err)
				}
			}
			// The released binary serves this store: a live session chain.
			old.ready.Store(true)
			fixture := toolChainFixtureOn(t, old, time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
			chainID := guardrail.ToolChainStagedReverseShellPersistence
			first := fixture.seed(t, "live", correlationDigest("upgrade-first-"+released.name))
			first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
			if _, err := fixture.chain.Observe(t.Context(), first); err != nil {
				t.Fatal(err)
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}

			upgraded, err := NewStore(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = upgraded.Close() })
			if err := upgraded.Init(); err != nil {
				t.Fatalf("upgrade from %s: %v", released.name, err)
			}
			next := toolChainFixtureOn(t, upgraded, fixture.now.Add(time.Second))
			root := rootRepositoryForTest(t, next, toolChainRootDigestForTest(t, next, "1001", "root-a"))
			if countToolChainRows(t, upgraded.db, "guardrail_chain_root_events") != 0 {
				t.Fatal("the root set does not start empty")
			}
			final := next.seed(t, "live", correlationDigest("upgrade-final-"+released.name))
			final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
			if result, err := next.chain.Observe(t.Context(), final); err != nil || !slices.Contains(result.DetectedChainIDs, chainID) {
				t.Fatalf("the live session chain was lost by the upgrade: %+v err=%v", result, err)
			}
			if result, err := root.Observe(t.Context(), final); err != nil || result.DetectedMask != 0 {
				t.Fatalf("the root window saw pre-upgrade session state: %+v err=%v", result, err)
			}
			if version, err := upgraded.SchemaVersion(); err != nil || version != len(migrations) {
				t.Fatalf("schema version=%d want=%d err=%v", version, len(migrations), err)
			}
		})
	}
}

// countToolChainRows counts a chain table of either set.
func countToolChainRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	session := strings.Replace(table, "guardrail_chain_root_", "guardrail_chain_", 1)
	if !knownTables[session] || !strings.HasPrefix(session, "guardrail_chain_") {
		t.Fatalf("not a chain table: %s", table)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func toolChainFixtureOn(t *testing.T, store *Store, now time.Time) *toolChainFixture {
	t.Helper()
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
		instance: mustCorrelationInstance(t, correl, "chain-upgrade", ConnectorCustodyHookOnly),
		now:      now,
	}
	chain.now = func() time.Time { return fixture.now }
	return fixture
}
