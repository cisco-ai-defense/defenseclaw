// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Root-scope tool-call chains (issue #1391, guardrail.chains.root_scope).
//
// A ToolChainRepository keeps its state in one of two table sets. The session
// set (guardrail_chain_*) is the per-session state every release since 1.0.0
// reads and writes. The root set (guardrail_chain_root_*) holds the same state
// for one piece of work a trusted connector follows across resumed sessions
// and sub-agents, keyed on a root scope digest instead of the session digest.
//
// The root tables are generated from the session DDL: the session migrations
// run through toolChainRootDDL, which renames the tables and indexes and turns
// every ON DELETE RESTRICT into ON DELETE CASCADE. They are created on first
// use, under the store's lifecycle lock (the lock Init migrates under), and
// the schema version does not move, so a 1.0.4 or 1.0.5 binary opened on the
// store after a rollback never reads them. With no RESTRICT foreign key, that
// binary's retention deletes correlation events without knowing the root
// tables, and the root rows that name those events go with them.
//
// A later migration that changes a session chain table must bring the same
// change to an existing root table (TestToolChainRootTablesMirrorSessionTables
// compares the two sets column by column).

// ToolChainScope names the table set of a repository.
type ToolChainScope string

const (
	ToolChainScopeSession ToolChainScope = "session"
	ToolChainScopeRoot    ToolChainScope = "root"

	toolChainRootScopeDomain = "defenseclaw.chain.root.v1"
	toolChainRootIDMaxBytes  = 512
)

// toolChainTableSet names the tables every repository statement uses. The
// statements are written against the session set; rewrite renames them.
type toolChainTableSet struct {
	scope   ToolChainScope
	rewrite *strings.Replacer
}

var (
	toolChainSessionTables = toolChainTableSet{scope: ToolChainScopeSession}
	toolChainRootTables    = toolChainTableSet{
		scope:   ToolChainScopeRoot,
		rewrite: strings.NewReplacer("guardrail_chain_", "guardrail_chain_root_"),
	}
)

// toolChainRootTableNames are the root tables, in creation order.
var toolChainRootTableNames = []string{
	"guardrail_chain_root_partitions",
	"guardrail_chain_root_events",
	"guardrail_chain_root_deny_receipts",
	"guardrail_chain_root_pending_actions",
	"guardrail_chain_root_pending_boundaries",
	"guardrail_chain_root_terminal_resets",
	"guardrail_chain_root_cutoff_barriers",
}

// sql names the repository's tables in a statement written against the
// session set. Every statement of the repository goes through it.
func (repo *ToolChainRepository) sql(query string) string {
	if repo == nil || repo.tables.rewrite == nil {
		return query
	}
	return repo.tables.rewrite.Replace(query)
}

// Scope reports the repository's table set.
func (repo *ToolChainRepository) Scope() ToolChainScope {
	if repo == nil || repo.tables.scope == "" {
		return ToolChainScopeSession
	}
	return repo.tables.scope
}

// scopeDigest is the partition key of an event in the repository's scope:
// the event's exact session digest, or, for the root set, the repository's
// root digest. A root event must still join exactly one session, so the root
// set takes no event the session set would refuse.
func (repo *ToolChainRepository) scopeDigest(
	ctx context.Context,
	tx *sql.Tx,
	eventID SemanticEventID,
	connectorID ConnectorInstanceID,
) (string, bool, error) {
	session, joined, err := loadExactToolChainSession(ctx, tx, eventID, connectorID)
	if err != nil || !joined || repo.tables.rewrite == nil {
		return session, joined, err
	}
	return repo.rootDigest, true, nil
}

// ToolChainRootScopeDigest is the root partition key of one piece of work:
// SHA-256 over the length-prefixed namespace, connector instance, trusted
// connector account id, person id and root session id. A root id from one
// connector or person can never name another's partition, and no two inputs
// share an encoding.
func ToolChainRootScopeDigest(
	connectorInstanceID ConnectorInstanceID,
	connectorAccountID, personID, rootSessionID string,
) (string, error) {
	if err := validateUUIDv7("connector instance id", string(connectorInstanceID)); err != nil {
		return "", err
	}
	for _, part := range [...]struct{ field, value string }{
		{"trusted connector account id", connectorAccountID},
		{"acting-for person id", personID},
		{"root session id", rootSessionID},
	} {
		if err := validateBoundedIdentifier(part.field, part.value, true, toolChainRootIDMaxBytes); err != nil {
			return "", err
		}
	}
	hash := sha256.New()
	for _, part := range []string{
		toolChainRootScopeDomain, string(connectorInstanceID), connectorAccountID, personID, rootSessionID,
	} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ToolChainRootRepository returns the repository of one root scope. The root
// tables are created on the first call of the process (ensureToolChainRootTables).
func (s *Store) ToolChainRootRepository(ctx context.Context, rootDigest string) (*ToolChainRepository, error) {
	if ctx == nil {
		return nil, errors.New("audit: tool-chain context is required")
	}
	if err := validateSHA256("tool-chain root scope digest", rootDigest, true); err != nil {
		return nil, err
	}
	repo, err := s.ToolChainRepository()
	if err != nil {
		return nil, err
	}
	if err := s.ensureToolChainRootTables(ctx); err != nil {
		return nil, err
	}
	repo.tables, repo.rootDigest = toolChainRootTables, rootDigest
	return repo, nil
}

// ensureToolChainRootTables creates the root tables once per store, holding
// the lifecycle lock exclusively as Init does while it migrates: no store
// transaction runs while the tables are created. Another process creating
// them at the same time is serialized by SQLite (CREATE ... IF NOT EXISTS in
// one transaction).
func (s *Store) ensureToolChainRootTables(ctx context.Context) error {
	if s.toolChainRootTablesReady.Load() {
		return nil
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.closed || !s.ready.Load() {
		return errors.New("audit: ready tool-chain store is required")
	}
	if s.toolChainRootTablesReady.Load() {
		return nil
	}
	err := retryBusyObserved(ctx, "guardrail_chain_root_tables_create",
		s.sqliteBusyObservabilityV8(), func() error {
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback() //nolint:errcheck
			if err := createToolChainRootTables(tx); err != nil {
				return err
			}
			return tx.Commit()
		})
	if err != nil {
		return fmt.Errorf("audit: create root-scope tool-chain state: %w", err)
	}
	s.toolChainRootTablesReady.Store(true)
	return nil
}

// toolChainSessionMigrations build the session chain tables in their current
// shape; the root set is built by running them again through toolChainRootDDL.
var toolChainSessionMigrations = []func(dbExecer) error{
	migrateToolChainState,
	migrateToolChainPendingState,
	migrateToolChainSQLValueSourceState,
	migrateToolChainReturnedCredentialSourceState,
}

func createToolChainRootTables(ex dbExecer) error {
	ddl := toolChainRootDDL{ex: ex}
	for _, migrate := range toolChainSessionMigrations {
		if err := migrate(ddl); err != nil {
			return err
		}
	}
	return nil
}

// toolChainRootDDL runs session chain DDL against the root set.
type toolChainRootDDL struct{ ex dbExecer }

func toolChainRootDDLSQL(query string) string {
	return strings.ReplaceAll(toolChainRootTables.rewrite.Replace(query),
		"ON DELETE RESTRICT", "ON DELETE CASCADE")
}

func (ddl toolChainRootDDL) Exec(query string, args ...any) (sql.Result, error) {
	return ddl.ex.Exec(toolChainRootDDLSQL(query), args...)
}

func (ddl toolChainRootDDL) Query(query string, args ...any) (*sql.Rows, error) {
	return ddl.ex.Query(toolChainRootDDLSQL(query), args...)
}

func (ddl toolChainRootDDL) QueryRow(query string, args ...any) *sql.Row {
	return ddl.ex.QueryRow(toolChainRootDDLSQL(query), args...)
}

// toolChainRootTablesExist reports whether this store has the root set (made
// by any process on it).
func toolChainRootTablesExist(ex dbExecer) (bool, error) {
	return tableExists(ex, toolChainRootTableNames[0])
}
