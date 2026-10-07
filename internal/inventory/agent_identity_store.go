// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// agentIdentitiesDDL is the agent_identities table of inventory.db v4. The
// v4 migration creates the same table; both statements are IF NOT EXISTS, so
// whichever runs first wins and the other is a no-op. The last_seen index
// serves the listing's order and its pages.
var agentIdentitiesDDL = []string{
	`CREATE TABLE IF NOT EXISTS agent_identities (agent_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_name TEXT, connector TEXT NOT NULL, install_fp TEXT, machine_hash TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_session_id TEXT, sessions_seen INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identities_last_seen ON agent_identities(last_seen DESC, agent_id)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identities_connector ON agent_identities(connector)`,
	// The sessions an agent identity has counted: the count is of distinct
	// session ids, so a session resumed after a gateway restart, which the
	// in-memory session registry sees as new, is not counted again.
	`CREATE TABLE IF NOT EXISTS agent_identity_sessions (agent_id TEXT NOT NULL, session_id TEXT NOT NULL, first_seen TEXT NOT NULL, PRIMARY KEY (agent_id, session_id)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identity_sessions_first_seen ON agent_identity_sessions(first_seen)`,
}

// agentIdentityTimeLayout is fixed-width UTC so the stored strings order the
// same way the times do, which the upsert's min/max rely on.
const agentIdentityTimeLayout = "2006-01-02T15:04:05.000000000Z"

// AgentIdentityRecord is one agent identity: one harness install for one
// user on one machine.
type AgentIdentityRecord struct {
	AgentID       string    `json:"agent_id"`
	UserID        string    `json:"user_id"`
	UserName      string    `json:"user_name,omitempty"`
	Connector     string    `json:"connector"`
	InstallFP     string    `json:"install_fp,omitempty"`
	MachineHash   string    `json:"machine_hash"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	LastSessionID string    `json:"last_session_id,omitempty"`
	// SessionsSeen is the session count. In an UpsertAgentIdentities batch
	// it is the number of sessions this process first saw since the previous
	// flush.
	SessionsSeen int64 `json:"sessions_seen"`
	// SessionIDs is, in a batch, the ids of those sessions (up to
	// agentIdentityBatchSessionCap). The session registry lives in memory,
	// so a session resumed after a gateway restart is new to it; the upsert
	// counts only the ids the store has not counted for this agent.
	SessionIDs []string `json:"-"`
}

// agentIdentityBatchSessionCap bounds the session ids a batch names. A
// session past it is counted without its id.
const agentIdentityBatchSessionCap = 1024

// NoteSession counts a session this process saw for the first time, once per
// id within a batch.
func (r *AgentIdentityRecord) NoteSession(id string) {
	if id == "" {
		return
	}
	if len(r.SessionIDs) < agentIdentityBatchSessionCap {
		if slices.Contains(r.SessionIDs, id) {
			return
		}
		r.SessionIDs = append(r.SessionIDs, id)
	}
	r.SessionsSeen++
}

// AgentIdentityFilter narrows ListAgentIdentities. Empty fields match
// everything.
type AgentIdentityFilter struct {
	// User matches the user id exactly or the user name case-insensitively,
	// bare or qualified on either side (useridentity.AccountFilterMatches).
	User      string
	Connector string
	// AgentIDs, when set, selects only these agents.
	AgentIDs []string
	// Offset skips that many matching rows; Limit caps the rows returned
	// after them (0 or less: no cap). The total counts every match.
	Offset int
	Limit  int
}

func ensureAgentIdentitiesTable(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	for _, stmt := range agentIdentitiesDDL {
		if _, err := exec.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// UpsertAgentIdentities writes one batch in a single transaction. A known
// agent keeps its first_seen, moves last_seen forward, adds the sessions of
// the batch it had not counted and takes the newest session id and user
// name.
func (s *InventoryStore) UpsertAgentIdentities(ctx context.Context, batch []AgentIdentityRecord) error {
	if s == nil || s.db == nil {
		return errors.New("inventory store: not open")
	}
	if len(batch) == 0 || s.legacySchema {
		return nil
	}
	return s.runInTx(ctx, "agent_identities.upsert", func(tx *sql.Tx) error {
		if err := ensureAgentIdentitiesTable(ctx, tx); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO agent_identities
			(agent_id, user_id, user_name, connector, install_fp, machine_hash, first_seen, last_seen, last_session_id, sessions_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(agent_id) DO UPDATE SET
				user_name = COALESCE(NULLIF(excluded.user_name, ''), agent_identities.user_name),
				first_seen = min(agent_identities.first_seen, excluded.first_seen),
				last_seen = max(agent_identities.last_seen, excluded.last_seen),
				last_session_id = CASE
					WHEN excluded.last_session_id <> '' AND excluded.last_seen >= agent_identities.last_seen
					THEN excluded.last_session_id ELSE agent_identities.last_session_id END,
				sessions_seen = agent_identities.sessions_seen + excluded.sessions_seen`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		sessionStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO agent_identity_sessions
			(agent_id, session_id, first_seen) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}
		defer sessionStmt.Close()
		for _, rec := range batch {
			if strings.TrimSpace(rec.AgentID) == "" {
				continue
			}
			first, last := rec.FirstSeen, rec.LastSeen
			if last.IsZero() {
				last = time.Now()
			}
			if first.IsZero() || first.After(last) {
				first = last
			}
			// Sightings the batch holds no id for count as they are; each
			// named session counts once, ever.
			sessions := max(rec.SessionsSeen-int64(len(rec.SessionIDs)), 0)
			for _, sessionID := range rec.SessionIDs {
				if sessionID == "" {
					continue
				}
				inserted, err := sessionStmt.ExecContext(ctx, rec.AgentID, sessionID, formatAgentIdentityTime(last))
				if err != nil {
					return err
				}
				if added, err := inserted.RowsAffected(); err == nil {
					sessions += added
				}
			}
			if _, err := stmt.ExecContext(ctx, rec.AgentID, rec.UserID, rec.UserName, rec.Connector,
				rec.InstallFP, rec.MachineHash, formatAgentIdentityTime(first), formatAgentIdentityTime(last),
				rec.LastSessionID, sessions); err != nil {
				return err
			}
		}
		return nil
	})
}

// PruneAgentIdentitySessions deletes the session ids first counted before
// cutoff and returns how many. They only remember which sessions were
// counted, so a session older than the window that resumes is counted again.
func (s *InventoryStore) PruneAgentIdentitySessions(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("inventory store: not open")
	}
	if s.legacySchema {
		return 0, nil
	}
	var removed int64
	err := s.runInTx(ctx, "agent_identities.prune_sessions", func(tx *sql.Tx) error {
		if err := ensureAgentIdentitiesTable(ctx, tx); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM agent_identity_sessions WHERE first_seen < ?`, formatAgentIdentityTime(cutoff))
		if err != nil {
			return err
		}
		removed, _ = result.RowsAffected()
		return nil
	})
	return removed, err
}

// ListAgentIdentities returns the stored identities matching filter, most
// recently seen first, and how many match in all.
func (s *InventoryStore) ListAgentIdentities(ctx context.Context, filter AgentIdentityFilter) ([]AgentIdentityRecord, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("inventory store: not open")
	}
	if s.legacySchema {
		return nil, 0, nil
	}
	if err := ensureAgentIdentitiesTable(ctx, s.db); err != nil {
		return nil, 0, err
	}
	where := ` WHERE 1=1`
	var args []any
	if connector := strings.TrimSpace(filter.Connector); connector != "" {
		where += ` AND connector = ?`
		args = append(args, strings.ToLower(connector))
	}
	if len(filter.AgentIDs) > 0 {
		where += ` AND agent_id IN (?` + strings.Repeat(`, ?`, len(filter.AgentIDs)-1) + `)`
		for _, id := range filter.AgentIDs {
			args = append(args, id)
		}
	}
	query := `SELECT agent_id, user_id, COALESCE(user_name, ''), connector, COALESCE(install_fp, ''), machine_hash,
		first_seen, last_seen, COALESCE(last_session_id, ''), sessions_seen FROM agent_identities` + where +
		` ORDER BY last_seen DESC, agent_id`
	// The user filter runs in Go (useridentity.AccountFilterMatches), so a
	// bare name selects a row stored as user@realm or DOMAIN\user and the
	// other way round, and the loop below counts, skips and limits. Without
	// it SQLite does.
	user := strings.TrimSpace(filter.User)
	total := -1
	if user == "" && (filter.Limit > 0 || filter.Offset > 0) {
		counted, err := s.queryDB(ctx, "agent_identities.count", `SELECT COUNT(*) FROM agent_identities`+where, args...)
		if err != nil {
			return nil, 0, err
		}
		for counted.Next() {
			err = counted.Scan(&total)
		}
		if err == nil {
			err = counted.Err()
		}
		counted.Close()
		if err != nil {
			return nil, 0, err
		}
		limit := filter.Limit
		if limit <= 0 {
			limit = -1
		}
		query += ` LIMIT ? OFFSET ?`
		args = append(args, limit, max(filter.Offset, 0))
	}
	skip := 0
	if total < 0 {
		skip = filter.Offset
	}
	rows, err := s.queryDB(ctx, "agent_identities.list", query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AgentIdentityRecord
	matched := 0
	for rows.Next() {
		var rec AgentIdentityRecord
		var first, last string
		if err := rows.Scan(&rec.AgentID, &rec.UserID, &rec.UserName, &rec.Connector, &rec.InstallFP,
			&rec.MachineHash, &first, &last, &rec.LastSessionID, &rec.SessionsSeen); err != nil {
			return nil, 0, err
		}
		if user != "" && !useridentity.AccountFilterMatches(user, rec.UserID, rec.UserName) {
			continue
		}
		matched++
		if matched <= skip || filter.Limit > 0 && len(out) == filter.Limit {
			continue
		}
		rec.FirstSeen, _ = time.Parse(agentIdentityTimeLayout, first)
		rec.LastSeen, _ = time.Parse(agentIdentityTimeLayout, last)
		out = append(out, rec)
	}
	if total < 0 {
		total = matched
	}
	return out, total, rows.Err()
}

func formatAgentIdentityTime(t time.Time) string {
	return t.UTC().Format(agentIdentityTimeLayout)
}
