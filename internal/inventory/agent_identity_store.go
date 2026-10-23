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
	`CREATE TABLE IF NOT EXISTS agent_identities (agent_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_name TEXT, connector TEXT NOT NULL, install_fp TEXT, machine_hash TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_session_id TEXT, sessions_seen INTEGER NOT NULL DEFAULT 0, user_domain TEXT, user_incarnation TEXT)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identities_last_seen ON agent_identities(last_seen DESC, agent_id)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identities_connector ON agent_identities(connector)`,
	// The sessions an agent identity has counted: the count is of distinct
	// session ids, so a session resumed after a gateway restart, which the
	// in-memory session registry sees as new, is not counted again.
	`CREATE TABLE IF NOT EXISTS agent_identity_sessions (agent_id TEXT NOT NULL, session_id TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (agent_id, session_id)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identity_sessions_first_seen ON agent_identity_sessions(first_seen)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_identity_sessions_last_seen ON agent_identity_sessions(last_seen)`,
	// The records a prune keeps aside for the gateway's 1.0.3 assignment
	// bridge (retireLegacyAgentIdentities); never listed.
	`CREATE TABLE IF NOT EXISTS agent_identities_retired (agent_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_name TEXT, connector TEXT NOT NULL, install_fp TEXT, machine_hash TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_session_id TEXT, sessions_seen INTEGER NOT NULL DEFAULT 0)`,
}

// agentIdentityColumns are the stored columns of agent_identities and
// agent_identities_retired, in their order.
const agentIdentityColumns = `agent_id, user_id, user_name, connector, install_fp, machine_hash, first_seen, last_seen, last_session_id, sessions_seen`

// agentIdentityTimeLayout is fixed-width UTC so the stored strings order the
// same way the times do, which the upsert's min/max rely on.
const agentIdentityTimeLayout = "2006-01-02T15:04:05.000000000Z"

// AgentIdentityRecord is one agent identity: one harness install for one
// user on one machine.
type AgentIdentityRecord struct {
	AgentID  string `json:"agent_id"`
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
	// UserDomain is the useridentity.AccountDomains of the account the
	// agent ran as when it was last seen: the domains a qualified --user
	// filter must name to select the row by its uid (inventory.db v7).
	UserDomain string `json:"-"`
	// UserIncarnation is the account token of that account (its account
	// incarnation or listed record, inventory.db v8): where both sides name
	// one, it tells two accounts of one uid apart where their domains may
	// overlap. "" for a row written before, or while none was known.
	UserIncarnation string    `json:"-"`
	Connector       string    `json:"connector"`
	InstallFP       string    `json:"install_fp,omitempty"`
	MachineHash     string    `json:"machine_hash"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	LastSessionID   string    `json:"last_session_id,omitempty"`
	// SessionsSeen is the session count. In an UpsertAgentIdentities batch
	// it is the number of sessions this process first saw since the previous
	// flush.
	SessionsSeen int64 `json:"sessions_seen"`
	// SessionIDs is, in a batch, the ids of those sessions (up to
	// agentIdentityBatchSessionCap). The session registry lives in memory,
	// so a session resumed after a gateway restart is new to it; the upsert
	// counts only ids the store has not retained for this agent.
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

// ForgetSession takes back a session NoteSession counted in this batch: it
// turned out to be a sub-agent's, not a chat of the agent. The last session
// is then the newest one the batch still counts.
func (r *AgentIdentityRecord) ForgetSession(id string) {
	if i := slices.Index(r.SessionIDs, id); i >= 0 {
		r.SessionIDs = slices.Delete(r.SessionIDs, i, i+1)
		r.SessionsSeen = max(r.SessionsSeen-1, 0)
	}
	if r.LastSessionID == id {
		r.LastSessionID = ""
		if n := len(r.SessionIDs); n > 0 {
			r.LastSessionID = r.SessionIDs[n-1]
		}
	}
}

// AgentIdentityFilter narrows ListAgentIdentities. Empty fields match
// everything.
type AgentIdentityFilter struct {
	// User matches the user id exactly or the user name case-insensitively;
	// a bare name selects every domain's account of that name, a qualified
	// one only rows of exactly that domain or of UserIDs
	// (useridentity.AccountFilter).
	User string
	// UserIDs are the ids of the account the OS resolves a qualified User
	// to, so a row recorded with the bare name matches it by id.
	UserIDs []string
	// UserDomains is the useridentity.AccountDomains of the account UserIDs
	// name, so a row recorded for it matches by id whatever spelling of its
	// domain User has.
	UserDomains string
	// UserIncarnation is the account token of the account UserIDs name, and
	// HolderChanged reports that another account is known to have held its
	// uid, so a row that names no token is not taken for its own
	// (useridentity.AccountFilter.WithAccountIncarnation).
	UserIncarnation string
	HolderChanged   bool
	// RemovedAccount reports whether no account holds a row's user id now
	// and the domain of a qualified User could have held it: such a User
	// that resolves to no account (a deleted one) still selects its rows
	// recorded with the bare name (GAP-1221).
	RemovedAccount func(id string) bool
	Connector      string
	// AgentIDs, when set, selects only these agents.
	AgentIDs []string
	// Retired also lists the records a prune kept aside for the gateway's
	// 1.0.3 assignment bridge (retireLegacyAgentIdentities). Only the bridge
	// sets it.
	Retired bool
	// Offset skips that many matching rows; Limit caps the rows returned
	// after them (0 or less: no cap). The total counts every match.
	Offset int
	Limit  int
}

// Account is the compiled user filter (useridentity.AccountFilter). Its
// MatchesIn takes a row's UserDomain.
func (f AgentIdentityFilter) Account() useridentity.AccountFilter {
	return useridentity.NewAccountFilter(f.User, f.UserIDs...).WithAccountDomains(f.UserDomains).
		WithAccountIncarnation(f.UserIncarnation, f.HolderChanged).WithRemovedAccounts(f.RemovedAccount)
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

// restartAnotherAccountsAgentIdentity drops the stored row of rec's agent ID,
// and the sessions it counted, when the row was recorded for another account
// than rec: one of another account token, or, where a side names none, of
// other domains. Accounts of one bare name, uid and home that nothing else
// tells apart derive one agent ID, and the upsert gave the second account
// the first one's first_seen, last session and session count (review of
// GAP-0947). The row then starts again from rec. A side that names neither
// (a row written before v7) proves nothing.
func restartAnotherAccountsAgentIdentity(ctx context.Context, tx *sql.Tx, rec AgentIdentityRecord) error {
	domains := strings.Fields(strings.ToLower(rec.UserDomain))
	incarnation := strings.TrimSpace(rec.UserIncarnation)
	if len(domains) == 0 && incarnation == "" {
		return nil
	}
	var stored, storedIncarnation string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(user_domain, ''), COALESCE(user_incarnation, '') FROM agent_identities WHERE agent_id = ?`,
		rec.AgentID).Scan(&stored, &storedIncarnation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	previous := strings.Fields(strings.ToLower(stored))
	switch {
	case incarnation != "" && storedIncarnation != "":
		if incarnation == storedIncarnation {
			return nil
		}
	case len(domains) == 0 || len(previous) == 0 ||
		slices.ContainsFunc(previous, func(domain string) bool { return slices.Contains(domains, domain) }):
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_identity_sessions WHERE agent_id = ?`, rec.AgentID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM agent_identities WHERE agent_id = ?`, rec.AgentID)
	return err
}

// AgentIdentitySession identifies a counted session that later proved to
// belong to a child agent.
type AgentIdentitySession struct {
	AgentID   string
	SessionID string
}

// UpsertAgentIdentities writes one batch in a single transaction.
func (s *InventoryStore) UpsertAgentIdentities(ctx context.Context, batch []AgentIdentityRecord) error {
	return s.UpsertAgentIdentitiesAndExclude(ctx, batch, nil)
}

// UpsertAgentIdentitiesAndExclude writes sightings and late child-session
// exclusions atomically. A known agent keeps its first_seen, moves last_seen
// forward, and counts each named session only once.
func (s *InventoryStore) UpsertAgentIdentitiesAndExclude(
	ctx context.Context, batch []AgentIdentityRecord, excluded []AgentIdentitySession,
) error {
	if s == nil || s.db == nil {
		return errors.New("inventory store: not open")
	}
	if len(batch) == 0 && len(excluded) == 0 || s.legacySchema {
		return nil
	}
	return s.runInTx(ctx, "agent_identities.upsert", func(tx *sql.Tx) error {
		if err := ensureAgentIdentitiesTable(ctx, tx); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO agent_identities
			(agent_id, user_id, user_name, connector, install_fp, machine_hash, first_seen, last_seen, last_session_id, sessions_seen, user_domain, user_incarnation)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(agent_id) DO UPDATE SET
				user_name = COALESCE(NULLIF(excluded.user_name, ''), agent_identities.user_name),
				user_domain = COALESCE(NULLIF(excluded.user_domain, ''), agent_identities.user_domain),
				user_incarnation = COALESCE(NULLIF(excluded.user_incarnation, ''), agent_identities.user_incarnation),
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
			(agent_id, session_id, first_seen, last_seen) VALUES (?, ?, ?, ?)`)
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
			if err := restartAnotherAccountsAgentIdentity(ctx, tx, rec); err != nil {
				return err
			}
			// Sightings the batch holds no id for count as they are; each
			// named session counts once while its deduplication row is retained.
			sessions := max(rec.SessionsSeen-int64(len(rec.SessionIDs)), 0)
			lastNewSessionID := ""
			lastSessionWasNamed := false
			for i, sessionID := range rec.SessionIDs {
				if sessionID == "" {
					continue
				}
				seen := formatAgentIdentityTime(last.Add(time.Duration(i) * time.Nanosecond))
				inserted, err := sessionStmt.ExecContext(ctx, rec.AgentID, sessionID, seen, seen)
				if err != nil {
					return err
				}
				added, err := inserted.RowsAffected()
				if err != nil {
					return err
				}
				sessions += added
				if added > 0 {
					lastNewSessionID = sessionID
				} else if _, err := tx.ExecContext(ctx, `UPDATE agent_identity_sessions
					SET last_seen = max(last_seen, ?) WHERE agent_id = ? AND session_id = ?`,
					seen, rec.AgentID, sessionID); err != nil {
					return err
				}
				if sessionID == rec.LastSessionID {
					lastSessionWasNamed = true
				}
			}
			// A resumed older session was already counted. Its later hook
			// must not replace the last genuinely new session.
			lastSessionID := rec.LastSessionID
			if lastSessionWasNamed && lastNewSessionID != rec.LastSessionID {
				lastSessionID = lastNewSessionID
			}
			if _, err := stmt.ExecContext(ctx, rec.AgentID, rec.UserID, rec.UserName, rec.Connector,
				rec.InstallFP, rec.MachineHash, formatAgentIdentityTime(first), formatAgentIdentityTime(last),
				lastSessionID, sessions, strings.TrimSpace(rec.UserDomain), strings.TrimSpace(rec.UserIncarnation)); err != nil {
				return err
			}
		}
		// A child link can arrive after the batch that first counted its
		// session. DELETE is idempotent, including when the session was
		// still only pending or the same link is reported twice.
		for _, child := range excluded {
			if child.AgentID == "" || child.SessionID == "" {
				continue
			}
			result, err := tx.ExecContext(ctx, `DELETE FROM agent_identity_sessions WHERE agent_id = ? AND session_id = ?`,
				child.AgentID, child.SessionID)
			if err != nil {
				return err
			}
			removed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if removed == 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE agent_identities SET
				sessions_seen = max(sessions_seen - 1, 0),
				last_session_id = CASE WHEN last_session_id = ? THEN
					COALESCE((SELECT session_id FROM agent_identity_sessions
						WHERE agent_id = ? ORDER BY first_seen DESC, session_id DESC LIMIT 1), '')
					ELSE last_session_id END
				WHERE agent_id = ?`, child.SessionID, child.AgentID, child.AgentID); err != nil {
				return err
			}
		}
		return nil
	})
}

// PruneAgentIdentitySessions deletes orphaned and expired deduplication
// rows. A resumed chat refreshes last_seen, so it stays deduplicated while
// active; sessions_seen remains a cumulative count after rows expire. A zero
// cutoff deletes only orphaned rows.
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
		result, err := tx.ExecContext(ctx, `DELETE FROM agent_identity_sessions
			WHERE last_seen < ? OR NOT EXISTS (SELECT 1 FROM agent_identities
				WHERE agent_identities.agent_id = agent_identity_sessions.agent_id)`,
			formatAgentIdentityTime(cutoff))
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
	from := ` FROM agent_identities`
	if filter.Retired {
		// Retired rows are records 1.0.0 to 1.0.3 wrote, which keep no
		// account domains (v7) and no account incarnations: they are
		// selected by their uid.
		from = ` FROM (SELECT ` + agentIdentityColumns + `, user_domain, user_incarnation FROM agent_identities UNION ALL SELECT ` +
			agentIdentityColumns + `, NULL AS user_domain, NULL AS user_incarnation FROM agent_identities_retired)`
	}
	query := `SELECT agent_id, user_id, COALESCE(user_name, ''), connector, COALESCE(install_fp, ''), machine_hash,
		first_seen, last_seen, COALESCE(last_session_id, ''), sessions_seen, COALESCE(user_domain, ''), COALESCE(user_incarnation, '')` + from + where +
		` ORDER BY last_seen DESC, agent_id`
	// The user filter runs in Go (useridentity.AccountFilter), so a
	// bare name selects a row stored as user@realm or DOMAIN\user, and the
	// loop below counts, skips and limits. Without
	// it SQLite does.
	user := strings.TrimSpace(filter.User)
	account := filter.Account()
	total := -1
	if user == "" && (filter.Limit > 0 || filter.Offset > 0) {
		counted, err := s.queryDB(ctx, "agent_identities.count", `SELECT COUNT(*)`+from+where, args...)
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
			&rec.MachineHash, &first, &last, &rec.LastSessionID, &rec.SessionsSeen, &rec.UserDomain, &rec.UserIncarnation); err != nil {
			return nil, 0, err
		}
		if user != "" && !account.MatchesIn(rec.UserID, rec.UserName, rec.UserDomain, rec.UserIncarnation) {
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
