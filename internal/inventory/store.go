// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// InventoryStore is the durable companion to AIStateStore: where the
// JSON state file is the fast boot-time hydration source, this
// SQLite database is the queryable history of every scan.
//
// The store is intentionally additive -- the existing JSON state
// file remains the authoritative current snapshot, and this DB only
// records what was already validated and persisted. If the DB is
// unavailable (path inaccessible, disk full, schema mismatch), the
// service degrades gracefully: scans still complete, the in-memory
// view still works, and only history-dependent queries are
// disabled. See the InventoryStore-aware code in ai_discovery.go
// (`recordScanIfPossible`) for the degradation path.
//
// Schema layout:
//   - ai_scans             one row per scan (scan_id, scanned_at, totals)
//   - ai_signals           one row per (scan_id, fingerprint) for active rows
//   - ai_confidence_snapshots  per (scan_id, ecosystem, name) confidence row
//   - ai_components_v      view: dedup'd components rolled up across scans
type InventoryStore struct {
	db *sql.DB
}

// NewInventoryStore opens (or creates) the inventory database at
// dbPath. The file is created with restrictive permissions (mode
// 0600) on first creation -- the database can contain workspace
// hashes and, when StoreRawLocalPaths is enabled, raw filesystem
// paths.
func NewInventoryStore(dbPath string) (*InventoryStore, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("inventory store: db path is required")
	}
	// Ensure parent dir exists with the same restrictive mode the
	// existing audit store uses.
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("inventory store: ensure parent dir: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("inventory store: open db %s: %w", dbPath, err)
	}
	st := &InventoryStore{db: db}
	if err := st.init(); err != nil {
		st.Close() //nolint:errcheck
		return nil, err
	}
	// Tighten file permissions even if SQLite created the file with
	// the default umask. We do this after init so the file
	// definitely exists.
	if err := os.Chmod(dbPath, 0o600); err != nil && !os.IsNotExist(err) {
		// Permission failures here are not fatal: in some
		// environments (containers, read-only mounts) chmod is
		// disallowed. Log via stderr only so the operator is
		// aware.
		fmt.Fprintf(os.Stderr, "[inventory] could not chmod %s to 0600: %v\n", dbPath, err)
	}
	return st, nil
}

// Close releases the underlying connection pool. Idempotent.
func (s *InventoryStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// inventoryMigrations is the ordered, append-only list of schema
// changes. Mirrors the audit store's pattern: never reorder or
// delete entries; only append. Each entry's `apply` runs inside a
// transaction with the schema_version bump.
var inventoryMigrations = []invMigration{
	{
		description: "v1: ai_scans + ai_signals + ai_confidence_snapshots + ai_components_v view",
		apply: func(ex invDBExecer) error {
			stmts := []string{
				`CREATE TABLE IF NOT EXISTS ai_scans (
					scan_id TEXT PRIMARY KEY,
					scanned_at DATETIME NOT NULL,
					duration_ms INTEGER NOT NULL,
					source TEXT NOT NULL,
					privacy_mode TEXT NOT NULL,
					result TEXT NOT NULL,
					total_signals INTEGER NOT NULL,
					active_signals INTEGER NOT NULL,
					files_scanned INTEGER NOT NULL
				)`,
				`CREATE INDEX IF NOT EXISTS idx_ai_scans_scanned_at ON ai_scans(scanned_at)`,
				`CREATE TABLE IF NOT EXISTS ai_signals (
					scan_id TEXT NOT NULL REFERENCES ai_scans(scan_id) ON DELETE CASCADE,
					fingerprint TEXT NOT NULL,
					signal_id TEXT NOT NULL,
					signature_id TEXT NOT NULL,
					name TEXT NOT NULL,
					vendor TEXT NOT NULL,
					product TEXT NOT NULL,
					category TEXT NOT NULL,
					detector TEXT NOT NULL,
					state TEXT NOT NULL,
					confidence REAL NOT NULL,
					component_ecosystem TEXT,
					component_name TEXT,
					component_framework TEXT,
					component_version TEXT,
					last_seen DATETIME NOT NULL,
					last_active_at DATETIME,
					evidence_json TEXT,
					runtime_json TEXT,
					PRIMARY KEY (scan_id, fingerprint)
				)`,
				`CREATE INDEX IF NOT EXISTS idx_ai_signals_component
					ON ai_signals(component_ecosystem, component_name)`,
				`CREATE INDEX IF NOT EXISTS idx_ai_signals_signature_id
					ON ai_signals(signature_id)`,
				`CREATE TABLE IF NOT EXISTS ai_confidence_snapshots (
					scan_id TEXT NOT NULL REFERENCES ai_scans(scan_id) ON DELETE CASCADE,
					ecosystem TEXT NOT NULL,
					name TEXT NOT NULL,
					identity_score REAL NOT NULL,
					identity_band TEXT NOT NULL,
					presence_score REAL NOT NULL,
					presence_band TEXT NOT NULL,
					policy_version INTEGER NOT NULL,
					detectors TEXT,
					factors_json TEXT,
					PRIMARY KEY (scan_id, ecosystem, name)
				)`,
				// View: roll signals + the most-recent confidence
				// snapshot per (ecosystem, name) into one row. The
				// gateway's components endpoint computes the rollup
				// in memory (see rollupComponents in
				// internal/gateway/ai_usage.go); this view exists
				// for ad-hoc operator queries against the SQLite
				// file (`sqlite3 inventory.db "select * from
				// ai_components_v"`).
				//
				// NOTE: the v1 view JOIN was case-sensitive and
				// dropped the score columns whenever the original
				// `Component.Ecosystem` casing didn't already match
				// the lowercased copy stored in
				// ai_confidence_snapshots (e.g. "PyPI" vs "pypi").
				// Migration v2 below drops + recreates the view
				// with LOWER() on both sides so existing operator
				// installs pick up the fix automatically.
				`CREATE VIEW IF NOT EXISTS ai_components_v AS
					SELECT
						s.component_ecosystem AS ecosystem,
						s.component_name      AS name,
						MAX(s.component_framework)         AS framework,
						MAX(s.component_version)           AS version,
						MAX(s.vendor)                      AS vendor,
						COUNT(*)                           AS install_count,
						MAX(s.last_seen)                   AS last_seen,
						MAX(s.last_active_at)              AS last_active_at,
						MAX(c.identity_score)              AS identity_score,
						MAX(c.identity_band)               AS identity_band,
						MAX(c.presence_score)              AS presence_score,
						MAX(c.presence_band)               AS presence_band,
						MAX(c.policy_version)              AS policy_version
					FROM ai_signals s
					LEFT JOIN ai_confidence_snapshots c
						ON c.ecosystem = s.component_ecosystem
						AND c.name      = s.component_name
						AND c.scan_id   = s.scan_id
					WHERE s.component_ecosystem IS NOT NULL
						AND s.component_name      IS NOT NULL
					GROUP BY s.component_ecosystem, s.component_name`,
			}
			for _, q := range stmts {
				if _, err := ex.Exec(q); err != nil {
					return fmt.Errorf("ai inventory: v1 migration: %w (stmt: %s)", err, firstLine(q))
				}
			}
			return nil
		},
	},
	{
		// v2 fixes the case-mismatch bug in the ai_components_v
		// view: ai_signals stores the original casing of
		// component_ecosystem (e.g. "PyPI") because RecordScan
		// inserts compEco verbatim, but ai_confidence_snapshots
		// stores the lowercased copy keyed off
		// strings.ToLower(...). The v1 JOIN compared raw columns,
		// so any ecosystem whose discovered casing wasn't already
		// lowercase silently lost its identity_score /
		// presence_score columns whenever an operator queried the
		// view directly via sqlite3. The view is not used by the
		// gateway code path (see comment on v1) so this is a
		// data-quality fix for ad-hoc inspection only, but the
		// fix is cheap and the failure mode (missing scores) is
		// hard to diagnose without it.
		description: "v2: rebuild ai_components_v with case-insensitive JOIN",
		apply: func(ex invDBExecer) error {
			stmts := []string{
				`DROP VIEW IF EXISTS ai_components_v`,
				`CREATE VIEW ai_components_v AS
					SELECT
						s.component_ecosystem AS ecosystem,
						s.component_name      AS name,
						MAX(s.component_framework)         AS framework,
						MAX(s.component_version)           AS version,
						MAX(s.vendor)                      AS vendor,
						COUNT(*)                           AS install_count,
						MAX(s.last_seen)                   AS last_seen,
						MAX(s.last_active_at)              AS last_active_at,
						MAX(c.identity_score)              AS identity_score,
						MAX(c.identity_band)               AS identity_band,
						MAX(c.presence_score)              AS presence_score,
						MAX(c.presence_band)               AS presence_band,
						MAX(c.policy_version)              AS policy_version
					FROM ai_signals s
					LEFT JOIN ai_confidence_snapshots c
						ON LOWER(c.ecosystem) = LOWER(s.component_ecosystem)
						AND LOWER(c.name)     = LOWER(s.component_name)
						AND c.scan_id         = s.scan_id
					WHERE s.component_ecosystem IS NOT NULL
						AND s.component_name      IS NOT NULL
					GROUP BY LOWER(s.component_ecosystem), LOWER(s.component_name)`,
			}
			for _, q := range stmts {
				if _, err := ex.Exec(q); err != nil {
					return fmt.Errorf("ai inventory: v2 migration: %w (stmt: %s)", err, firstLine(q))
				}
			}
			return nil
		},
	},
}

type invMigration struct {
	description string
	apply       func(ex invDBExecer) error
}

// invDBExecer is satisfied by both *sql.DB and *sql.Tx so migration
// bodies can run in either context.
type invDBExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func (s *InventoryStore) init() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("inventory store: create schema_version: %w", err)
	}
	current := 0
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("inventory store: read schema version: %w", err)
	}
	for i := current; i < len(inventoryMigrations); i++ {
		ver := i + 1
		m := inventoryMigrations[i]
		if err := s.applyMigration(ver, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *InventoryStore) applyMigration(ver int, m invMigration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("inventory store: begin migration %d: %w", ver, err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := m.apply(tx); err != nil {
		return fmt.Errorf("inventory store: migration %d (%s): %w", ver, m.description, err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
		ver, time.Now().UTC()); err != nil {
		return fmt.Errorf("inventory store: record migration %d: %w", ver, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("inventory store: commit migration %d: %w", ver, err)
	}
	return nil
}

// SchemaVersion returns the highest applied migration number.
func (s *InventoryStore) SchemaVersion() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	return v, err
}

// RecordScan persists a complete scan + every active signal in it
// + computed confidence snapshots per (ecosystem, name). The whole
// thing runs in one transaction so the database always sees a
// consistent set of rows for any given scan_id.
//
// `params` is passed to ComputeComponentConfidence; callers should
// hand the same ConfidenceParams the rest of the gateway uses so
// the snapshots match the wire-time scoring.
//
// Errors are returned but should not be fatal to the caller -- the
// JSON state file is the authoritative source of the current
// snapshot; this database is purely additive history. The discovery
// service caller (`classifyAndPersist`) wraps this in a
// degraded-mode helper.
func (s *InventoryStore) RecordScan(ctx context.Context, report AIDiscoveryReport, params ConfidenceParams) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("inventory store: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO ai_scans
		(scan_id, scanned_at, duration_ms, source, privacy_mode, result,
		 total_signals, active_signals, files_scanned)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.Summary.ScanID,
		report.Summary.ScannedAt.UTC(),
		report.Summary.DurationMs,
		report.Summary.Source,
		report.Summary.PrivacyMode,
		report.Summary.Result,
		report.Summary.TotalSignals,
		report.Summary.ActiveSignals,
		report.Summary.FilesScanned,
	); err != nil {
		return fmt.Errorf("inventory store: insert scan: %w", err)
	}

	// Bucket signals by (ecosystem, name) on the way through so we
	// can compute one confidence snapshot per component without a
	// second pass over the data.
	type compKey struct{ ecosystem, name string }
	buckets := map[compKey][]AISignal{}

	for _, sig := range report.Signals {
		// Only persist active states (new, changed, seen). "gone"
		// signals are interesting for the report but we do not
		// want them participating in the dedup view -- the view
		// joins on the latest scan, and gone rows would skew it.
		if sig.State != AIStateNew && sig.State != AIStateChanged && sig.State != AIStateSeen {
			continue
		}

		evidenceJSON, err := json.Marshal(sig.Evidence)
		if err != nil {
			return fmt.Errorf("inventory store: marshal evidence for %s: %w", sig.SignalID, err)
		}
		var runtimeJSON []byte
		if sig.Runtime != nil {
			runtimeJSON, err = json.Marshal(sig.Runtime)
			if err != nil {
				return fmt.Errorf("inventory store: marshal runtime for %s: %w", sig.SignalID, err)
			}
		}

		var compEco, compName, compFw, compVer sql.NullString
		if sig.Component != nil {
			if sig.Component.Ecosystem != "" {
				compEco = sql.NullString{String: sig.Component.Ecosystem, Valid: true}
			}
			if sig.Component.Name != "" {
				compName = sql.NullString{String: sig.Component.Name, Valid: true}
			}
			if sig.Component.Framework != "" {
				compFw = sql.NullString{String: sig.Component.Framework, Valid: true}
			}
			if sig.Component.Version != "" {
				compVer = sql.NullString{String: sig.Component.Version, Valid: true}
			}
		}
		var lastActive sql.NullTime
		if sig.LastActiveAt != nil {
			lastActive = sql.NullTime{Time: *sig.LastActiveAt, Valid: true}
		}

		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO ai_signals
			(scan_id, fingerprint, signal_id, signature_id, name, vendor, product,
			 category, detector, state, confidence,
			 component_ecosystem, component_name, component_framework, component_version,
			 last_seen, last_active_at, evidence_json, runtime_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			report.Summary.ScanID,
			sig.Fingerprint,
			sig.SignalID,
			sig.SignatureID,
			sig.Name,
			sig.Vendor,
			sig.Product,
			sig.Category,
			sig.Detector,
			sig.State,
			sig.Confidence,
			compEco, compName, compFw, compVer,
			sig.LastSeen.UTC(),
			lastActive,
			string(evidenceJSON),
			nullStringFromBytes(runtimeJSON),
		); err != nil {
			return fmt.Errorf("inventory store: insert signal %s: %w", sig.SignalID, err)
		}

		if sig.Component != nil && sig.Component.Ecosystem != "" && sig.Component.Name != "" {
			k := compKey{
				ecosystem: strings.ToLower(sig.Component.Ecosystem),
				name:      strings.ToLower(sig.Component.Name),
			}
			buckets[k] = append(buckets[k], sig)
		}
	}

	// Compute one confidence snapshot per component bucket.
	now := report.Summary.ScannedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for k, signals := range buckets {
		conf := ComputeComponentConfidence(signals, now, params)
		factorsJSON, err := json.Marshal(struct {
			Identity []ConfidenceFactor `json:"identity"`
			Presence []ConfidenceFactor `json:"presence"`
		}{Identity: conf.IdentityFactors, Presence: conf.PresenceFactors})
		if err != nil {
			return fmt.Errorf("inventory store: marshal factors for %s/%s: %w", k.ecosystem, k.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO ai_confidence_snapshots
			(scan_id, ecosystem, name, identity_score, identity_band,
			 presence_score, presence_band, policy_version, detectors, factors_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			report.Summary.ScanID,
			k.ecosystem, k.name,
			conf.IdentityScore, conf.IdentityBand,
			conf.PresenceScore, conf.PresenceBand,
			conf.PolicyVersion,
			strings.Join(conf.Detectors, ","),
			string(factorsJSON),
		); err != nil {
			return fmt.Errorf("inventory store: insert confidence snapshot %s/%s: %w", k.ecosystem, k.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("inventory store: commit scan %s: %w", report.Summary.ScanID, err)
	}
	return nil
}

// ComponentLocationRow is one row for the locations endpoint /
// `agent components show` table -- it answers "where on this box
// did we see this component?".
type ComponentLocationRow struct {
	Detector      string     `json:"detector"`
	State         string     `json:"state"`
	Basename      string     `json:"basename,omitempty"`
	PathHash      string     `json:"path_hash,omitempty"`
	WorkspaceHash string     `json:"workspace_hash,omitempty"`
	RawPath       string     `json:"raw_path,omitempty"`
	Quality       float64    `json:"quality,omitempty"`
	MatchKind     string     `json:"match_kind,omitempty"`
	LastSeen      time.Time  `json:"last_seen"`
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
}

// ListComponentLocations returns every active location currently
// known for the given (ecosystem, name) component, drawn from the
// most-recent scan that contains it. RawPath is included only when
// the caller passes `includeRawPaths=true` -- the gateway sets that
// based on `privacy.disable_redaction && ai_discovery.store_raw_local_paths`.
func (s *InventoryStore) ListComponentLocations(ctx context.Context, ecosystem, name string, includeRawPaths bool) ([]ComponentLocationRow, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.detector, s.state, s.evidence_json, s.last_seen, s.last_active_at
		FROM ai_signals s
		WHERE LOWER(s.component_ecosystem) = LOWER(?)
		  AND LOWER(s.component_name) = LOWER(?)
		  AND s.scan_id = (
		    SELECT scan_id FROM ai_signals
		    WHERE LOWER(component_ecosystem) = LOWER(?)
		      AND LOWER(component_name) = LOWER(?)
		    ORDER BY last_seen DESC LIMIT 1
		  )
		ORDER BY s.last_seen DESC`,
		ecosystem, name, ecosystem, name,
	)
	if err != nil {
		return nil, fmt.Errorf("inventory store: list locations: %w", err)
	}
	defer rows.Close()
	out := []ComponentLocationRow{}
	for rows.Next() {
		var (
			detector     string
			state        string
			evidenceJSON sql.NullString
			lastSeen     time.Time
			lastActive   sql.NullTime
		)
		if err := rows.Scan(&detector, &state, &evidenceJSON, &lastSeen, &lastActive); err != nil {
			return nil, fmt.Errorf("inventory store: scan location: %w", err)
		}
		var evidence []AIEvidence
		if evidenceJSON.Valid && evidenceJSON.String != "" {
			if err := json.Unmarshal([]byte(evidenceJSON.String), &evidence); err != nil {
				continue // skip bad rows rather than failing the whole list
			}
		}
		var lastActivePtr *time.Time
		if lastActive.Valid {
			t := lastActive.Time
			lastActivePtr = &t
		}
		// One row per evidence entry so the renderer can show
		// "manifest evidence" and "process evidence" as separate
		// locations rather than a single row with both.
		if len(evidence) == 0 {
			out = append(out, ComponentLocationRow{
				Detector:     detector,
				State:        state,
				LastSeen:     lastSeen,
				LastActiveAt: lastActivePtr,
			})
			continue
		}
		for _, ev := range evidence {
			row := ComponentLocationRow{
				Detector:      detector,
				State:         state,
				Basename:      ev.Basename,
				PathHash:      ev.PathHash,
				WorkspaceHash: ev.WorkspaceHash,
				Quality:       ev.Quality,
				MatchKind:     ev.MatchKind,
				LastSeen:      lastSeen,
				LastActiveAt:  lastActivePtr,
			}
			if includeRawPaths {
				row.RawPath = ev.RawPath
			}
			out = append(out, row)
		}
	}
	return out, rows.Err()
}

// ComponentHistoryRow is a single point in the score history
// returned to `agent components history`.
type ComponentHistoryRow struct {
	ScanID         string    `json:"scan_id"`
	ScannedAt      time.Time `json:"scanned_at"`
	IdentityScore  float64   `json:"identity_score"`
	IdentityBand   string    `json:"identity_band"`
	PresenceScore  float64   `json:"presence_score"`
	PresenceBand   string    `json:"presence_band"`
	Detectors      string    `json:"detectors,omitempty"`
	PolicyVersion  int       `json:"policy_version"`
}

// ComponentHistory returns up to `limit` (most-recent first)
// confidence snapshots for the given component. Used by `agent
// components history NAME`.
func (s *InventoryStore) ComponentHistory(ctx context.Context, ecosystem, name string, limit int) ([]ComponentHistoryRow, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.scan_id, sc.scanned_at, c.identity_score, c.identity_band,
		       c.presence_score, c.presence_band, c.detectors, c.policy_version
		FROM ai_confidence_snapshots c
		JOIN ai_scans sc ON sc.scan_id = c.scan_id
		WHERE LOWER(c.ecosystem) = LOWER(?)
		  AND LOWER(c.name)      = LOWER(?)
		ORDER BY sc.scanned_at DESC
		LIMIT ?`,
		ecosystem, name, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("inventory store: query history: %w", err)
	}
	defer rows.Close()
	out := []ComponentHistoryRow{}
	for rows.Next() {
		var r ComponentHistoryRow
		if err := rows.Scan(&r.ScanID, &r.ScannedAt, &r.IdentityScore, &r.IdentityBand,
			&r.PresenceScore, &r.PresenceBand, &r.Detectors, &r.PolicyVersion); err != nil {
			return nil, fmt.Errorf("inventory store: scan history row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneScansBefore deletes ai_scans rows (and cascades to signals +
// snapshots) older than `cutoff`. Returns the number of scans
// removed. Caller should run on a periodic ticker; the discovery
// service does this from `runRetentionSweepIfPossible`.
func (s *InventoryStore) PruneScansBefore(ctx context.Context, cutoff time.Time) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM ai_scans WHERE scanned_at < ?`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("inventory store: prune scans: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// nullStringFromBytes converts a possibly-empty []byte into a
// sql.NullString so JSON-marshaled fields land as NULL when nothing
// is set.
func nullStringFromBytes(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// firstLine extracts the first non-empty line of a SQL statement
// for error context. Keeps multi-line CREATE TABLE strings from
// blowing up error messages.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 80 {
				return line[:80] + "…"
			}
			return line
		}
	}
	return ""
}
