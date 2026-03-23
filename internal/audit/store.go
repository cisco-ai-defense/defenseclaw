package audit

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
	Severity  string    `json:"severity"`
}

type BlockEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}

type AllowEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: open db %s: %w", dbPath, err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: set WAL mode: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		actor TEXT NOT NULL DEFAULT 'defenseclaw',
		details TEXT,
		severity TEXT
	);

	CREATE TABLE IF NOT EXISTS scan_results (
		id TEXT PRIMARY KEY,
		scanner TEXT NOT NULL,
		target TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		duration_ms INTEGER,
		finding_count INTEGER,
		max_severity TEXT,
		raw_json TEXT
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		location TEXT,
		remediation TEXT,
		scanner TEXT NOT NULL,
		tags TEXT,
		FOREIGN KEY (scan_id) REFERENCES scan_results(id)
	);

	CREATE TABLE IF NOT EXISTS block_list (
		id TEXT PRIMARY KEY,
		target_type TEXT NOT NULL,
		target_name TEXT NOT NULL,
		reason TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS allow_list (
		id TEXT PRIMARY KEY,
		target_type TEXT NOT NULL,
		target_name TEXT NOT NULL,
		reason TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
	CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
	CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_block_type_name ON block_list(target_type, target_name);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_allow_type_name ON allow_list(target_type, target_name);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("audit: init schema: %w", err)
	}
	return nil
}

// --- Audit Events ---

func (s *Store) LogEvent(e Event) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Actor == "" {
		e.Actor = "defenseclaw"
	}

	_, err := s.db.Exec(
		`INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp, e.Action, e.Target, e.Actor, e.Details, e.Severity,
	)
	if err != nil {
		return fmt.Errorf("audit: log event: %w", err)
	}
	return nil
}

func (s *Store) InsertScanResult(id, scannerName, target string, ts time.Time, durationMs int64, findingCount int, maxSeverity, rawJSON string) error {
	_, err := s.db.Exec(
		`INSERT INTO scan_results (id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scannerName, target, ts, durationMs, findingCount, maxSeverity, rawJSON,
	)
	if err != nil {
		return fmt.Errorf("audit: insert scan result: %w", err)
	}
	return nil
}

func (s *Store) InsertFinding(id, scanID, severity, title, description, location, remediation, scannerName, tags string) error {
	_, err := s.db.Exec(
		`INSERT INTO findings (id, scan_id, severity, title, description, location, remediation, scanner, tags)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, severity, title, description, location, remediation, scannerName, tags,
	)
	if err != nil {
		return fmt.Errorf("audit: insert finding: %w", err)
	}
	return nil
}

func (s *Store) ListEvents(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(
		`SELECT id, timestamp, action, target, actor, details, severity
		 FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var target, details, severity sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &severity); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.Severity = severity.String
		events = append(events, e)
	}
	return events, rows.Err()
}

// --- Block List ---

func (s *Store) AddBlock(targetType, targetName, reason string) error {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO block_list (id, target_type, target_name, reason, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, targetType, targetName, reason, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("audit: add block: %w", err)
	}
	return nil
}

func (s *Store) RemoveBlock(targetType, targetName string) error {
	_, err := s.db.Exec(
		`DELETE FROM block_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: remove block: %w", err)
	}
	return nil
}

func (s *Store) IsBlocked(targetType, targetName string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM block_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("audit: check block: %w", err)
	}
	return count > 0, nil
}

func (s *Store) ListBlocked() ([]BlockEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, target_name, reason, created_at
		 FROM block_list ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list blocked: %w", err)
	}
	defer rows.Close()

	var entries []BlockEntry
	for rows.Next() {
		var e BlockEntry
		var reason sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan block row: %w", err)
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// --- Allow List ---

func (s *Store) AddAllow(targetType, targetName, reason string) error {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO allow_list (id, target_type, target_name, reason, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, targetType, targetName, reason, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("audit: add allow: %w", err)
	}
	return nil
}

func (s *Store) RemoveAllow(targetType, targetName string) error {
	_, err := s.db.Exec(
		`DELETE FROM allow_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: remove allow: %w", err)
	}
	return nil
}

func (s *Store) IsAllowed(targetType, targetName string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM allow_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("audit: check allow: %w", err)
	}
	return count > 0, nil
}

func (s *Store) ListAllowed() ([]AllowEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, target_name, reason, created_at
		 FROM allow_list ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list allowed: %w", err)
	}
	defer rows.Close()

	var entries []AllowEntry
	for rows.Next() {
		var e AllowEntry
		var reason sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan allow row: %w", err)
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// --- TUI Queries ---

type ScanResultRow struct {
	ID           string    `json:"id"`
	Scanner      string    `json:"scanner"`
	Target       string    `json:"target"`
	Timestamp    time.Time `json:"timestamp"`
	DurationMs   int64     `json:"duration_ms"`
	FindingCount int       `json:"finding_count"`
	MaxSeverity  string    `json:"max_severity"`
}

type FindingRow struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
	Scanner     string `json:"scanner"`
}

func (s *Store) ListAlerts(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, action, target, actor, details, severity
		 FROM audit_events
		 WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')
		   AND action NOT LIKE 'dismiss%'
		 ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list alerts: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var target, details, severity sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &severity); err != nil {
			return nil, fmt.Errorf("audit: scan alert row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.Severity = severity.String
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) ListScanResults(limit int) ([]ScanResultRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, scanner, target, timestamp, duration_ms, finding_count, max_severity
		 FROM scan_results ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan results: %w", err)
	}
	defer rows.Close()

	var results []ScanResultRow
	for rows.Next() {
		var r ScanResultRow
		var maxSev sql.NullString
		if err := rows.Scan(&r.ID, &r.Scanner, &r.Target, &r.Timestamp, &r.DurationMs, &r.FindingCount, &maxSev); err != nil {
			return nil, fmt.Errorf("audit: scan result row: %w", err)
		}
		r.MaxSeverity = maxSev.String
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *Store) ListFindingsByScan(scanID string) ([]FindingRow, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, severity, title, description, location, remediation, scanner
		 FROM findings WHERE scan_id = ? ORDER BY severity DESC`, scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list findings: %w", err)
	}
	defer rows.Close()

	var findings []FindingRow
	for rows.Next() {
		var f FindingRow
		var desc, loc, rem sql.NullString
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Title, &desc, &loc, &rem, &f.Scanner); err != nil {
			return nil, fmt.Errorf("audit: scan finding row: %w", err)
		}
		f.Description = desc.String
		f.Location = loc.String
		f.Remediation = rem.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (s *Store) ListBlockedByType(targetType string) ([]BlockEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, target_name, reason, created_at
		 FROM block_list WHERE target_type = ? ORDER BY created_at DESC`, targetType,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list blocked by type: %w", err)
	}
	defer rows.Close()

	var entries []BlockEntry
	for rows.Next() {
		var e BlockEntry
		var reason sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan block row: %w", err)
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) ListAllowedByType(targetType string) ([]AllowEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, target_name, reason, created_at
		 FROM allow_list WHERE target_type = ? ORDER BY created_at DESC`, targetType,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list allowed by type: %w", err)
	}
	defer rows.Close()

	var entries []AllowEntry
	for rows.Next() {
		var e AllowEntry
		var reason sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan allow row: %w", err)
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

type Counts struct {
	BlockedSkills int
	AllowedSkills int
	BlockedMCPs   int
	AllowedMCPs   int
	Alerts        int
	TotalScans    int
}

func (s *Store) GetCounts() (Counts, error) {
	var c Counts
	queries := []struct {
		sql  string
		dest *int
	}{
		{`SELECT COUNT(*) FROM block_list WHERE target_type = 'skill'`, &c.BlockedSkills},
		{`SELECT COUNT(*) FROM allow_list WHERE target_type = 'skill'`, &c.AllowedSkills},
		{`SELECT COUNT(*) FROM block_list WHERE target_type = 'mcp'`, &c.BlockedMCPs},
		{`SELECT COUNT(*) FROM allow_list WHERE target_type = 'mcp'`, &c.AllowedMCPs},
		{`SELECT COUNT(*) FROM audit_events WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')`, &c.Alerts},
		{`SELECT COUNT(*) FROM scan_results`, &c.TotalScans},
	}
	for _, q := range queries {
		if err := s.db.QueryRow(q.sql).Scan(q.dest); err != nil {
			return c, fmt.Errorf("audit: count query: %w", err)
		}
	}
	return c, nil
}

type LatestScanInfo struct {
	ID           string
	Target       string
	Timestamp    time.Time
	FindingCount int
	MaxSeverity  string
	RawJSON      string
}

func (s *Store) LatestScansByScanner(scannerName string) ([]LatestScanInfo, error) {
	rows, err := s.db.Query(`
		SELECT sr.id, sr.target, sr.timestamp, sr.finding_count, sr.max_severity, sr.raw_json
		FROM scan_results sr
		INNER JOIN (
			SELECT target, MAX(timestamp) as max_ts
			FROM scan_results
			WHERE scanner = ?
			GROUP BY target
		) latest ON sr.target = latest.target AND sr.timestamp = latest.max_ts
		WHERE sr.scanner = ?
	`, scannerName, scannerName)
	if err != nil {
		return nil, fmt.Errorf("audit: latest scans by scanner: %w", err)
	}
	defer rows.Close()

	var results []LatestScanInfo
	for rows.Next() {
		var r LatestScanInfo
		var maxSev, rawJSON sql.NullString
		if err := rows.Scan(&r.ID, &r.Target, &r.Timestamp, &r.FindingCount, &maxSev, &rawJSON); err != nil {
			return nil, fmt.Errorf("audit: scan latest row: %w", err)
		}
		r.MaxSeverity = maxSev.String
		r.RawJSON = rawJSON.String
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *Store) Close() error {
	return s.db.Close()
}
