package policy

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// SQLitePolicyStore implements PolicyStore backed by a SQLite database.
// Uses modernc.org/sqlite — a pure Go implementation with no CGO dependency.
type SQLitePolicyStore struct {
	db *sql.DB
}

// NewSQLitePolicyStore opens (or creates) a SQLite database at the given path
// and initializes the policies table.
func NewSQLitePolicyStore(dbPath string) (*SQLitePolicyStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	if err := createPoliciesTable(db); err != nil {
		db.Close()
		return nil, err
	}

	return &SQLitePolicyStore{db: db}, nil
}

func createPoliciesTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS policies (
			tenant_id   INTEGER NOT NULL,
			fleet_id    INTEGER NOT NULL,
			version     INTEGER NOT NULL,
			profile     TEXT    NOT NULL DEFAULT 'standard',
			policy_bin  BLOB   NOT NULL,
			signature   TEXT   NOT NULL DEFAULT '',
			created_at  TEXT   NOT NULL,
			distributed INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant_id, fleet_id, version)
		)
	`)
	if err != nil {
		return fmt.Errorf("create policies table: %w", err)
	}

	// Index for efficient latest-version lookups
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_policies_tenant_fleet_version
		ON policies (tenant_id, fleet_id, version DESC)
	`)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	return nil
}

func (s *SQLitePolicyStore) SavePolicy(tenantID, fleetID uint64, version uint32, policyBin []byte, signature []byte, profile string) error {
	sigHex := hex.EncodeToString(signature)
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.db.Exec(`
		INSERT INTO policies (tenant_id, fleet_id, version, profile, policy_bin, signature, created_at, distributed)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`, tenantID, fleetID, version, profile, policyBin, sigHex, now)
	if err != nil {
		return fmt.Errorf("save policy version %d for tenant=%d fleet=%d: %w", version, tenantID, fleetID, err)
	}
	return nil
}

func (s *SQLitePolicyStore) GetLatestPolicy(tenantID, fleetID uint64) (*PolicyRecord, error) {
	row := s.db.QueryRow(`
		SELECT tenant_id, fleet_id, version, profile, policy_bin, signature, created_at, distributed
		FROM policies
		WHERE tenant_id = ? AND fleet_id = ?
		ORDER BY version DESC
		LIMIT 1
	`, tenantID, fleetID)

	rec, err := scanPolicyRow(row)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *SQLitePolicyStore) GetPolicy(tenantID, fleetID uint64, version uint32) (*PolicyRecord, error) {
	row := s.db.QueryRow(`
		SELECT tenant_id, fleet_id, version, profile, policy_bin, signature, created_at, distributed
		FROM policies
		WHERE tenant_id = ? AND fleet_id = ? AND version = ?
	`, tenantID, fleetID, version)

	rec, err := scanPolicyRow(row)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *SQLitePolicyStore) ListVersions(tenantID, fleetID uint64) ([]PolicyRecord, error) {
	rows, err := s.db.Query(`
		SELECT tenant_id, fleet_id, version, profile, '', '', created_at, distributed
		FROM policies
		WHERE tenant_id = ? AND fleet_id = ?
		ORDER BY version DESC
	`, tenantID, fleetID)
	if err != nil {
		return nil, fmt.Errorf("list policy versions: %w", err)
	}
	defer rows.Close()

	var records []PolicyRecord
	for rows.Next() {
		rec, err := scanPolicyRows(rows)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			records = append(records, *rec)
		}
	}
	return records, rows.Err()
}

func (s *SQLitePolicyStore) MarkDistributed(tenantID, fleetID uint64, version uint32) error {
	res, err := s.db.Exec(`
		UPDATE policies SET distributed = 1
		WHERE tenant_id = ? AND fleet_id = ? AND version = ?
	`, tenantID, fleetID, version)
	if err != nil {
		return fmt.Errorf("mark distributed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy version %d not found for tenant=%d fleet=%d", version, tenantID, fleetID)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLitePolicyStore) Close() error {
	return s.db.Close()
}

// policyScanner is an interface satisfied by both *sql.Row and *sql.Rows.
type policyScanner interface {
	Scan(dest ...any) error
}

func scanPolicyFromScanner(sc policyScanner) (*PolicyRecord, error) {
	var (
		rec       PolicyRecord
		sigHex    string
		createdAt string
		distInt   int
	)

	err := sc.Scan(
		&rec.TenantID, &rec.FleetID, &rec.Version, &rec.Profile,
		&rec.PolicyBin, &sigHex, &createdAt, &distInt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan policy: %w", err)
	}

	rec.Distributed = distInt != 0

	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		rec.CreatedAt = t
	}
	if sigHex != "" {
		if sigBytes, err := hex.DecodeString(sigHex); err == nil {
			rec.Signature = sigBytes
		}
	}

	return &rec, nil
}

func scanPolicyRow(row *sql.Row) (*PolicyRecord, error) {
	return scanPolicyFromScanner(row)
}

func scanPolicyRows(rows *sql.Rows) (*PolicyRecord, error) {
	return scanPolicyFromScanner(rows)
}
