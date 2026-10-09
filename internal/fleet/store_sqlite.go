package fleet

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// SQLiteStore implements DeviceStore backed by a SQLite database.
// Uses modernc.org/sqlite — a pure Go implementation with no CGO dependency.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database at the given path
// and initializes the devices table.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	// M-11: Limit concurrent connections and WAL size for resource-constrained
	// environments (edge devices, single-writer pattern).
	db.SetMaxOpenConns(2)
	if _, err := db.Exec("PRAGMA journal_size_limit=8388608"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL size limit: %w", err)
	}

	if err := createTable(db); err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func createTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			device_id       INTEGER PRIMARY KEY,
			tenant_id       INTEGER NOT NULL,
			fleet_id        INTEGER NOT NULL,
			hw_profile      TEXT NOT NULL DEFAULT '',
			fw_version      TEXT NOT NULL DEFAULT '',
			policy_version  INTEGER NOT NULL DEFAULT 0,
			capabilities    INTEGER NOT NULL DEFAULT 0,
			status          TEXT NOT NULL DEFAULT 'online',
			last_heartbeat  TEXT NOT NULL,
			last_audit_hmac TEXT NOT NULL DEFAULT '',
			site_id         TEXT NOT NULL DEFAULT '',
			registered_at   TEXT NOT NULL,
			flags           INTEGER NOT NULL DEFAULT 0,
			denied_total    INTEGER NOT NULL DEFAULT 0,
			allowed_total   INTEGER NOT NULL DEFAULT 0,
			warned_total    INTEGER NOT NULL DEFAULT 0,
			escalated_total INTEGER NOT NULL DEFAULT 0,
			flash_writes    INTEGER NOT NULL DEFAULT 0,
			last_uptime     INTEGER NOT NULL DEFAULT 0,
			prev_denied     INTEGER NOT NULL DEFAULT 0,
			prev_allowed    INTEGER NOT NULL DEFAULT 0,
			prev_warned     INTEGER NOT NULL DEFAULT 0,
			prev_escalated  INTEGER NOT NULL DEFAULT 0,
			boot_epoch      INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return fmt.Errorf("create devices table: %w", err)
	}

	// NEW-3 migration: add replay detection columns to existing databases.
	// ALTER TABLE ADD COLUMN is idempotent with IF NOT EXISTS in modern SQLite,
	// but modernc.org/sqlite may not support that syntax, so we catch errors.
	for _, col := range []string{
		"ALTER TABLE devices ADD COLUMN last_uptime INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN prev_denied INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN prev_allowed INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN warned_total INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN escalated_total INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN prev_warned INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN prev_escalated INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN boot_epoch INTEGER NOT NULL DEFAULT 0",
	} {
		if _, err := db.Exec(col); err != nil {
			// Ignore "duplicate column name" — column already exists.
			if !isDuplicateColumnErr(err) {
				return fmt.Errorf("migrate devices table: %w", err)
			}
		}
	}

	// Index for efficient tenant+fleet queries
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_devices_tenant_fleet
		ON devices (tenant_id, fleet_id)
	`)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	// Per-device HMAC signing keys (32 bytes each, hex-encoded in storage).
	// Each device gets a unique random key generated at registration time.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS device_keys (
			device_id  INTEGER PRIMARY KEY,
			key_hex    TEXT NOT NULL,
			created_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create device_keys table: %w", err)
	}

	// M-12: Decommission tombstones — persist decommissioned device IDs so
	// that re-registration can detect previously decommissioned devices even
	// after a gateway restart.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS decommissioned_devices (
			device_id INTEGER PRIMARY KEY
		)
	`)
	if err != nil {
		return fmt.Errorf("create decommissioned_devices table: %w", err)
	}

	return nil
}

func (s *SQLiteStore) SaveDevice(dev *manager.Device) error {
	hmacHex := hex.EncodeToString(dev.LastAuditHMAC)

	_, err := s.db.Exec(`
		INSERT INTO devices (
			device_id, tenant_id, fleet_id, hw_profile, fw_version,
			policy_version, capabilities, status, last_heartbeat,
			last_audit_hmac, site_id, registered_at, flags,
			denied_total, allowed_total, warned_total, escalated_total,
			flash_writes, last_uptime, prev_denied, prev_allowed,
			prev_warned, prev_escalated, boot_epoch
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			hw_profile      = excluded.hw_profile,
			fw_version      = excluded.fw_version,
			policy_version  = excluded.policy_version,
			capabilities    = excluded.capabilities,
			status          = excluded.status,
			last_heartbeat  = excluded.last_heartbeat,
			last_audit_hmac = excluded.last_audit_hmac,
			site_id         = excluded.site_id,
			flags           = excluded.flags,
			denied_total    = excluded.denied_total,
			allowed_total   = excluded.allowed_total,
			warned_total    = excluded.warned_total,
			escalated_total = excluded.escalated_total,
			flash_writes    = excluded.flash_writes,
			last_uptime     = excluded.last_uptime,
			prev_denied     = excluded.prev_denied,
			prev_allowed    = excluded.prev_allowed,
			prev_warned     = excluded.prev_warned,
			prev_escalated  = excluded.prev_escalated,
			boot_epoch      = excluded.boot_epoch
	`,
		dev.DeviceID, dev.TenantID, dev.FleetID,
		dev.HWProfile, dev.FWVersion,
		dev.PolicyVersion, dev.Capabilities,
		string(dev.Status), dev.LastHeartbeat.Format(time.RFC3339),
		hmacHex, dev.SiteID, dev.RegisteredAt.Format(time.RFC3339),
		dev.Flags, dev.DeniedTotal, dev.AllowedTotal,
		dev.WarnedTotal, dev.EscalatedTotal,
		dev.FlashWrites, dev.LastUptime, dev.PrevDenied, dev.PrevAllowed,
		dev.PrevWarned, dev.PrevEscalated, dev.BootEpoch,
	)
	if err != nil {
		return fmt.Errorf("upsert device %d: %w", dev.DeviceID, err)
	}
	return nil
}

func (s *SQLiteStore) LoadDevice(tenantID, fleetID uint16, deviceID uint32) (*manager.Device, error) {
	fullID := manager.ComposeID(tenantID, fleetID, deviceID)

	row := s.db.QueryRow(`
		SELECT device_id, tenant_id, fleet_id, hw_profile, fw_version,
		       policy_version, capabilities, status, last_heartbeat,
		       last_audit_hmac, site_id, registered_at, flags,
		       denied_total, allowed_total, warned_total, escalated_total,
		       flash_writes, last_uptime, prev_denied, prev_allowed,
		       prev_warned, prev_escalated, boot_epoch
		FROM devices WHERE device_id = ?
	`, fullID)

	return scanDevice(row)
}

func (s *SQLiteStore) ListDevices() ([]*manager.Device, error) {
	rows, err := s.db.Query(`
		SELECT device_id, tenant_id, fleet_id, hw_profile, fw_version,
		       policy_version, capabilities, status, last_heartbeat,
		       last_audit_hmac, site_id, registered_at, flags,
		       denied_total, allowed_total, warned_total, escalated_total,
		       flash_writes, last_uptime, prev_denied, prev_allowed,
		       prev_warned, prev_escalated, boot_epoch
		FROM devices ORDER BY device_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []*manager.Device
	for rows.Next() {
		dev, err := scanDeviceRows(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, dev)
	}
	return devices, rows.Err()
}

func (s *SQLiteStore) DeleteDevice(tenantID, fleetID uint16, deviceID uint32) error {
	fullID := manager.ComposeID(tenantID, fleetID, deviceID)
	_, err := s.db.Exec("DELETE FROM devices WHERE device_id = ?", fullID)
	if err != nil {
		return fmt.Errorf("delete device %d: %w", fullID, err)
	}
	return nil
}

// SaveDeviceKey persists a per-device HMAC signing key (32 bytes).
// The key is stored hex-encoded. Upsert semantics: replaces existing key.
func (s *SQLiteStore) SaveDeviceKey(deviceID uint64, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("device key must be exactly 32 bytes, got %d", len(key))
	}
	keyHex := hex.EncodeToString(key)
	_, err := s.db.Exec(`
		INSERT INTO device_keys (device_id, key_hex, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			key_hex    = excluded.key_hex,
			created_at = excluded.created_at
	`, deviceID, keyHex, time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("save device key %d: %w", deviceID, err)
	}
	return nil
}

// LoadDeviceKey retrieves the per-device HMAC signing key.
// Returns nil, nil if no key is stored for the device.
func (s *SQLiteStore) LoadDeviceKey(deviceID uint64) ([]byte, error) {
	var keyHex string
	err := s.db.QueryRow(`SELECT key_hex FROM device_keys WHERE device_id = ?`, deviceID).Scan(&keyHex)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load device key %d: %w", deviceID, err)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode device key hex for %d: %w", deviceID, err)
	}
	return key, nil
}

// DeleteDeviceKey removes the per-device HMAC signing key.
// NEW-5 fix: Called during device decommission to revoke the key.
func (s *SQLiteStore) DeleteDeviceKey(deviceID uint64) error {
	_, err := s.db.Exec("DELETE FROM device_keys WHERE device_id = ?", deviceID)
	if err != nil {
		return fmt.Errorf("delete device key %d: %w", deviceID, err)
	}
	return nil
}

// SaveDecommissioned records a device ID as decommissioned (M-12).
func (s *SQLiteStore) SaveDecommissioned(deviceID uint64) error {
	_, err := s.db.Exec(
		"INSERT OR IGNORE INTO decommissioned_devices (device_id) VALUES (?)", deviceID)
	if err != nil {
		return fmt.Errorf("save decommissioned %d: %w", deviceID, err)
	}
	return nil
}

// LoadDecommissioned returns all decommissioned device IDs (M-12).
func (s *SQLiteStore) LoadDecommissioned() ([]uint64, error) {
	rows, err := s.db.Query("SELECT device_id FROM decommissioned_devices")
	if err != nil {
		return nil, fmt.Errorf("load decommissioned: %w", err)
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan decommissioned: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeleteDecommissioned removes a device from the tombstone table on re-registration (M-12).
func (s *SQLiteStore) DeleteDecommissioned(deviceID uint64) error {
	_, err := s.db.Exec("DELETE FROM decommissioned_devices WHERE device_id = ?", deviceID)
	if err != nil {
		return fmt.Errorf("delete decommissioned %d: %w", deviceID, err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// isDuplicateColumnErr returns true if the error indicates that the column
// already exists (e.g., from ALTER TABLE ADD COLUMN on an already-migrated DB).
func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column")
}

// scanner is an interface satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanDeviceFromScanner(s scanner) (*manager.Device, error) {
	var (
		dev          manager.Device
		status       string
		lastHB       string
		hmacHex      string
		registeredAt string
	)

	err := s.Scan(
		&dev.DeviceID, &dev.TenantID, &dev.FleetID,
		&dev.HWProfile, &dev.FWVersion,
		&dev.PolicyVersion, &dev.Capabilities,
		&status, &lastHB, &hmacHex, &dev.SiteID,
		&registeredAt, &dev.Flags,
		&dev.DeniedTotal, &dev.AllowedTotal,
		&dev.WarnedTotal, &dev.EscalatedTotal,
		&dev.FlashWrites, &dev.LastUptime,
		&dev.PrevDenied, &dev.PrevAllowed,
		&dev.PrevWarned, &dev.PrevEscalated,
		&dev.BootEpoch,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan device: %w", err)
	}

	dev.Status = manager.DeviceStatus(status)

	if t, err := time.Parse(time.RFC3339, lastHB); err == nil {
		dev.LastHeartbeat = t
	}
	if t, err := time.Parse(time.RFC3339, registeredAt); err == nil {
		dev.RegisteredAt = t
	}
	if hmacHex != "" {
		if hmacBytes, err := hex.DecodeString(hmacHex); err != nil {
			log.Printf("[fleet] invalid audit HMAC hex in store for device %d: %v", dev.DeviceID, err)
		} else {
			dev.LastAuditHMAC = hmacBytes
		}
	}

	return &dev, nil
}

func scanDevice(row *sql.Row) (*manager.Device, error) {
	return scanDeviceFromScanner(row)
}

func scanDeviceRows(rows *sql.Rows) (*manager.Device, error) {
	return scanDeviceFromScanner(rows)
}
