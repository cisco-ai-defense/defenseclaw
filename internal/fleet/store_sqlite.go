package fleet

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
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
			flash_writes    INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return fmt.Errorf("create devices table: %w", err)
	}

	// Index for efficient tenant+fleet queries
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_devices_tenant_fleet
		ON devices (tenant_id, fleet_id)
	`)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
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
			denied_total, allowed_total, flash_writes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			hw_profile     = excluded.hw_profile,
			fw_version     = excluded.fw_version,
			policy_version = excluded.policy_version,
			capabilities   = excluded.capabilities,
			status         = excluded.status,
			last_heartbeat = excluded.last_heartbeat,
			last_audit_hmac= excluded.last_audit_hmac,
			site_id        = excluded.site_id,
			flags          = excluded.flags,
			denied_total   = excluded.denied_total,
			allowed_total  = excluded.allowed_total,
			flash_writes   = excluded.flash_writes
	`,
		dev.DeviceID, dev.TenantID, dev.FleetID,
		dev.HWProfile, dev.FWVersion,
		dev.PolicyVersion, dev.Capabilities,
		string(dev.Status), dev.LastHeartbeat.Format(time.RFC3339),
		hmacHex, dev.SiteID, dev.RegisteredAt.Format(time.RFC3339),
		dev.Flags, dev.DeniedTotal, dev.AllowedTotal, dev.FlashWrites,
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
		       denied_total, allowed_total, flash_writes
		FROM devices WHERE device_id = ?
	`, fullID)

	return scanDevice(row)
}

func (s *SQLiteStore) ListDevices() ([]*manager.Device, error) {
	rows, err := s.db.Query(`
		SELECT device_id, tenant_id, fleet_id, hw_profile, fw_version,
		       policy_version, capabilities, status, last_heartbeat,
		       last_audit_hmac, site_id, registered_at, flags,
		       denied_total, allowed_total, flash_writes
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

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// scanner is an interface satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanDeviceFromScanner(s scanner) (*manager.Device, error) {
	var (
		dev         manager.Device
		status      string
		lastHB      string
		hmacHex     string
		registeredAt string
	)

	err := s.Scan(
		&dev.DeviceID, &dev.TenantID, &dev.FleetID,
		&dev.HWProfile, &dev.FWVersion,
		&dev.PolicyVersion, &dev.Capabilities,
		&status, &lastHB, &hmacHex, &dev.SiteID,
		&registeredAt, &dev.Flags,
		&dev.DeniedTotal, &dev.AllowedTotal, &dev.FlashWrites,
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
