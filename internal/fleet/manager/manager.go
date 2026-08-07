// Package manager implements the IoT Fleet Manager service.
// It handles device registration, heartbeat processing, anomaly detection,
// and alert dispatch for DefenseClaw Lite IoT devices.
package manager

import (
	"encoding/binary"
	"sync"
	"time"
)

// DeviceStatus represents the current state of a fleet device.
type DeviceStatus string

const (
	StatusOnline   DeviceStatus = "online"
	StatusOffline  DeviceStatus = "offline"
	StatusDegraded DeviceStatus = "degraded"
	StatusLockdown DeviceStatus = "lockdown"
)

// Device holds the registered state of an IoT device.
type Device struct {
	DeviceID       uint64       `json:"device_id"`
	TenantID       uint16       `json:"tenant_id"`
	FleetID        uint16       `json:"fleet_id"`
	HWProfile      string       `json:"hw_profile"`
	FWVersion      string       `json:"fw_version"`
	PolicyVersion  uint16       `json:"policy_version"`
	Capabilities   uint8        `json:"capabilities"`
	Status         DeviceStatus `json:"status"`
	LastHeartbeat  time.Time    `json:"last_heartbeat"`
	LastAuditHMAC  []byte       `json:"last_audit_hmac"`
	SiteID         string       `json:"site_id"`
	RegisteredAt   time.Time    `json:"registered_at"`
	Flags          uint8        `json:"flags"`
	DeniedTotal    uint64       `json:"denied_total"`
	AllowedTotal   uint64       `json:"allowed_total"`
	FlashWrites    uint32       `json:"flash_writes"`
}

// Heartbeat represents a parsed 32-byte device heartbeat.
type Heartbeat struct {
	DeviceID       uint32
	UptimeSec      uint32
	PolicyVersion  uint16
	FWVersion      uint16
	DeniedCount    uint16
	AllowedCount   uint16
	WarnedCount    uint16
	EscalatedCount uint16
	CacheHitPct    uint8
	SessionCount   uint8
	AuditHeadHMAC  uint64
	Flags          uint8
}

// AlertType defines fleet alert categories.
type AlertType string

const (
	AlertDeviceOffline  AlertType = "device_offline"
	AlertBlockSpike     AlertType = "block_spike"
	AlertTamperDetect   AlertType = "tamper_detect"
	AlertPolicyDrift    AlertType = "policy_drift"
	AlertCanaryRollback AlertType = "canary_rollback"
	AlertSEDegraded     AlertType = "se_degraded"
)

// Alert represents a fleet alert to dispatch.
type Alert struct {
	Type      AlertType `json:"type"`
	DeviceID  uint64    `json:"device_id"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertHandler is called when an anomaly is detected.
type AlertHandler func(alert Alert)

// FleetManager is the core fleet management service.
type FleetManager struct {
	mu            sync.RWMutex
	devices       map[uint64]*Device
	alertHandler  AlertHandler
	heartbeatInterval time.Duration
}

// New creates a new FleetManager instance.
func New(alertHandler AlertHandler) *FleetManager {
	return &FleetManager{
		devices:           make(map[uint64]*Device),
		alertHandler:      alertHandler,
		heartbeatInterval: 30 * time.Second,
	}
}

// RegisterDevice adds a new device to the fleet registry.
func (fm *FleetManager) RegisterDevice(tenantID, fleetID uint16, deviceID uint32,
	hwProfile, fwVersion string, policyVersion uint16, capabilities uint8) *Device {

	fullID := ComposeID(tenantID, fleetID, deviceID)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	dev := &Device{
		DeviceID:      fullID,
		TenantID:      tenantID,
		FleetID:       fleetID,
		HWProfile:     hwProfile,
		FWVersion:     fwVersion,
		PolicyVersion: policyVersion,
		Capabilities:  capabilities,
		Status:        StatusOnline,
		RegisteredAt:  time.Now(),
		LastHeartbeat: time.Now(),
	}
	fm.devices[fullID] = dev
	return dev
}

// ProcessHeartbeat updates device state from a heartbeat.
func (fm *FleetManager) ProcessHeartbeat(tenantID, fleetID uint16, deviceID uint32, hb *Heartbeat) {
	fullID := ComposeID(tenantID, fleetID, deviceID)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	dev, exists := fm.devices[fullID]
	if !exists {
		return
	}

	dev.LastHeartbeat = time.Now()
	dev.PolicyVersion = hb.PolicyVersion
	dev.Flags = hb.Flags
	dev.DeniedTotal += uint64(hb.DeniedCount)
	dev.AllowedTotal += uint64(hb.AllowedCount)

	// Update status based on flags
	if hb.Flags&0x04 != 0 { // TAMPER_DETECT
		dev.Status = StatusLockdown
		fm.fireAlert(Alert{
			Type:      AlertTamperDetect,
			DeviceID:  fullID,
			Message:   "Audit chain integrity failure detected",
			Severity:  "critical",
			Timestamp: time.Now(),
		})
	} else if hb.Flags&0x80 != 0 { // SE_DEGRADED
		dev.Status = StatusDegraded
		fm.fireAlert(Alert{
			Type:      AlertSEDegraded,
			DeviceID:  fullID,
			Message:   "Secure element in degraded mode",
			Severity:  "critical",
			Timestamp: time.Now(),
		})
	} else if hb.Flags&0x20 != 0 { // OFFLINE_MODE
		dev.Status = StatusDegraded
	} else {
		dev.Status = StatusOnline
	}

	// Store audit HMAC for chain verification
	hmacBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(hmacBytes, hb.AuditHeadHMAC)
	dev.LastAuditHMAC = hmacBytes
}

// CheckOfflineDevices detects devices that have gone silent.
func (fm *FleetManager) CheckOfflineDevices() {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	threshold := time.Now().Add(-3 * fm.heartbeatInterval)
	for _, dev := range fm.devices {
		if dev.Status == StatusOnline && dev.LastHeartbeat.Before(threshold) {
			fm.fireAlert(Alert{
				Type:      AlertDeviceOffline,
				DeviceID:  dev.DeviceID,
				Message:   "Device silent for >3× heartbeat interval",
				Severity:  "warning",
				Timestamp: time.Now(),
			})
		}
	}
}

// GetDevice returns a device by composite ID.
func (fm *FleetManager) GetDevice(fullID uint64) (*Device, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	dev, ok := fm.devices[fullID]
	return dev, ok
}

// GetFleetHealth returns aggregate fleet statistics.
func (fm *FleetManager) GetFleetHealth() FleetHealth {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	health := FleetHealth{
		PolicyVersions: make(map[uint16]int),
	}
	for _, dev := range fm.devices {
		health.TotalDevices++
		switch dev.Status {
		case StatusOnline:
			health.Online++
		case StatusOffline:
			health.Offline++
		case StatusDegraded:
			health.Degraded++
		case StatusLockdown:
			health.Lockdown++
		}
		health.PolicyVersions[dev.PolicyVersion]++
	}
	return health
}

// FleetHealth holds aggregate fleet status.
type FleetHealth struct {
	TotalDevices   int            `json:"total_devices"`
	Online         int            `json:"online"`
	Offline        int            `json:"offline"`
	Degraded       int            `json:"degraded"`
	Lockdown       int            `json:"lockdown"`
	PolicyVersions map[uint16]int `json:"policy_versions"`
}

// ComposeID creates a 64-bit composite device identity.
func ComposeID(tenantID, fleetID uint16, deviceID uint32) uint64 {
	return (uint64(tenantID) << 48) | (uint64(fleetID) << 32) | uint64(deviceID)
}

// ParseHeartbeat decodes a 32-byte heartbeat wire format.
func ParseHeartbeat(data []byte) (*Heartbeat, error) {
	if len(data) != 32 {
		return nil, ErrInvalidHeartbeat
	}
	hb := &Heartbeat{
		DeviceID:       binary.BigEndian.Uint32(data[0:4]),
		UptimeSec:      binary.BigEndian.Uint32(data[4:8]),
		PolicyVersion:  binary.BigEndian.Uint16(data[8:10]),
		FWVersion:      binary.BigEndian.Uint16(data[10:12]),
		DeniedCount:    binary.BigEndian.Uint16(data[12:14]),
		AllowedCount:   binary.BigEndian.Uint16(data[14:16]),
		WarnedCount:    binary.BigEndian.Uint16(data[16:18]),
		EscalatedCount: binary.BigEndian.Uint16(data[18:20]),
		CacheHitPct:    data[20],
		SessionCount:   data[21],
		AuditHeadHMAC:  binary.BigEndian.Uint64(data[22:30]),
		Flags:          data[30],
	}
	return hb, nil
}

func (fm *FleetManager) fireAlert(alert Alert) {
	if fm.alertHandler != nil {
		fm.alertHandler(alert)
	}
}

// Sentinel errors
type fleetError string

func (e fleetError) Error() string { return string(e) }

const ErrInvalidHeartbeat = fleetError("invalid heartbeat: must be 32 bytes")
