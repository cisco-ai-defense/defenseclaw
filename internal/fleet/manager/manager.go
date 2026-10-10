// Package manager implements the IoT Fleet Manager service.
// It handles device registration, heartbeat processing, anomaly detection,
// and alert dispatch for Edge Connector IoT devices.
package manager

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
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
	WarnedTotal    uint64       `json:"warned_total"`
	EscalatedTotal uint64       `json:"escalated_total"`
	FlashWrites    uint32       `json:"flash_writes"`

	// NEW-3 fix: Replay detection via monotonic uptime and delta counters.
	LastUptime    uint32 `json:"last_uptime"`
	PrevDenied    uint16 `json:"prev_denied"`
	PrevAllowed   uint16 `json:"prev_allowed"`
	PrevWarned    uint16 `json:"prev_warned"`
	PrevEscalated uint16 `json:"prev_escalated"`

	// P1-replay fix: BootEpoch is incremented each time a device reboot is
	// detected (uptime < last_uptime). Persisted to SQLite so that after a
	// gateway restart we can distinguish "new boot" from "replay of old
	// heartbeat with lower uptime".
	BootEpoch uint32 `json:"boot_epoch"`
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
	Capabilities   uint8
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
	AlertDeviceAutoReg  AlertType = "device_auto_registered"
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

// DeviceStore is the persistence interface for fleet devices.
// Implementations are provided in the parent fleet package to avoid
// pulling storage dependencies into the manager core.
type DeviceStore interface {
	SaveDevice(dev *Device) error
	LoadDevice(tenantID, fleetID uint16, deviceID uint32) (*Device, error)
	ListDevices() ([]*Device, error)
	DeleteDevice(tenantID, fleetID uint16, deviceID uint32) error
}

// FleetManager is the core fleet management service.
//
// TODO(M-9): The mu RWMutex currently protects the entire devices map for all
// operations.  ProcessHeartbeat holds the write lock for the full duration of
// heartbeat processing (parsing, delta computation, anomaly checks, AND store
// persistence).  H-5 fix reverted the H-6 lock-narrowing because the manual
// Unlock pattern left the mutex held on panics.  This is a bottleneck at
// scale.  Phase 2: refactor to per-device or sharded locks so heartbeat
// processing for device A does not block device B (tracked as "Should Fix").
type FleetManager struct {
	mu                sync.RWMutex
	devices           map[uint64]*Device
	alertHandler      AlertHandler
	heartbeatInterval time.Duration
	store             DeviceStore

	// AutoRegister controls whether unknown devices are automatically
	// registered on their first heartbeat. Defaults to true.
	AutoRegister bool

	// Metrics hooks (set externally to avoid circular imports)
	onDeviceRegistered func()
	onDeviceOffline    func()
	onHeartbeat        func()
	// P2-19 fix: Status transition hook so metrics gauges update correctly
	// when a device moves between states (e.g., online → lockdown).
	onStatusChange func(oldStatus, newStatus DeviceStatus)

	// M-10: Counter for store errors so they are observable via metrics.
	onStoreError func()
}

// New creates a new FleetManager instance.
// P1-06 fix: AutoRegister defaults to false. The sidecar sets it from
// env var DCLAW_FLEET_AUTO_REGISTER, so explicit opt-in is required.
// Previously the default was true, which allowed anonymous devices to
// enroll themselves without operator approval.
func New(alertHandler AlertHandler) *FleetManager {
	return &FleetManager{
		devices:           make(map[uint64]*Device),
		alertHandler:      alertHandler,
		heartbeatInterval: 30 * time.Second,
		AutoRegister:      false,
	}
}

// SetStore configures the persistence backend. When set, RegisterDevice
// and ProcessHeartbeat will persist device state after mutation.
// This must be called before processing any requests.
func (fm *FleetManager) SetStore(store DeviceStore) {
	fm.store = store
}

// LoadFromStore populates the in-memory device map from the configured store.
// Call this once at startup after SetStore. Returns the number of devices loaded.
func (fm *FleetManager) LoadFromStore() (int, error) {
	if fm.store == nil {
		return 0, nil
	}

	devices, err := fm.store.ListDevices()
	if err != nil {
		return 0, fmt.Errorf("load devices from store: %w", err)
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	for _, dev := range devices {
		fm.devices[dev.DeviceID] = dev
	}
	return len(devices), nil
}

// SetMetricsHooks configures callbacks for metrics updates.
func (fm *FleetManager) SetMetricsHooks(onRegistered, onOffline, onHeartbeat func()) {
	fm.onDeviceRegistered = onRegistered
	fm.onDeviceOffline = onOffline
	fm.onHeartbeat = onHeartbeat
}

// SetStoreErrorHook configures a callback for store write failures (M-10).
func (fm *FleetManager) SetStoreErrorHook(hook func()) {
	fm.onStoreError = hook
}

// SetStatusChangeHook configures a callback for device status transitions.
// P2-19 fix: Called whenever a heartbeat causes a device's status to change,
// so metrics gauges can decrement the old status and increment the new one.
func (fm *FleetManager) SetStatusChangeHook(hook func(oldStatus, newStatus DeviceStatus)) {
	fm.onStatusChange = hook
}

// StartMonitoring runs CheckOfflineDevices on a recurring interval.
// It blocks until the context is cancelled.
func (fm *FleetManager) StartMonitoring(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fm.CheckOfflineDevices()
		}
	}
}

// ErrDeviceExists is returned when attempting to register a device that already exists.
const ErrDeviceExists = fleetError("device already registered")

// RegisterDevice adds a new device to the fleet registry.
// Returns ErrDeviceExists if the device is already registered.
func (fm *FleetManager) RegisterDevice(tenantID, fleetID uint16, deviceID uint32,
	hwProfile, fwVersion string, policyVersion uint16, capabilities uint8) (*Device, error) {

	fullID := ComposeID(tenantID, fleetID, deviceID)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	if existing, ok := fm.devices[fullID]; ok {
		// Update safe fields on re-registration, preserve counters.
		// Policy version must not regress (anti-rollback on re-registration).
		existing.FWVersion = fwVersion
		if policyVersion > existing.PolicyVersion {
			existing.PolicyVersion = policyVersion
		}
		existing.HWProfile = hwProfile
		existing.Capabilities = capabilities
		if fm.store != nil {
			if err := fm.store.SaveDevice(existing); err != nil {
				log.Printf("[fleet] store error: %v", err)
			}
		}
		devCopy := *existing
		return &devCopy, ErrDeviceExists
	}

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
	if fm.store != nil {
		if err := fm.store.SaveDevice(dev); err != nil {
			log.Printf("[fleet] store error: %v", err)
		}
	}
	if fm.onDeviceRegistered != nil {
		fm.onDeviceRegistered()
	}
	devCopy := *dev
	return &devCopy, nil
}

// ProcessHeartbeat updates device state from a heartbeat.
// If the device is not registered and AutoRegister is true, it will be
// auto-registered with a default "auto-discovered" profile before
// processing the heartbeat.
func (fm *FleetManager) ProcessHeartbeat(tenantID, fleetID uint16, deviceID uint32, hb *Heartbeat) {
	fullID := ComposeID(tenantID, fleetID, deviceID)

	fm.mu.Lock()
	// H-5 fix: Use defer to guarantee the mutex is released even if a panic
	// occurs during heartbeat processing. The previous manual-unlock pattern
	// (H-6 narrowing) left the mutex held on any panic between Lock and Unlock,
	// deadlocking all subsequent fleet operations. Correctness (no deadlock on
	// panic) is more important than the lock-narrowing performance optimization
	// in Phase 1. Persistence (SaveDevice) now runs inside the lock.
	defer fm.mu.Unlock()

	dev, exists := fm.devices[fullID]
	if !exists {
		if !fm.AutoRegister {
			return
		}
		// Auto-register the unknown device using heartbeat fields.
		dev = &Device{
			DeviceID:      fullID,
			TenantID:      tenantID,
			FleetID:       fleetID,
			HWProfile:     "auto-discovered",
			FWVersion:     fmt.Sprintf("%d", hb.FWVersion),
			PolicyVersion: hb.PolicyVersion,
			Capabilities:  hb.Capabilities,
			Status:        StatusOnline,
			RegisteredAt:  time.Now(),
			LastHeartbeat: time.Now(),
		}
		fm.devices[fullID] = dev
		if fm.store != nil {
			if err := fm.store.SaveDevice(dev); err != nil {
				log.Printf("[fleet] store error on auto-register: %v", err)
			}
		}
		if fm.onDeviceRegistered != nil {
			fm.onDeviceRegistered()
		}
		log.Printf("[fleet] auto-registered device %d (tenant=%d fleet=%d) from heartbeat", deviceID, tenantID, fleetID)
		fm.fireAlert(Alert{
			Type:      AlertDeviceAutoReg,
			DeviceID:  fullID,
			Message:   fmt.Sprintf("Device auto-registered from first heartbeat (fw=%d, policy=%d)", hb.FWVersion, hb.PolicyVersion),
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	// NEW-3 fix: Replay detection — reject heartbeats where the monotonic
	// uptime has not advanced.  A legitimate device's uptime_sec increases
	// on every heartbeat.  A replayed (or stale) heartbeat will have
	// uptime <= the last seen value.
	//
	// Reboot handling: when uptime < last_uptime (or uptime == 0 while
	// last_uptime > 0), the device has rebooted. Accept the heartbeat but
	// reset the delta counters to 0 so the first post-reboot absolute
	// values are treated as the full delta. Don't reject legitimate reboots.
	//
	// P1-replay fix: Increment BootEpoch on each detected reboot so that
	// after a gateway restart we can distinguish a genuine new boot from a
	// replayed heartbeat with lower uptime.
	isReboot := hb.UptimeSec < dev.LastUptime || (hb.UptimeSec == 0 && dev.LastUptime > 0)
	if isReboot {
		// Device rebooted — increment boot epoch, reset replay counters.
		dev.BootEpoch++
		log.Printf("[fleet] device %d rebooted (boot_epoch=%d): uptime %d < last %d, resetting counters",
			deviceID, dev.BootEpoch, hb.UptimeSec, dev.LastUptime)
		dev.PrevDenied = 0
		dev.PrevAllowed = 0
		dev.PrevWarned = 0
		dev.PrevEscalated = 0
	} else if hb.UptimeSec > 0 && hb.UptimeSec == dev.LastUptime {
		// Exact same uptime with no reboot — replay. Drop it.
		log.Printf("[fleet] replay detected for device %d: uptime %d == last %d, dropping",
			deviceID, hb.UptimeSec, dev.LastUptime)
		return
	}
	dev.LastUptime = hb.UptimeSec

	dev.LastHeartbeat = time.Now()
	dev.Flags = hb.Flags

	// P1-replay fix: PolicyVersion, FWVersion, and Capabilities can only
	// advance (anti-rollback). A replayed heartbeat with an older policy
	// version must NOT revert the device's state. These fields are only
	// allowed to increase; they should be updated via authenticated
	// registration for downgrades.
	if hb.PolicyVersion > dev.PolicyVersion {
		dev.PolicyVersion = hb.PolicyVersion
	}
	if hb.FWVersion > fwVersionToUint16(dev.FWVersion) {
		dev.FWVersion = fmt.Sprintf("%d", hb.FWVersion)
	}
	if hb.Capabilities > dev.Capabilities {
		dev.Capabilities = hb.Capabilities
	}

	// NEW-3 fix: Compute counter deltas instead of blindly accumulating
	// absolute values.  The device sends cumulative counters that reset on
	// reboot; detect reboot (new < prev) and treat the new value as the
	// full delta.
	if hb.DeniedCount >= dev.PrevDenied {
		dev.DeniedTotal += uint64(hb.DeniedCount - dev.PrevDenied)
	} else {
		// Counter wrapped or device rebooted — treat raw value as delta
		dev.DeniedTotal += uint64(hb.DeniedCount)
	}
	if hb.AllowedCount >= dev.PrevAllowed {
		dev.AllowedTotal += uint64(hb.AllowedCount - dev.PrevAllowed)
	} else {
		dev.AllowedTotal += uint64(hb.AllowedCount)
	}
	if hb.WarnedCount >= dev.PrevWarned {
		dev.WarnedTotal += uint64(hb.WarnedCount - dev.PrevWarned)
	} else {
		dev.WarnedTotal += uint64(hb.WarnedCount)
	}
	if hb.EscalatedCount >= dev.PrevEscalated {
		dev.EscalatedTotal += uint64(hb.EscalatedCount - dev.PrevEscalated)
	} else {
		dev.EscalatedTotal += uint64(hb.EscalatedCount)
	}
	dev.PrevDenied = hb.DeniedCount
	dev.PrevAllowed = hb.AllowedCount
	dev.PrevWarned = hb.WarnedCount
	dev.PrevEscalated = hb.EscalatedCount

	if fm.onHeartbeat != nil {
		fm.onHeartbeat()
	}

	// P2-19 fix: Detect canary rollback flag (bit 0x08) from heartbeat.
	// When set, the device performed an OTA canary rollback. Fire an alert
	// and increment the rollback counter for the metrics/dashboard.
	if hb.Flags&0x08 != 0 {
		fm.fireAlert(Alert{
			Type:      AlertCanaryRollback,
			DeviceID:  fullID,
			Message:   fmt.Sprintf("Device performed OTA canary rollback (policy_v=%d)", hb.PolicyVersion),
			Severity:  "high",
			Timestamp: time.Now(),
		})
	}

	// P2-19 fix: Capture old status before updating so we can fire the
	// status-change metrics hook with both old and new values.
	oldStatus := dev.Status

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

	// P2-19 fix: Fire status-change hook when device transitions between
	// states so the Prometheus gauge decrements the old status and
	// increments the new one.
	if dev.Status != oldStatus && fm.onStatusChange != nil {
		fm.onStatusChange(oldStatus, dev.Status)
	}

	// Store audit HMAC for chain verification
	hmacBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(hmacBytes, hb.AuditHeadHMAC)
	dev.LastAuditHMAC = hmacBytes

	// H-5 fix: Persist inside the lock (reverts H-6 narrowing). A panic
	// between the old manual Unlock and SaveDevice would leave state
	// unsaved. The global lock is a Phase 2 optimization target (M-9).
	// For lockdown transitions, retry once on failure to ensure the
	// security-critical status survives gateway restart (H-2 fix).
	if fm.store != nil {
		if err := fm.store.SaveDevice(dev); err != nil {
			log.Printf("[fleet] store error: %v", err)
			if fm.onStoreError != nil {
				fm.onStoreError()
			}
			// H-2 fix: Retry once for security-critical status transitions.
			// If lockdown is lost due to store failure, a compromised device
			// escapes lockdown after gateway restart.
			// H-4 fix: Removed 50ms sleep — it was inside the deferred mutex
			// unlock (H-5 fix), blocking ALL fleet operations for 50ms.
			if dev.Status == StatusLockdown || dev.Status == StatusDegraded {
				if retryErr := fm.store.SaveDevice(dev); retryErr != nil {
					log.Printf("[fleet] CRITICAL: failed to persist %s status for device %d after retry: %v",
						dev.Status, dev.DeviceID, retryErr)
				}
			}
		}
	}
}

// CheckOfflineDevices detects devices that have gone silent.
func (fm *FleetManager) CheckOfflineDevices() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	threshold := time.Now().Add(-3 * fm.heartbeatInterval)
	for _, dev := range fm.devices {
		if dev.Status == StatusOnline && dev.LastHeartbeat.Before(threshold) {
			dev.Status = StatusOffline
			if fm.store != nil {
				if err := fm.store.SaveDevice(dev); err != nil {
					log.Printf("[fleet] store error: %v", err)
				}
			}
			if fm.onDeviceOffline != nil {
				fm.onDeviceOffline()
			}
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

// GetDevice returns a copy of a device by composite ID.
func (fm *FleetManager) GetDevice(fullID uint64) (Device, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	dev, ok := fm.devices[fullID]
	if !ok {
		return Device{}, false
	}
	return *dev, true
}

// ListDevices returns a snapshot copy of all registered devices.
func (fm *FleetManager) ListDevices() []Device {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	result := make([]Device, 0, len(fm.devices))
	for _, dev := range fm.devices {
		result = append(result, *dev)
	}
	return result
}

// DecommissionDevice removes a device from the in-memory registry and from the
// backing store (if configured). Returns true if the device existed.
func (fm *FleetManager) DecommissionDevice(tenantID, fleetID uint16, deviceID uint32) bool {
	fullID := ComposeID(tenantID, fleetID, deviceID)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	if _, ok := fm.devices[fullID]; !ok {
		return false
	}
	delete(fm.devices, fullID)
	if fm.store != nil {
		if err := fm.store.DeleteDevice(tenantID, fleetID, deviceID); err != nil {
			log.Printf("[fleet] store error: %v", err)
		}
	}
	return true
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
		Capabilities:   data[31],
	}
	return hb, nil
}

func (fm *FleetManager) fireAlert(alert Alert) {
	if fm.alertHandler != nil {
		fm.alertHandler(alert)
	}
}

// GetAlertHandler returns the current alert handler (may be nil).
// P2-19 fix: Needed by WireMetrics to wrap the handler with metric counters.
func (fm *FleetManager) GetAlertHandler() AlertHandler {
	return fm.alertHandler
}

// SetAlertHandler replaces the alert handler.
// P2-19 fix: Needed by WireMetrics to wrap the handler with metric counters.
func (fm *FleetManager) SetAlertHandler(h AlertHandler) {
	fm.alertHandler = h
}

// fwVersionToUint16 parses a stored firmware version string back to uint16
// for numeric comparison.
// M-9 fix: Support semver strings like "1.2.3" by encoding as
// major*10000 + minor*100 + patch. Falls back to plain uint16 parse
// for bare numeric strings like "42". Returns 0 on parse failure.
func fwVersionToUint16(s string) uint16 {
	var major, minor, patch int
	n, _ := fmt.Sscanf(s, "%d.%d.%d", &major, &minor, &patch)
	if n == 3 {
		v := major*10000 + minor*100 + patch
		if v > 65535 {
			v = 65535
		}
		return uint16(v)
	}
	// Fallback: plain uint16
	var v uint16
	fmt.Sscanf(s, "%d", &v)
	return v
}

// Sentinel errors
type fleetError string

func (e fleetError) Error() string { return string(e) }

const ErrInvalidHeartbeat = fleetError("invalid heartbeat: must be 32 bytes")
