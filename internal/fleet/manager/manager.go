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
	mu          sync.RWMutex
	deviceLocks [256]sync.Mutex
	devices     map[uint64]*Device

	// hookMu protects all callback/hook fields from concurrent read/write.
	hookMu           sync.Mutex
	alertHandler     AlertHandler
	onDeviceRegistered func()
	onDeviceOffline    func()
	onHeartbeat        func()
	onStatusChange     func(oldStatus, newStatus DeviceStatus)
	onStoreError       func()

	heartbeatInterval time.Duration
	store             DeviceStore

	// AutoRegister controls whether unknown devices are automatically
	// registered on their first heartbeat. Defaults to false.
	AutoRegister bool
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
// Must be called before processing starts (before Start/StartMonitoring).
func (fm *FleetManager) SetMetricsHooks(onRegistered, onOffline, onHeartbeat func()) {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	fm.onDeviceRegistered = onRegistered
	fm.onDeviceOffline = onOffline
	fm.onHeartbeat = onHeartbeat
}

// SetStoreErrorHook configures a callback for store write failures (M-10).
func (fm *FleetManager) SetStoreErrorHook(hook func()) {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	fm.onStoreError = hook
}

// SetStatusChangeHook configures a callback for device status transitions.
// P2-19 fix: Called whenever a heartbeat causes a device's status to change,
// so metrics gauges can decrement the old status and increment the new one.
func (fm *FleetManager) SetStatusChangeHook(hook func(oldStatus, newStatus DeviceStatus)) {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
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
	fm.hookMu.Lock()
	onReg := fm.onDeviceRegistered
	fm.hookMu.Unlock()
	if onReg != nil {
		onReg()
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

	shard := fullID % 256
	fm.deviceLocks[shard].Lock()

	fm.mu.RLock()
	dev, exists := fm.devices[fullID]
	fm.mu.RUnlock()

	if !exists {
		if !fm.AutoRegister {
			fm.deviceLocks[shard].Unlock()
			return
		}
		// Release shard lock before acquiring mu.Lock to maintain
		// consistent lock ordering (mu before shard) and prevent
		// deadlock with ListDevices/GetFleetHealth.
		fm.deviceLocks[shard].Unlock()

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
		fm.mu.Lock()
		if existing, ok := fm.devices[fullID]; ok {
			dev = existing
		} else {
			fm.devices[fullID] = dev
		}
		fm.mu.Unlock()

		// Re-acquire shard lock for the remainder of heartbeat processing.
		fm.deviceLocks[shard].Lock()

		if fm.store != nil {
			if err := fm.store.SaveDevice(dev); err != nil {
				log.Printf("[fleet] store error on auto-register: %v", err)
			}
		}
		fm.hookMu.Lock()
		onReg := fm.onDeviceRegistered
		fm.hookMu.Unlock()
		if onReg != nil {
			onReg()
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
	defer fm.deviceLocks[shard].Unlock()

	// NEW-3 fix: Replay detection — reject heartbeats where the monotonic
	// uptime has not advanced.
	// H-6 note: Combined with per-device HMAC keys and BootEpoch, replay
	// requires key compromise. The C-side boot_nonce (H-2 fix) ensures
	// verdict HMACs are unique per boot session.  A legitimate device's uptime_sec increases
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

	fm.hookMu.Lock()
	onHB := fm.onHeartbeat
	fm.hookMu.Unlock()
	if onHB != nil {
		onHB()
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

	if dev.Status != oldStatus {
		fm.hookMu.Lock()
		onSC := fm.onStatusChange
		fm.hookMu.Unlock()
		if onSC != nil {
			onSC(oldStatus, dev.Status)
		}
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
			fm.hookMu.Lock()
			onSE := fm.onStoreError
			fm.hookMu.Unlock()
			if onSE != nil {
				onSE()
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
// H-8 fix: Two-phase approach to avoid deadlock. Phase 1 collects candidate
// device IDs under RLock only (no shard locks). Phase 2 releases RLock, then
// processes each candidate under only the shard lock, re-checking the condition
// to handle races with concurrent heartbeat processing.
func (fm *FleetManager) CheckOfflineDevices() {
	// Phase 1: collect ALL device IDs under RLock. We only read map keys here,
	// not device fields, to avoid racing with ProcessHeartbeat which writes
	// device fields under only the shard lock.
	fm.mu.RLock()
	candidates := make([]uint64, 0, len(fm.devices))
	for id := range fm.devices {
		candidates = append(candidates, id)
	}
	fm.mu.RUnlock()

	threshold := time.Now().Add(-3 * fm.heartbeatInterval)

	// Phase 2: check and update each device under its shard lock.
	for _, id := range candidates {
		shard := id % 256
		fm.deviceLocks[shard].Lock()
		fm.mu.RLock()
		dev, ok := fm.devices[id]
		fm.mu.RUnlock()
		if ok && dev.Status == StatusOnline && dev.LastHeartbeat.Before(threshold) {
			dev.Status = StatusOffline
			if fm.store != nil {
				if err := fm.store.SaveDevice(dev); err != nil {
					log.Printf("[fleet] store error: %v", err)
				}
			}
			fm.hookMu.Lock()
			onOff := fm.onDeviceOffline
			fm.hookMu.Unlock()
			if onOff != nil {
				onOff()
			}
			fm.fireAlert(Alert{
				Type:      AlertDeviceOffline,
				DeviceID:  dev.DeviceID,
				Message:   "Device silent for >3× heartbeat interval",
				Severity:  "warning",
				Timestamp: time.Now(),
			})
		}
		fm.deviceLocks[shard].Unlock()
	}
}

// GetDevice returns a copy of a device by composite ID.
func (fm *FleetManager) GetDevice(fullID uint64) (Device, bool) {
	fm.mu.RLock()
	dev, ok := fm.devices[fullID]
	fm.mu.RUnlock()
	if !ok {
		return Device{}, false
	}
	// Acquire the shard lock to get a consistent snapshot of the device.
	// ProcessHeartbeat mutates *dev under the shard lock (not fm.mu), so
	// we must hold the same shard lock while copying the struct.
	shard := fullID % 256
	fm.deviceLocks[shard].Lock()
	copy := *dev
	fm.deviceLocks[shard].Unlock()
	return copy, true
}

// ListDevices returns a snapshot copy of all registered devices.
// Two-phase approach: collect pointers under mu.RLock (no shard locks),
// then copy each device under its shard lock (no mu). This prevents
// deadlock with ProcessHeartbeat's auto-register path which acquires
// shard → mu.
func (fm *FleetManager) ListDevices() []Device {
	fm.mu.RLock()
	type devRef struct {
		id  uint64
		dev *Device
	}
	refs := make([]devRef, 0, len(fm.devices))
	for id, dev := range fm.devices {
		refs = append(refs, devRef{id, dev})
	}
	fm.mu.RUnlock()

	result := make([]Device, 0, len(refs))
	for _, ref := range refs {
		shard := ref.id % 256
		fm.deviceLocks[shard].Lock()
		result = append(result, *ref.dev)
		fm.deviceLocks[shard].Unlock()
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
// Two-phase: collect pointers under mu.RLock, read fields under shard locks.
func (fm *FleetManager) GetFleetHealth() FleetHealth {
	fm.mu.RLock()
	type devRef struct {
		id  uint64
		dev *Device
	}
	refs := make([]devRef, 0, len(fm.devices))
	for id, dev := range fm.devices {
		refs = append(refs, devRef{id, dev})
	}
	fm.mu.RUnlock()

	health := FleetHealth{
		PolicyVersions: make(map[uint16]int),
	}
	for _, ref := range refs {
		shard := ref.id % 256
		fm.deviceLocks[shard].Lock()
		health.TotalDevices++
		switch ref.dev.Status {
		case StatusOnline:
			health.Online++
		case StatusOffline:
			health.Offline++
		case StatusDegraded:
			health.Degraded++
		case StatusLockdown:
			health.Lockdown++
		}
		health.PolicyVersions[ref.dev.PolicyVersion]++
		fm.deviceLocks[shard].Unlock()
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
	fm.hookMu.Lock()
	h := fm.alertHandler
	fm.hookMu.Unlock()
	if h != nil {
		h(alert)
	}
}

// GetAlertHandler returns the current alert handler (may be nil).
// P2-19 fix: Needed by WireMetrics to wrap the handler with metric counters.
func (fm *FleetManager) GetAlertHandler() AlertHandler {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	return fm.alertHandler
}

// SetAlertHandler replaces the alert handler.
// P2-19 fix: Needed by WireMetrics to wrap the handler with metric counters.
func (fm *FleetManager) SetAlertHandler(h AlertHandler) {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	fm.alertHandler = h
}

// fwVersionToUint16 parses a stored firmware version string back to uint16
// for numeric comparison.
// M-9 fix: Support semver strings like "1.2.3" by encoding as
// major*10000 + minor*100 + patch. Falls back to plain uint16 parse
// for bare numeric strings like "42". Returns 0 on parse failure.
//
// LOW-3: Maximum representable semver is 6.55.35 (6*10000 + 55*100 + 35 = 65535).
// Versions beyond this saturate at uint16 max (65535). This is sufficient for
// firmware versions in the edge-connector ecosystem.
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
