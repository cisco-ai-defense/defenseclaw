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

	LastUptime    uint32 `json:"last_uptime"`
	PrevDenied    uint32 `json:"prev_denied"`
	PrevAllowed   uint32 `json:"prev_allowed"`
	PrevWarned    uint32 `json:"prev_warned"`
	PrevEscalated uint32 `json:"prev_escalated"`

	// BootEpoch is incremented each time a device reboot is detected
	// (uptime < last_uptime). Persisted to SQLite so that after a gateway
	// restart we can distinguish "new boot" from "replay of old heartbeat
	// with lower uptime".
	BootEpoch uint32 `json:"boot_epoch"`
}

// Heartbeat represents a parsed 32-byte device heartbeat.
type Heartbeat struct {
	DeviceID       uint32
	UptimeSec      uint32
	PolicyVersion  uint16
	FWVersion      uint16
	DeniedCount    uint32
	AllowedCount   uint32
	WarnedCount    uint32
	EscalatedCount uint32
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
// Locking: mu RWMutex protects the devices map; per-device mutations use
// the sharded deviceLocks[256] array to reduce contention under high
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
	for _, dev := range devices {
		fm.devices[dev.DeviceID] = dev
	}
	count := len(devices)
	fm.mu.Unlock()

	// Immediately check for stale online statuses from before the restart.
	// Devices that were online when the gateway last shut down may have gone
	// silent in the interim; mark them offline now rather than waiting for
	// the first monitoring tick.
	fm.CheckOfflineDevices()

	return count, nil
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

// SetStoreErrorHook configures a callback for store write failures.
func (fm *FleetManager) SetStoreErrorHook(hook func()) {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	fm.onStoreError = hook
}

// SetStatusChangeHook configures a callback for device status transitions.
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

	// Lock ordering: mu (global map lock) before shard lock.
	// Auto-register needs mu.Lock, so acquire mu first when device is unknown.
	fm.mu.RLock()
	dev, exists := fm.devices[fullID]
	fm.mu.RUnlock()

	if !exists {
		if !fm.AutoRegister {
			return
		}

		fm.mu.Lock()
		// Double-check under write lock — another goroutine may have registered
		// between the RUnlock and Lock above.
		if existing, ok := fm.devices[fullID]; ok {
			dev = existing
		} else {
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
		}
		fm.mu.Unlock()

		fm.deviceLocks[shard].Lock()
		// Check device wasn't decommissioned between releasing fm.mu and
		// acquiring shard lock. Another goroutine may have called
		// DecommissionDevice which deletes from fm.devices under fm.mu.
		fm.mu.RLock()
		refreshedDev, stillExists := fm.devices[fullID]
		if !stillExists {
			fm.mu.RUnlock()
			fm.deviceLocks[shard].Unlock()
			log.Printf("[fleet] device %d was decommissioned during auto-registration, aborting", deviceID)
			return
		}
		dev = refreshedDev
		fm.mu.RUnlock()

		devCopyForStore := *dev
		fm.deviceLocks[shard].Unlock()

		if fm.store != nil {
			if err := fm.store.SaveDevice(&devCopyForStore); err != nil {
				log.Printf("[fleet] store error on auto-register: %v", err)
				fm.mu.Lock()
				delete(fm.devices, fullID)
				fm.mu.Unlock()
				return
			}
		}

		// Re-acquire shard lock for the rest of heartbeat processing.
		fm.deviceLocks[shard].Lock()
		// Re-verify device still exists after releasing and re-acquiring shard lock.
		fm.mu.RLock()
		refreshedDev, stillExists = fm.devices[fullID]
		if !stillExists {
			fm.mu.RUnlock()
			fm.deviceLocks[shard].Unlock()
			log.Printf("[fleet] device %d was decommissioned during auto-registration store write, aborting", deviceID)
			return
		}
		dev = refreshedDev
		fm.mu.RUnlock()
		defer fm.deviceLocks[shard].Unlock()
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
	} else {
		fm.deviceLocks[shard].Lock()
		defer fm.deviceLocks[shard].Unlock()
	}

	//
	// Reboot handling: when uptime < last_uptime (or uptime == 0 while
	// last_uptime > 0), the device has rebooted. Accept the heartbeat but
	// reset the delta counters to 0 so the first post-reboot absolute
	// values are treated as the full delta. Don't reject legitimate reboots.
	//
	// Increment BootEpoch on each detected reboot so that after a gateway
	// restart we can distinguish a genuine new boot from a replayed
	// heartbeat with lower uptime.
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

	// PolicyVersion, FWVersion, and Capabilities can only advance
	// (anti-rollback). A replayed heartbeat with an older policy version
	// must NOT revert the device's state. These fields are only allowed to
	// increase; they should be updated via authenticated registration for
	// downgrades.
	if hb.PolicyVersion > dev.PolicyVersion {
		dev.PolicyVersion = hb.PolicyVersion
	}
	if uint32(hb.FWVersion) > fwVersionToUint32(dev.FWVersion) {
		dev.FWVersion = fmt.Sprintf("%d", hb.FWVersion)
	}
	if hb.Capabilities > dev.Capabilities {
		dev.Capabilities = hb.Capabilities
	}

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

	if hb.Flags&0x08 != 0 {
		fm.fireAlert(Alert{
			Type:      AlertCanaryRollback,
			DeviceID:  fullID,
			Message:   fmt.Sprintf("Device performed OTA canary rollback (policy_v=%d)", hb.PolicyVersion),
			Severity:  "high",
			Timestamp: time.Now(),
		})
	}

	oldStatus := dev.Status

	// Update status based on flags.
	// Flag layout matches the C encoder in cbor_codec.c:
	//   0x02 = POLICY_STALE  (clock not trusted — treated as degraded)
	//   0x04 = TAMPER_DETECT  (reserved — C encoder does not set this yet)
	//   0x08 = CANARY_ROLLBACK (handled above)
	//   0x20 = OFFLINE_MODE
	//   0x80 = SE_DEGRADED    (reserved — C encoder does not set this yet)
	if hb.Flags&0x04 != 0 { // TAMPER_DETECT — C encoder sets when audit chain breaks
		dev.Status = StatusLockdown
		fm.fireAlert(Alert{
			Type:      AlertTamperDetect,
			DeviceID:  fullID,
			Message:   "Audit chain integrity failure detected",
			Severity:  "critical",
			Timestamp: time.Now(),
		})
	} else if hb.Flags&0x80 != 0 { // SE_DEGRADED — C encoder sets when secure element unavailable
		dev.Status = StatusDegraded
		fm.fireAlert(Alert{
			Type:      AlertSEDegraded,
			DeviceID:  fullID,
			Message:   "Secure element in degraded mode",
			Severity:  "critical",
			Timestamp: time.Now(),
		})
	} else if hb.Flags&0x02 != 0 { // POLICY_STALE (clock not trusted)
		dev.Status = StatusDegraded
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

	if fm.store != nil {
		if err := fm.store.SaveDevice(dev); err != nil {
			log.Printf("[fleet] store error: %v", err)
			fm.hookMu.Lock()
			onSE := fm.onStoreError
			fm.hookMu.Unlock()
			if onSE != nil {
				onSE()
			}
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

	// Resolve device pointers under mu.RLock (no shard lock needed).
	type offlineCandidate struct {
		id  uint64
		dev *Device
	}
	fm.mu.RLock()
	resolved := make([]offlineCandidate, 0, len(candidates))
	for _, id := range candidates {
		if dev, ok := fm.devices[id]; ok {
			resolved = append(resolved, offlineCandidate{id, dev})
		}
	}
	fm.mu.RUnlock()

	// Check and update each device under its shard lock only.
	for _, c := range resolved {
		shard := c.id % 256
		fm.deviceLocks[shard].Lock()

		// Re-verify device still exists and pointer is unchanged (could have
		// been decommissioned between resolve and update).
		fm.mu.RLock()
		current, exists := fm.devices[c.id]
		fm.mu.RUnlock()
		if !exists || current != c.dev {
			fm.deviceLocks[shard].Unlock()
			continue
		}

		dev := c.dev
		if dev.Status == StatusOnline && dev.LastHeartbeat.Before(threshold) {
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
		DeniedCount:    uint32(binary.BigEndian.Uint16(data[12:14])),
		AllowedCount:   uint32(binary.BigEndian.Uint16(data[14:16])),
		WarnedCount:    uint32(binary.BigEndian.Uint16(data[16:18])),
		EscalatedCount: uint32(binary.BigEndian.Uint16(data[18:20])),
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
func (fm *FleetManager) GetAlertHandler() AlertHandler {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	return fm.alertHandler
}

// SetAlertHandler replaces the alert handler.
func (fm *FleetManager) SetAlertHandler(h AlertHandler) {
	fm.hookMu.Lock()
	defer fm.hookMu.Unlock()
	fm.alertHandler = h
}

// fwVersionToUint32 parses a stored firmware version string to uint32 for
// numeric comparison. Supports semver "major.minor.patch" (encoded as
// major*1000000 + minor*1000 + patch) and bare numeric strings like "42".
// Returns 0 on parse failure.
func fwVersionToUint32(s string) uint32 {
	var major, minor, patch int
	n, _ := fmt.Sscanf(s, "%d.%d.%d", &major, &minor, &patch)
	if n == 3 {
		if major < 0 || minor < 0 || patch < 0 {
			return 0
		}
		if major > 4294 || minor > 999 || patch > 999 {
			return 0
		}
		return uint32(major)*1000000 + uint32(minor)*1000 + uint32(patch)
	}
	var v uint32
	fmt.Sscanf(s, "%d", &v)
	return v
}

// Sentinel errors
type fleetError string

func (e fleetError) Error() string { return string(e) }

const ErrInvalidHeartbeat = fleetError("invalid heartbeat: must be 32 bytes")
