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

package mqtt

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// DeviceKeyProvider resolves the signing key for a given device.
// The default implementation returns a fleet-wide shared key read from
// the DCLAW_DEVICE_KEY environment variable (hex-encoded, 32 bytes).
// In production, replace with a per-device key lookup.
type DeviceKeyProvider interface {
	KeyForDevice(deviceID uint64) []byte
}

// DeviceKeyLookup is the interface that DeviceKeyStore providers must implement
// for per-device key resolution. Matches fleet.DeviceKeyStore.
type DeviceKeyLookup interface {
	LoadDeviceKey(deviceID uint64) ([]byte, error)
}

// DeviceKeyChecker is an optional interface that a DeviceKeyProvider can
// implement to report whether a per-device key has been provisioned. The
// bridge uses this to reject unsigned heartbeats from keyed devices.
type DeviceKeyChecker interface {
	HasDeviceKey(deviceID uint64) (bool, error)
}

// storeBackedKeyProvider resolves per-device keys from the DeviceKeyStore.
// Falls back to a fleet-wide key, or to a zero key only in explicit development mode.
type storeBackedKeyProvider struct {
	store       DeviceKeyLookup
	fallbackKey []byte
}

func newStoreBackedKeyProvider(store DeviceKeyLookup) *storeBackedKeyProvider {
	var fallback []byte
	raw := os.Getenv("DCLAW_DEVICE_KEY")
	if raw != "" {
		decoded, err := hex.DecodeString(raw)
		if err == nil && nonzeroDeviceKey(decoded) {
			fallback = decoded
		} else {
			log.Printf("[mqtt-bridge] ERROR: DCLAW_DEVICE_KEY is invalid (want 64 hex chars / 32 bytes)")
		}
	}
	if fallback == nil {
		if isProductionMode() {
			log.Printf("[mqtt-bridge] ERROR: no valid fleet device key; per-device key lookup is required")
		} else {
			fallback = make([]byte, 32)
			log.Printf("[mqtt-bridge] WARNING: explicit development mode is using an all-zero device key")
		}
	}
	return &storeBackedKeyProvider{store: store, fallbackKey: fallback}
}

func (p *storeBackedKeyProvider) KeyForDevice(deviceID uint64) []byte {
	if p.store != nil {
		key, err := p.store.LoadDeviceKey(deviceID)
		if err != nil {
			// Do NOT fall back to fleet key on store errors. The fleet key
			// is a known zero/deterministic dev key; falling back to it when
			// the store is broken lets an attacker sign with the well-known
			// key. Only fall back when the store explicitly returns
			// (nil, nil) meaning "no per-device key provisioned."
			log.Printf("[mqtt-bridge] ERROR: key store lookup failed for device %d: %v — refusing fallback to fleet key", deviceID, err)
			return nil
		}
		if key != nil {
			if !nonzeroDeviceKey(key) {
				log.Printf("[mqtt-bridge] ERROR: invalid per-device key for device %d", deviceID)
				return nil
			}
			return key
		}
	}
	return p.fallbackKey
}

// HasDeviceKey reports whether a per-device key has been provisioned for
// this device. Returns true only when the backing store has a specific key;
// returns false when the device would fall back to the fleet-wide key.
func (p *storeBackedKeyProvider) HasDeviceKey(deviceID uint64) (bool, error) {
	if p.store == nil {
		return false, nil
	}
	key, err := p.store.LoadDeviceKey(deviceID)
	if err != nil {
		return false, fmt.Errorf("key store lookup for device %d: %w", deviceID, err)
	}
	return key != nil, nil
}

// envDeviceKeyProvider reads DCLAW_DEVICE_KEY from the environment.
// Falls back to a 32-byte zero key when the env var is unset (dev mode).
// Deprecated: Use storeBackedKeyProvider for per-device key support.
type envDeviceKeyProvider struct {
	key []byte
}

func newEnvDeviceKeyProvider() *envDeviceKeyProvider {
	raw := os.Getenv("DCLAW_DEVICE_KEY")
	if raw != "" {
		decoded, err := hex.DecodeString(raw)
		if err == nil && nonzeroDeviceKey(decoded) {
			return &envDeviceKeyProvider{key: decoded}
		}
		log.Printf("[mqtt-bridge] ERROR: DCLAW_DEVICE_KEY is invalid (want 64 hex chars / 32 bytes)")
	}
	if isProductionMode() {
		log.Printf("[mqtt-bridge] ERROR: No DCLAW_DEVICE_KEY set in production mode — HMAC verification will reject all messages")
		return &envDeviceKeyProvider{key: nil}
	}
	return &envDeviceKeyProvider{key: make([]byte, 32)}
}

func nonzeroDeviceKey(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	for _, b := range key {
		if b != 0 {
			return true
		}
	}
	return false
}

// isProductionMode defaults to fail-closed. Explicit development mode is
// honored only on unmanaged hosts and never overrides DCLAW_PRODUCTION=true.
func isProductionMode() bool {
	if managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) || managed.IsStandaloneManagedHost() {
		return true
	}
	v := os.Getenv("DCLAW_PRODUCTION")
	if v == "true" || v == "1" {
		return true
	}
	return !strings.EqualFold(os.Getenv("DCLAW_DEV_MODE"), "ON")
}

func (p *envDeviceKeyProvider) KeyForDevice(_ uint64) []byte {
	return p.key
}

// Bridge connects the MQTT subscriber to the fleet manager and verdict cache.
// It subscribes to device heartbeat and verdict-request topics, decodes the
// binary/CBOR payloads, and routes them to the appropriate handlers.
type Bridge struct {
	client      Client
	fleet       *manager.FleetManager
	cache       *verdict.Cache
	keyProvider DeviceKeyProvider
	logger      *log.Logger
	cancelMu    sync.Mutex
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stopped     chan struct{}
	stopOnce    sync.Once
	stopping    atomic.Bool

	// AllowAutoRegistration controls whether unknown devices are automatically
	// registered when they send a heartbeat or registration message. In production
	// this should be false — operators must register devices via CLI/API. In dev
	// mode (DCLAW_FLEET_AUTO_REGISTER=true) this can be enabled for convenience.
	AllowAutoRegistration bool

	decommissioned   map[uint64]time.Time
	decommissionedMu sync.RWMutex

	// Metrics hooks (set externally to avoid circular imports)
	onAllow func()
	onBlock func()
	// replayForDevice republishes durable OTA state after a signed device
	// registration or accepted heartbeat. The signed wire carries the durable
	// emergency sequence actually applied by the device.
	replayForDevice func(context.Context, uint64, uint64, uint16, uint32) (uint32, error)
	replayMu        sync.Mutex
	replayState     map[uint64]deviceReplayState

	heartbeatMinInterval time.Duration
	lastHeartbeat        map[uint64]time.Time
	lastHeartbeatMu      sync.Mutex

	verdictRateMu  sync.Mutex
	verdictRateMap map[uint64]*verdictRateEntry

	decommStore DecommissionChecker

	// Stats for observability
	mu                  sync.RWMutex
	heartbeatsProcessed uint64
	verdictsProcessed   uint64
	decodeErrors        uint64
	rateLimitDrops      uint64
}

type deviceReplayState struct {
	bootCounter uint32
	uptimeSec   uint32
	inFlight    bool
}

// DecommissionChecker is the narrow interface for checking if a device
type DecommissionChecker interface {
	IsDecommissioned(fullDeviceID uint64) (bool, error)
}

// verdictRateEntry tracks per-device verdict request rate.
type verdictRateEntry struct {
	count    int
	windowAt time.Time
}

// verdictRateLimit is the maximum number of verdict requests per device
// per second. Exceeding this drops the request with a warning log.
const verdictRateLimit = 20

// SetOnAllow configures a callback that fires for an authenticated ALLOW verdict.
func (b *Bridge) SetOnAllow(fn func()) {
	b.onAllow = fn
}

// SetOnBlock configures a callback that fires when a verdict request
// results in a BLOCK action.  Used by WireMetrics to increment the
// fleet-level blocks counter without a circular import.
func (b *Bridge) SetOnBlock(fn func()) {
	b.onBlock = fn
}

// SetReplayForDevice supplies the durable policy/emergency catch-up callback.
// Configure it before Start. It is called only after signed 68-byte frames
// pass HMAC and freshness checks; unsigned development frames cannot trigger
// a fleet-wide OTA broadcast.
func (b *Bridge) SetReplayForDevice(fn func(context.Context, uint64, uint64, uint16, uint32) (uint32, error)) {
	b.replayForDevice = fn
}

// NewBridge creates a new MQTT bridge.
func NewBridge(client Client, fleet *manager.FleetManager, cache *verdict.Cache) *Bridge {
	return &Bridge{
		client:               client,
		fleet:                fleet,
		cache:                cache,
		keyProvider:          newEnvDeviceKeyProvider(),
		logger:               log.Default(),
		stopped:              make(chan struct{}),
		decommissioned:       make(map[uint64]time.Time),
		heartbeatMinInterval: time.Second, // 1 heartbeat/sec default
		lastHeartbeat:        make(map[uint64]time.Time),
		verdictRateMap:       make(map[uint64]*verdictRateEntry),
		replayState:          make(map[uint64]deviceReplayState),
	}
}

// SetHeartbeatRateLimit configures the minimum interval between heartbeats from the same device.
// Zero disables rate limiting (useful for tests).
func (b *Bridge) SetHeartbeatRateLimit(d time.Duration) { b.heartbeatMinInterval = d }

// MarkDecommissioned adds a device ID to the decommissioned set with a timestamp.
func (b *Bridge) MarkDecommissioned(fullDeviceID uint64) {
	b.decommissionedMu.Lock()
	b.decommissioned[fullDeviceID] = time.Now()
	b.decommissionedMu.Unlock()
	b.replayMu.Lock()
	delete(b.replayState, fullDeviceID)
	b.replayMu.Unlock()
}

// isDecommissioned checks if a device has been decommissioned.
func (b *Bridge) isDecommissioned(fullDeviceID uint64) bool {
	b.decommissionedMu.RLock()
	_, ok := b.decommissioned[fullDeviceID]
	b.decommissionedMu.RUnlock()
	return ok
}

// ClearDecommissioned removes a device ID from the decommissioned set.
// Called when a previously decommissioned device is re-registered via the
// API, so the bridge stops rejecting its MQTT traffic.
func (b *Bridge) ClearDecommissioned(fullDeviceID uint64) {
	b.decommissionedMu.Lock()
	delete(b.decommissioned, fullDeviceID)
	b.decommissionedMu.Unlock()
	b.replayMu.Lock()
	delete(b.replayState, fullDeviceID)
	b.replayMu.Unlock()
}

// SetDeviceKeyStore configures per-device key resolution via a persistent store.
// When set, the bridge looks up a unique 32-byte key for each device before
// falling back to the fleet-wide DCLAW_DEVICE_KEY environment variable.
func (b *Bridge) SetDeviceKeyStore(store DeviceKeyLookup) {
	b.keyProvider = newStoreBackedKeyProvider(store)
}

// SetKeyProvider overrides the default device key provider.
func (b *Bridge) SetKeyProvider(kp DeviceKeyProvider) {
	b.keyProvider = kp
}

func (b *Bridge) SetDecommissionStore(ds DecommissionChecker) {
	b.decommStore = ds
}

// Start connects to the MQTT broker and begins processing messages.
// It blocks until the context is cancelled or Stop() is called.
func (b *Bridge) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer b.stopOnce.Do(func() { close(b.stopped) })
	b.cancelMu.Lock()
	b.cancel = cancel
	b.cancelMu.Unlock()

	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		err := b.client.Connect(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b.logger.Printf("[mqtt-bridge] connect failed: %v — retrying in %v", err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	// Subscribe to heartbeat topic
	if err := b.client.Subscribe(ctx, TopicHeartbeat, 0, b.handleHeartbeat); err != nil {
		_ = b.client.Disconnect()
		return fmt.Errorf("subscribe heartbeat: %w", err)
	}

	// Subscribe to verdict request topic
	if err := b.client.Subscribe(ctx, TopicVerdictReq, 1, b.handleVerdictRequest); err != nil {
		_ = b.client.Disconnect()
		return fmt.Errorf("subscribe verdict/req: %w", err)
	}

	// Subscribe to device registration topic
	if err := b.client.Subscribe(ctx, TopicRegister, 1, b.handleRegistration); err != nil {
		_ = b.client.Disconnect()
		return fmt.Errorf("subscribe register: %w", err)
	}

	b.logger.Printf("[mqtt-bridge] subscribed to %s, %s, and %s", TopicHeartbeat, TopicVerdictReq, TopicRegister)

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-b.stopped:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-5 * time.Minute)

				b.lastHeartbeatMu.Lock()
				for id, ts := range b.lastHeartbeat {
					if ts.Before(cutoff) {
						delete(b.lastHeartbeat, id)
					}
				}
				b.lastHeartbeatMu.Unlock()

				b.verdictRateMu.Lock()
				for id, entry := range b.verdictRateMap {
					if entry.windowAt.Before(cutoff) {
						delete(b.verdictRateMap, id)
					}
				}
				b.verdictRateMu.Unlock()

				decommCutoff := time.Now().Add(-7 * 24 * time.Hour)
				var candidates []uint64
				b.decommissionedMu.RLock()
				for id, ts := range b.decommissioned {
					if ts.Before(decommCutoff) {
						candidates = append(candidates, id)
					}
				}
				b.decommissionedMu.RUnlock()

				// Check store outside lock.
				var toDelete []uint64
				var toRefresh []uint64
				for _, id := range candidates {
					if b.decommStore != nil {
						still, err := b.decommStore.IsDecommissioned(id)
						if err != nil {
							// Store error — keep the tombstone to be safe.
							continue
						}
						if still {
							toRefresh = append(toRefresh, id)
							continue
						}
					}
					toDelete = append(toDelete, id)
				}

				// Apply changes under lock
				if len(toDelete) > 0 || len(toRefresh) > 0 {
					b.decommissionedMu.Lock()
					for _, id := range toDelete {
						delete(b.decommissioned, id)
					}
					for _, id := range toRefresh {
						b.decommissioned[id] = time.Now()
					}
					b.decommissionedMu.Unlock()
				}
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	_ = b.client.Disconnect()
	b.wg.Wait()
	return nil
}

// Stop triggers a graceful shutdown of the bridge.
func (b *Bridge) Stop() {
	b.stopping.Store(true)
	b.cancelMu.Lock()
	cancel := b.cancel
	b.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Wait for the stopped channel to close, with a timeout
	select {
	case <-b.stopped:
	case <-time.After(5 * time.Second):
		b.logger.Println("[mqtt-bridge] shutdown timed out after 5s")
	}
}

func (b *Bridge) tryAcquire() bool {
	if b.stopping.Load() {
		return false
	}
	b.wg.Add(1)
	if b.stopping.Load() {
		b.wg.Done()
		return false
	}
	return true
}

// Stats returns bridge processing statistics.
func (b *Bridge) Stats() (heartbeats, verdicts, errors uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.heartbeatsProcessed, b.verdictsProcessed, b.decodeErrors
}

// handleHeartbeat processes a heartbeat message from an edge device.
func (b *Bridge) handleHeartbeat(msg Message) {
	if !b.tryAcquire() {
		return
	}
	defer b.wg.Done()

	parts, err := ParseTopic(msg.Topic)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] bad heartbeat topic: %v", err)
		b.incErrors()
		return
	}

	if err := validateTopicIDs(parts); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: heartbeat rejected — %v", err)
		b.incErrors()
		return
	}

	fullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	if b.isDecommissioned(fullID) {
		b.logger.Printf("[mqtt-bridge] rejected heartbeat from decommissioned device %d", parts.DeviceID)
		b.incErrors()
		return
	}

	now := time.Now()
	b.lastHeartbeatMu.Lock()
	minInterval := b.heartbeatMinInterval
	if minInterval < 0 {
		minInterval = time.Second
	}
	if minInterval > 0 {
		if last, ok := b.lastHeartbeat[fullID]; ok && now.Sub(last) < minInterval {
			b.lastHeartbeatMu.Unlock()
			b.logger.Printf("[mqtt-bridge] WARNING: rate-limited heartbeat from device %d (interval=%v)",
				parts.DeviceID, now.Sub(last))
			b.mu.Lock()
			b.rateLimitDrops++
			b.mu.Unlock()
			return
		}
	}
	const maxHeartbeatEntries = 100000
	if len(b.lastHeartbeat) >= maxHeartbeatEntries {
		b.lastHeartbeatMu.Unlock()
		b.logger.Printf("[mqtt-bridge] WARNING: heartbeat rate-limit map full (%d entries), dropping heartbeat from device %d",
			maxHeartbeatEntries, parts.DeviceID)
		b.incErrors()
		return
	}
	b.lastHeartbeat[fullID] = now
	b.lastHeartbeatMu.Unlock()

	if parts.Suffix != "heartbeat" {
		b.logger.Printf("[mqtt-bridge] unexpected suffix %q for heartbeat handler", parts.Suffix)
		b.incErrors()
		return
	}

	hw, err := DecodeHeartbeat(msg.Payload)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] decode heartbeat from device %d: %v", parts.DeviceID, err)
		b.incErrors()
		return
	}

	if hw.DeviceID != parts.DeviceID {
		b.logger.Printf("[mqtt-bridge] WARNING: heartbeat rejected — topic device_id=%d does not match payload device_id=%d (possible spoofing attempt)",
			parts.DeviceID, hw.DeviceID)
		b.incErrors()
		return
	}

	if err := b.verifyMessageHMAC(msg, parts, hw); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: heartbeat rejected — %v", err)
		b.incErrors()
		return
	}

	// Convert to the manager's Heartbeat type
	hb := &manager.Heartbeat{
		DeviceID:       hw.DeviceID,
		UptimeSec:      hw.UptimeSec,
		BootCounter:    hw.BootCounter,
		PolicyVersion:  hw.PolicyVersion,
		FWVersion:      hw.FWVersion,
		DeniedCount:    uint32(hw.DeniedCount),
		AllowedCount:   uint32(hw.AllowedCount),
		WarnedCount:    uint32(hw.WarnedCount),
		EscalatedCount: uint32(hw.EscalatedCount),
		CacheHitPct:    hw.CacheHitPct,
		SessionCount:   hw.SessionCount,
		AuditHeadHMAC:  hw.AuditHeadHMAC,
		Flags:          hw.Flags,
		Capabilities:   hw.Capabilities,
	}

	if !b.fleet.ProcessHeartbeat(parts.TenantID, parts.FleetID, parts.DeviceID, hb) {
		b.incErrors()
		return
	}

	b.mu.Lock()
	b.heartbeatsProcessed++
	b.mu.Unlock()
	b.maybeReplayForDevice(fullID, parts, hw, hw.Signed)
}

func (b *Bridge) maybeReplayForDevice(fullID uint64, parts *TopicParts, hw *HeartbeatWire, signed bool) {
	if !signed || b.replayForDevice == nil {
		return
	}
	b.replayMu.Lock()
	state := b.replayState[fullID]
	// A captured signed packet must not become a fleet-wide publish amplifier.
	if state.inFlight || hw.BootCounter < state.bootCounter ||
		(hw.BootCounter == state.bootCounter && hw.UptimeSec <= state.uptimeSec) {
		b.replayMu.Unlock()
		return
	}
	state.bootCounter = hw.BootCounter
	state.uptimeSec = hw.UptimeSec
	state.inFlight = true
	b.replayState[fullID] = state
	b.replayMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := b.replayForDevice(ctx, uint64(parts.TenantID), uint64(parts.FleetID), hw.PolicyVersion, hw.LastEmergencySeq)
	cancel()

	b.replayMu.Lock()
	state = b.replayState[fullID]
	state.inFlight = false
	b.replayState[fullID] = state
	b.replayMu.Unlock()
	if err != nil {
		b.logger.Printf("[mqtt-bridge] OTA catch-up failed for device %d: %v", parts.DeviceID, err)
		b.incErrors()
	}
}

// handleRegistration processes a registration message from an edge device.
// The payload uses the same signed heartbeat wire format. Re-registration is
// idempotent: a valid duplicate never changes an enrolled device's metadata,
// so a replayed packet cannot roll back firmware or capabilities.
func (b *Bridge) handleRegistration(msg Message) {
	if !b.tryAcquire() {
		return
	}
	defer b.wg.Done()

	parts, err := ParseTopic(msg.Topic)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] bad registration topic: %v", err)
		b.incErrors()
		return
	}

	if err := validateTopicIDs(parts); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: registration rejected — %v", err)
		b.incErrors()
		return
	}

	fullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	if b.isDecommissioned(fullID) {
		b.logger.Printf("[mqtt-bridge] rejected registration from decommissioned device %d", parts.DeviceID)
		b.incErrors()
		return
	}

	if parts.Suffix != "register" {
		b.logger.Printf("[mqtt-bridge] unexpected suffix %q for registration handler", parts.Suffix)
		b.incErrors()
		return
	}

	hw, err := DecodeHeartbeat(msg.Payload)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] decode registration from device %d: %v", parts.DeviceID, err)
		b.incErrors()
		return
	}

	if hw.DeviceID != parts.DeviceID {
		b.logger.Printf("[mqtt-bridge] WARNING: registration rejected — topic device_id=%d does not match payload device_id=%d (possible spoofing attempt)",
			parts.DeviceID, hw.DeviceID)
		b.incErrors()
		return
	}

	if err := b.verifyMessageHMAC(msg, parts, hw); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: registration rejected — %v", err)
		b.incErrors()
		return
	}

	// Check whether this is an already enrolled device. A registration from a
	// reconnect must not overwrite inventory with a replayed older payload.
	dev, existsAlready := b.fleet.GetDevice(manager.ComposeID(
		parts.TenantID, parts.FleetID, parts.DeviceID))

	if existsAlready {
		if dev.TenantID != parts.TenantID || dev.FleetID != parts.FleetID {
			b.logger.Printf("[mqtt-bridge] WARNING: registration rejected — device %d topic tenant/fleet (%d/%d) does not match stored (%d/%d)",
				parts.DeviceID, parts.TenantID, parts.FleetID, dev.TenantID, dev.FleetID)
			b.incErrors()
			return
		}
		// The inventory's durable heartbeat baseline rejects captured older
		// registrations; same-boot reconnects can still catch up when uptime
		// has advanced since the last accepted heartbeat.
		if hw.Signed && (hw.BootCounter < dev.BootCounter ||
			(hw.BootCounter == dev.BootCounter && hw.UptimeSec <= dev.LastUptime)) {
			b.logger.Printf("[mqtt-bridge] stale registration ignored for device %d", parts.DeviceID)
			return
		}
		b.logger.Printf("[mqtt-bridge] device %d re-registered (authenticated no-op)", parts.DeviceID)
		b.maybeReplayForDevice(fullID, parts, hw, hw.Signed)
		return
	}

	if !existsAlready && (!b.AllowAutoRegistration || isProductionMode()) {
		b.logger.Printf("[mqtt-bridge] WARNING: auto-registration denied for unknown device %d (tenant=%d fleet=%d) — allowed only in explicit unmanaged development mode; register via CLI/API in production",
			parts.DeviceID, parts.TenantID, parts.FleetID)
		return
	}

	_, regErr := b.fleet.RegisterDeviceIfAbsent(
		parts.TenantID, parts.FleetID, parts.DeviceID,
		"mqtt-registered",
		fmt.Sprintf("%d", hw.FWVersion),
		hw.PolicyVersion,
		hw.Capabilities,
	)

	if regErr != nil && regErr != manager.ErrDeviceExists {
		b.logger.Printf("[mqtt-bridge] register device %d: %v", parts.DeviceID, regErr)
		b.incErrors()
		return
	}

	if regErr == manager.ErrDeviceExists {
		b.logger.Printf("[mqtt-bridge] device %d re-registered (authenticated no-op)", parts.DeviceID)
	} else {
		b.logger.Printf("[mqtt-bridge] device %d registered via MQTT (tenant=%d fleet=%d fw=%d policy=%d)",
			parts.DeviceID, parts.TenantID, parts.FleetID, hw.FWVersion, hw.PolicyVersion)
	}
	b.maybeReplayForDevice(fullID, parts, hw, hw.Signed)
}

// handleVerdictRequest processes a verdict request from an edge device.
// It evaluates the tool hash via the verdict cache and publishes the response
// back to the device on its verdict/resp topic.
func (b *Bridge) handleVerdictRequest(msg Message) {
	if !b.tryAcquire() {
		return
	}
	defer b.wg.Done()

	parts, err := ParseTopic(msg.Topic)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] bad verdict topic: %v", err)
		b.incErrors()
		return
	}

	if err := validateTopicIDs(parts); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — %v", err)
		b.incErrors()
		return
	}

	fullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	if b.isDecommissioned(fullID) {
		b.logger.Printf("[mqtt-bridge] rejected verdict request from decommissioned device %d", parts.DeviceID)
		b.incErrors()
		return
	}

	dev, registered := b.fleet.GetDevice(fullID)
	if !registered {
		b.logger.Printf("[mqtt-bridge] rejected verdict request from unregistered device %d (tenant=%d fleet=%d)",
			parts.DeviceID, parts.TenantID, parts.FleetID)
		b.incErrors()
		return
	}

	if dev.Status == manager.StatusLockdown {
		b.logger.Printf("[mqtt-bridge] verdict request from lockdown device %d — returning BLOCK",
			parts.DeviceID)
		// Strip trailing 32-byte HMAC for keyed devices so the CBOR
		// decoder in sendLockdownBlockResponse sees clean CBOR only.
		lockdownPayload := msg.Payload
		if b.keyProvider != nil {
			dk := b.keyProvider.KeyForDevice(fullID)
			var zk [32]byte
			if dk != nil && !bytes.Equal(dk, zk[:]) && len(msg.Payload) >= 64 {
				lockdownPayload = msg.Payload[:len(msg.Payload)-32]
			}
		}
		b.sendLockdownBlockResponse(parts, lockdownPayload)
		b.incErrors()
		return
	}

	{
		now := time.Now()
		b.verdictRateMu.Lock()
		entry, ok := b.verdictRateMap[fullID]
		if !ok {
			entry = &verdictRateEntry{windowAt: now}
			b.verdictRateMap[fullID] = entry
		}
		if now.Sub(entry.windowAt) >= time.Second {
			entry.count = 0
			entry.windowAt = now
		}
		entry.count++
		overLimit := entry.count > verdictRateLimit
		overLimitCount := entry.count
		b.verdictRateMu.Unlock()

		if overLimit {
			b.logger.Printf("[mqtt-bridge] WARNING: verdict request rate-limited for device %d (%d req/s exceeds limit %d)",
				parts.DeviceID, overLimitCount, verdictRateLimit)
			b.mu.Lock()
			b.rateLimitDrops++
			b.mu.Unlock()
			return
		}
	}

	if len(msg.Payload) < 32 {
		b.logger.Printf("[mqtt-bridge] verdict request from device %d too short (%d bytes, need >= 32)",
			parts.DeviceID, len(msg.Payload))
		b.incErrors()
		return
	}

	payloadBody := msg.Payload
	isKeyed := false

	if b.keyProvider != nil {
		vrFullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
		vrDeviceKey := b.keyProvider.KeyForDevice(vrFullID)
		if vrDeviceKey == nil {
			b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — key lookup returned nil for device %d (fail closed)", parts.DeviceID)
			b.incErrors()
			return
		}
		if checker, ok := b.keyProvider.(DeviceKeyChecker); ok {
			hasKey, checkErr := checker.HasDeviceKey(vrFullID)
			if checkErr != nil {
				b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — key store error for device %d: %v (fail closed)", parts.DeviceID, checkErr)
				b.incErrors()
				return
			}
			if hasKey {
				isKeyed = true
			} else {
				b.logger.Printf("[mqtt-bridge] WARNING: processing verdict request from unkeyed device %d", parts.DeviceID)
			}
		} else {
			// Legacy envDeviceKeyProvider: no DeviceKeyChecker interface.
			// Verify HMAC if the key is non-zero (provisioned).
			var zeroKey [32]byte
			if len(vrDeviceKey) > 0 && !bytes.Equal(vrDeviceKey, zeroKey[:]) {
				isKeyed = true
			}
		}

		if isKeyed {
			if len(msg.Payload) < 64 {
				b.logger.Printf("[mqtt-bridge] verdict request from keyed device %d too short for HMAC (%d bytes)", parts.DeviceID, len(msg.Payload))
				b.incErrors()
				return
			}
			payloadBody = msg.Payload[:len(msg.Payload)-32]
			payloadHMAC := msg.Payload[len(msg.Payload)-32:]
			mac := hmac.New(sha256.New, vrDeviceKey)
			mac.Write([]byte(msg.Topic))
			mac.Write(payloadBody)
			expected := mac.Sum(nil)
			if !hmac.Equal(expected, payloadHMAC) {
				b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — HMAC verification failed for device %d", parts.DeviceID)
				b.incErrors()
				return
			}
		}
	}
	_ = isKeyed

	vr, err := DecodeVerdictRequest(payloadBody)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] decode verdict request from device %d: %v", parts.DeviceID, err)
		b.incErrors()
		return
	}

	// Evaluate via the verdict cache (cache hit or pipeline execution).
	// Tenant/fleet scoping ensures verdicts are isolated across tenants.
	action, severity := b.cache.Evaluate(parts.TenantID, parts.FleetID, vr.ToolHash)

	// Count verdicts only after the request has been authenticated and decoded.
	if action == verdict.ActionAllow && b.onAllow != nil {
		b.onAllow()
	}
	if action == verdict.ActionBlock && b.onBlock != nil {
		b.onBlock()
	}

	// Build a response
	resp := &VerdictResponse{
		RequestID: vr.RequestID,
		Action:    uint8(action),
		Severity:  severity,
		TTL:       60, // 60 minutes default TTL
		ServerTS:  uint32(time.Now().Unix()),
	}

	// Compute the HMAC tag matching the C-side verdict_protocol.c scheme.
	// The session ID on the C side comes from dclaw_mqtt_get_session_id()
	// which returns the MQTT session identifier; here we use the session ID
	// derived from the device's MQTT connection (device ID as string).
	// The device key is resolved via the DeviceKeyProvider (defaults to
	// DCLAW_DEVICE_KEY env var; zero key in dev mode).
	sessionID := fmt.Sprintf("%d", parts.DeviceID)
	// Look up the per-device key using the full composite ID so that the
	// store-backed provider can find keys stored during registration.
	fullDeviceID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	deviceKey := b.keyProvider.KeyForDevice(fullDeviceID)
	if deviceKey == nil {
		b.logger.Printf("[mqtt-bridge] ERROR: cannot sign verdict response for device %d — nil key (store error or unprovisioned)", parts.DeviceID)
		b.incErrors()
		return
	}
	resp.HMACTag = computeVerdictHMACFull(deviceKey, sessionID,
		vr.RequestID, resp.Action, resp.Severity, resp.TTL,
		resp.Reason, resp.Flags, resp.ServerTS, vr.ToolHash, vr.BootNonce, vr.RequestNonce)

	// Publish the response to the device's verdict/resp topic
	respTopic := fmt.Sprintf("defenseclaw/%d/%d/%d/verdict/resp",
		parts.TenantID, parts.FleetID, parts.DeviceID)

	payload := EncodeVerdictResponse(resp)

	pubCtx, pubCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pubCancel()
	if err := b.client.Publish(pubCtx, respTopic, 0, payload); err != nil {
		b.logger.Printf("[mqtt-bridge] publish verdict response to %s: %v", respTopic, err)
		b.incErrors()
		return
	}

	b.mu.Lock()
	b.verdictsProcessed++
	b.mu.Unlock()
}

// validateTopicIDs checks that the topic's tenant/fleet/device IDs are all non-zero,
// preventing attackers from injecting zero-valued IDs that collide with other devices.
func validateTopicIDs(parts *TopicParts) error {
	if parts.TenantID == 0 {
		return fmt.Errorf("zero tenant_id in topic")
	}
	if parts.FleetID == 0 {
		return fmt.Errorf("zero fleet_id in topic")
	}
	if parts.DeviceID == 0 {
		return fmt.Errorf("zero device_id in topic")
	}
	return nil
}

func (b *Bridge) incErrors() {
	b.mu.Lock()
	b.decodeErrors++
	b.mu.Unlock()
}

// sendLockdownBlockResponse sends a BLOCK verdict response to a device that
func (b *Bridge) sendLockdownBlockResponse(parts *TopicParts, rawPayload []byte) {
	// Decode the verdict request to get the real RequestID, ToolHash, BootNonce, and RequestNonce.
	var requestID uint16
	var toolHash [32]byte
	var bootNonce [16]byte
	var requestNonce [4]byte
	if vr, err := DecodeVerdictRequest(rawPayload); err == nil {
		requestID = vr.RequestID
		toolHash = vr.ToolHash
		bootNonce = vr.BootNonce
		requestNonce = vr.RequestNonce
	} else {
		b.logger.Printf("[mqtt-bridge] lockdown BLOCK: failed to decode verdict request: %v (using request_id=1)", err)
		requestID = 1 // fallback to non-zero so the C agent does not discard
	}

	resp := &VerdictResponse{
		RequestID: requestID,
		Action:    uint8(verdict.ActionBlock),
		Severity:  0,
		TTL:       0,
		ServerTS:  uint32(time.Now().Unix()),
	}

	sessionID := fmt.Sprintf("%d", parts.DeviceID)
	fullDeviceID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	deviceKey := b.keyProvider.KeyForDevice(fullDeviceID)
	if deviceKey == nil {
		b.logger.Printf("[mqtt-bridge] ERROR: cannot sign lockdown response for device %d — nil key", parts.DeviceID)
		return
	}
	resp.HMACTag = computeVerdictHMACFull(deviceKey, sessionID,
		resp.RequestID, resp.Action, resp.Severity, resp.TTL,
		resp.Reason, resp.Flags, resp.ServerTS, toolHash, bootNonce, requestNonce)

	respTopic := fmt.Sprintf("defenseclaw/%d/%d/%d/verdict/resp",
		parts.TenantID, parts.FleetID, parts.DeviceID)
	payload := EncodeVerdictResponse(resp)

	lockdownCtx, lockdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer lockdownCancel()
	if err := b.client.Publish(lockdownCtx, respTopic, 0, payload); err != nil {
		b.logger.Printf("[mqtt-bridge] publish lockdown BLOCK to %s: %v", respTopic, err)
	}

	if b.onBlock != nil {
		b.onBlock()
	}
}

// verifyMessageHMAC validates the HMAC-SHA256 tag on a signed or unsigned
// heartbeat/registration message. Returns nil when verification succeeds
// (or the message is an acceptable unsigned legacy message). Returns an
// error describing the rejection reason otherwise. Both handleHeartbeat
// and handleRegistration delegate to this method to avoid duplicating the
// ~50-line HMAC verification block.
func (b *Bridge) verifyMessageHMAC(msg Message, parts *TopicParts, hw *HeartbeatWire) error {
	if b.keyProvider == nil {
		return fmt.Errorf("device key provider is not configured")
	}

	fullDeviceID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	deviceKey := b.keyProvider.KeyForDevice(fullDeviceID)

	if deviceKey == nil {
		return fmt.Errorf("key lookup returned nil for device %d (key store error, fail closed)", parts.DeviceID)
	}

	if hw.Signed {
		// Signed message: verify HMAC-SHA256 over topic + payload.
		// Including the topic binds the HMAC to the message type, so a
		// valid signed heartbeat cannot be replayed on the /register topic.
		mac := hmac.New(sha256.New, deviceKey)
		mac.Write([]byte(msg.Topic))
		mac.Write(msg.Payload[:40])
		expected := mac.Sum(nil)

		if !hmac.Equal(expected, hw.HMACTag) {
			return fmt.Errorf("HMAC verification failed for device %d (possible spoofing attempt)", parts.DeviceID)
		}
	} else {
		if isProductionMode() {
			return fmt.Errorf("unsigned heartbeat/registration from device %d rejected in production", parts.DeviceID)
		}
		// Unsigned (legacy) message: check whether this device has a
		// per-device key provisioned. If it does, reject -- an attacker
		// could bypass HMAC by sending a shorter (unsigned) payload.
		if checker, ok := b.keyProvider.(DeviceKeyChecker); ok {
			hasKey, err := checker.HasDeviceKey(fullDeviceID)
			if err != nil {
				return fmt.Errorf("key store error for device %d: %v (fail-closed)", parts.DeviceID, err)
			}
			if hasKey {
				return fmt.Errorf("unsigned message from keyed device %d (possible HMAC bypass attempt)", parts.DeviceID)
			}
		}
		b.logger.Printf("[mqtt-bridge] WARNING: device %d sent unsigned message (no HMAC) — upgrade edge-connector for signed messages",
			parts.DeviceID)
	}
	return nil
}

// computeVerdictHMACFull computes the full 32-byte HMAC-SHA256 tag covering all
// verdict response fields plus the tool hash. Extended from 16 to 32 bytes to
// use the full SHA-256 output and eliminate truncation-based collision attacks.
func computeVerdictHMACFull(deviceKey []byte, sessionID string,
	requestID uint16, action, severity uint8, ttl uint16,
	reason, flags uint8, serverTS uint32, toolHash [32]byte,
	bootNonce [16]byte, requestNonce [4]byte) [32]byte {

	mac := hmac.New(sha256.New, deviceKey)

	// session_id (string bytes, no NUL terminator — matches C strlen)
	mac.Write([]byte(sessionID))

	// request_id: 2 bytes little-endian (matches C-side)
	var rid [2]byte
	binary.LittleEndian.PutUint16(rid[:], requestID)
	mac.Write(rid[:])

	// action: 1 byte
	mac.Write([]byte{action})

	// severity (1 byte)
	mac.Write([]byte{severity})

	// ttl (2 bytes little-endian)
	var ttlBuf [2]byte
	binary.LittleEndian.PutUint16(ttlBuf[:], ttl)
	mac.Write(ttlBuf[:])

	// reason (1 byte)
	mac.Write([]byte{reason})

	// flags (1 byte)
	mac.Write([]byte{flags})

	// server_ts (4 bytes little-endian)
	var tsBuf [4]byte
	binary.LittleEndian.PutUint32(tsBuf[:], serverTS)
	mac.Write(tsBuf[:])

	mac.Write(toolHash[:])

	mac.Write(bootNonce[:])

	mac.Write(requestNonce[:])

	full := mac.Sum(nil)
	var tag [32]byte
	copy(tag[:], full[:])
	return tag
}
