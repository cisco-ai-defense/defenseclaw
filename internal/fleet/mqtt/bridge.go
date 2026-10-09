package mqtt

import (
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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
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
// bridge uses this to reject unsigned heartbeats from keyed devices (P1-06).
//
// P1-06 fix: Returns (bool, error) so that key-store errors are surfaced.
// The bridge treats errors as "key exists" (fail closed) rather than
// silently falling back to unsigned acceptance.
type DeviceKeyChecker interface {
	HasDeviceKey(deviceID uint64) (bool, error)
}

// storeBackedKeyProvider resolves per-device keys from the DeviceKeyStore.
// Falls back to the fleet-wide DCLAW_DEVICE_KEY env var or zero key
// when no per-device key is found (for backward compatibility during rollout).
type storeBackedKeyProvider struct {
	store       DeviceKeyLookup
	fallbackKey []byte
}

func newStoreBackedKeyProvider(store DeviceKeyLookup) *storeBackedKeyProvider {
	fallback := make([]byte, 32)
	raw := os.Getenv("DCLAW_DEVICE_KEY")
	if raw != "" {
		decoded, err := hex.DecodeString(raw)
		if err == nil && len(decoded) == 32 {
			fallback = decoded
		} else {
			log.Printf("[mqtt-bridge] WARNING: DCLAW_DEVICE_KEY is set but invalid (want 64 hex chars / 32 bytes), falling back to zero key")
		}
	} else if isProductionMode() {
		// CRT-3 fix: In production mode, refuse to use a zero key as fallback.
		log.Printf("[mqtt-bridge] ERROR: No DCLAW_DEVICE_KEY set in production mode — zero-key fallback disabled")
		fallback = nil
	}
	return &storeBackedKeyProvider{store: store, fallbackKey: fallback}
}

func (p *storeBackedKeyProvider) KeyForDevice(deviceID uint64) []byte {
	if p.store != nil {
		key, err := p.store.LoadDeviceKey(deviceID)
		if err != nil {
			// P1-HMAC fix: Do NOT fall back to fleet key on store errors.
			// The fleet key is a known zero/deterministic dev key; falling
			// back to it when the store is broken lets an attacker sign with
			// the well-known key. Only fall back when the store explicitly
			// returns (nil, nil) meaning "no per-device key provisioned."
			log.Printf("[mqtt-bridge] ERROR: key store lookup failed for device %d: %v — refusing fallback to fleet key", deviceID, err)
			return nil
		}
		if key != nil {
			return key
		}
	}
	return p.fallbackKey
}

// HasDeviceKey reports whether a per-device key has been provisioned for
// this device. Returns true only when the backing store has a specific key;
// returns false when the device would fall back to the fleet-wide key.
//
// P1-06 fix: Returns (bool, error) so that key-store errors are surfaced
// to the caller. The bridge treats errors as fail-closed (reject the
// message) rather than silently accepting unsigned payloads.
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
		if err == nil && len(decoded) == 32 {
			return &envDeviceKeyProvider{key: decoded}
		}
		log.Printf("[mqtt-bridge] WARNING: DCLAW_DEVICE_KEY is set but invalid (want 64 hex chars / 32 bytes), falling back to zero key")
	}
	// CRT-3 fix: In production mode (DCLAW_PRODUCTION=true), refuse to use
	// a zero key. A zero key is a well-known constant that any attacker can
	// use to forge HMAC signatures. Return nil so HMAC checks fail closed.
	if isProductionMode() {
		log.Printf("[mqtt-bridge] ERROR: No DCLAW_DEVICE_KEY set in production mode — HMAC verification will reject all messages")
		return &envDeviceKeyProvider{key: nil}
	}
	return &envDeviceKeyProvider{key: make([]byte, 32)}
}

// isProductionMode returns true when the env var DCLAW_PRODUCTION is set to
// "true" or "1", OR when DCLAW_DEV_MODE is "OFF", "0", or "false".
// H-1 fix: DCLAW_PRODUCTION defaults to true when DCLAW_DEV_MODE=OFF so that
// operators only need to set one knob. Used by CRT-3 to refuse zero-key fallbacks.
func isProductionMode() bool {
	v := os.Getenv("DCLAW_PRODUCTION")
	if v == "true" || v == "1" {
		return true
	}
	devMode := strings.ToLower(os.Getenv("DCLAW_DEV_MODE"))
	if devMode == "off" || devMode == "0" || devMode == "false" {
		return true
	}
	return false
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

	// AllowAutoRegistration controls whether unknown devices are automatically
	// registered when they send a heartbeat or registration message. In production
	// this should be false — operators must register devices via CLI/API. In dev
	// mode (DCLAW_FLEET_AUTO_REGISTER=true) this can be enabled for convenience.
	// P0-6 fix: default is false to prevent unauthenticated auto-registration.
	AllowAutoRegistration bool

	// NEW-5 fix: decommissioned tracks device IDs that have been decommissioned.
	// MQTT messages from these devices are explicitly rejected with a log message.
	// M-6 fix: Entries now carry a timestamp so the cleanup goroutine can evict
	// stale decommission records after 24 hours to prevent unbounded map growth.
	decommissioned   map[uint64]time.Time
	decommissionedMu sync.RWMutex

	// Metrics hooks (set externally to avoid circular imports)
	onBlock func()

	// H-3 fix: Per-device rate limiter for heartbeat/verdict processing.
	// Tracks the last heartbeat time per device; drops messages faster than minInterval.
	heartbeatMinInterval time.Duration
	lastHeartbeat        map[uint64]time.Time
	lastHeartbeatMu      sync.Mutex

	// CRT-1 fix: Per-device verdict request rate limiter to prevent cache
	// probing and DoS. Allows up to verdictRateLimit requests per second
	// per device; excess requests are dropped with a warning.
	verdictRateMu  sync.Mutex
	verdictRateMap map[uint64]*verdictRateEntry

	// Stats for observability
	mu                  sync.RWMutex
	heartbeatsProcessed uint64
	verdictsProcessed   uint64
	decodeErrors        uint64
	rateLimitDrops      uint64
}

// verdictRateEntry tracks per-device verdict request rate for CRT-1.
type verdictRateEntry struct {
	count    int
	windowAt time.Time
}

// verdictRateLimit is the maximum number of verdict requests per device
// per second. Exceeding this drops the request with a warning log.
const verdictRateLimit = 20

// SetOnBlock configures a callback that fires when a verdict request
// results in a BLOCK action.  Used by WireMetrics to increment the
// fleet-level blocks counter without a circular import.
func (b *Bridge) SetOnBlock(fn func()) {
	b.onBlock = fn
}

// BridgeConfig holds configuration for the MQTT bridge.
type BridgeConfig struct {
	// BrokerURL is the MQTT broker address (e.g. "tcp://localhost:1883").
	BrokerURL string

	// ClientID identifies this fleet manager to the broker.
	ClientID string

	// HeartbeatQoS is the QoS for heartbeat subscriptions (default 0).
	HeartbeatQoS byte

	// VerdictQoS is the QoS for verdict request subscriptions (default 1).
	VerdictQoS byte
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
		heartbeatMinInterval: time.Second, // H-3: 1 heartbeat/sec default
		lastHeartbeat:        make(map[uint64]time.Time),
		verdictRateMap:       make(map[uint64]*verdictRateEntry),
	}
}

// SetHeartbeatRateLimit configures the minimum interval between heartbeats from the same device.
// Zero disables rate limiting (useful for tests).
func (b *Bridge) SetHeartbeatRateLimit(d time.Duration) { b.heartbeatMinInterval = d }

// MarkDecommissioned adds a device ID to the decommissioned set with a timestamp.
// NEW-5 fix: MQTT messages from decommissioned devices are rejected.
// M-6 fix: Records the decommission time for cleanup after 24 hours.
func (b *Bridge) MarkDecommissioned(fullDeviceID uint64) {
	b.decommissionedMu.Lock()
	b.decommissioned[fullDeviceID] = time.Now()
	b.decommissionedMu.Unlock()
}

// isDecommissioned checks if a device has been decommissioned.
func (b *Bridge) isDecommissioned(fullDeviceID uint64) bool {
	b.decommissionedMu.RLock()
	_, ok := b.decommissioned[fullDeviceID]
	b.decommissionedMu.RUnlock()
	return ok
}

// ClearDecommissioned removes a device ID from the decommissioned set.
// P1-tombstone fix: Called when a previously decommissioned device is
// re-registered via the API, so the bridge stops rejecting its MQTT traffic.
func (b *Bridge) ClearDecommissioned(fullDeviceID uint64) {
	b.decommissionedMu.Lock()
	delete(b.decommissioned, fullDeviceID)
	b.decommissionedMu.Unlock()
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

// Start connects to the MQTT broker and begins processing messages.
// It blocks until the context is cancelled or Stop() is called.
func (b *Bridge) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	b.cancelMu.Lock()
	b.cancel = cancel
	b.cancelMu.Unlock()

	if err := b.client.Connect(ctx); err != nil {
		return fmt.Errorf("mqtt connect: %w", err)
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

	// NEW-4 fix: Spawn a goroutine that periodically cleans up stale entries
	// from the rate limiter maps to prevent unbounded memory growth. Entries
	// older than 5 minutes are removed every 60 seconds.
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

				// M-6 fix: Clean decommissioned entries older than 24 hours
				// to prevent unbounded map growth from accumulated decomissions.
				decommCutoff := time.Now().Add(-24 * time.Hour)
				b.decommissionedMu.Lock()
				for id, ts := range b.decommissioned {
					if ts.Before(decommCutoff) {
						delete(b.decommissioned, id)
					}
				}
				b.decommissionedMu.Unlock()
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	_ = b.client.Disconnect()
	b.wg.Wait()
	close(b.stopped)
	return nil
}

// Stop triggers a graceful shutdown of the bridge.
func (b *Bridge) Stop() {
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

// Stats returns bridge processing statistics.
func (b *Bridge) Stats() (heartbeats, verdicts, errors uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.heartbeatsProcessed, b.verdictsProcessed, b.decodeErrors
}

// handleHeartbeat processes a heartbeat message from an edge device.
func (b *Bridge) handleHeartbeat(msg Message) {
	b.wg.Add(1)
	defer b.wg.Done()

	parts, err := ParseTopic(msg.Topic)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] bad heartbeat topic: %v", err)
		b.incErrors()
		return
	}

	// NEW-5 fix: Reject messages from decommissioned devices.
	fullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	if b.isDecommissioned(fullID) {
		b.logger.Printf("[mqtt-bridge] rejected heartbeat from decommissioned device %d", parts.DeviceID)
		b.incErrors()
		return
	}

	// H-3 fix: Per-device rate limiting — drop heartbeats faster than minInterval.
	// 0 = disabled (tests), negative treated as 1s default.
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

	// P1-06 fix: Validate that the device_id in the payload matches the
	// topic's device_id. A mismatch indicates a spoofed heartbeat — an
	// attacker publishing to another device's topic to manipulate its
	// status. This is the same validation pattern as handleRegistration.
	if hw.DeviceID != parts.DeviceID {
		b.logger.Printf("[mqtt-bridge] WARNING: heartbeat rejected — topic device_id=%d does not match payload device_id=%d (possible spoofing attempt)",
			parts.DeviceID, hw.DeviceID)
		b.incErrors()
		return
	}

	// P1-06 fix (HMAC): Verify the HMAC-SHA256 tag on signed heartbeats.
	// An anonymous MQTT publisher can match topic and payload device_id, but
	// cannot forge a valid HMAC without the per-device key. This prevents
	// matching-ID heartbeat spoofing.
	if err := b.verifyMessageHMAC(msg, parts, hw); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: heartbeat rejected — %v", err)
		b.incErrors()
		return
	}

	// Convert to the manager's Heartbeat type
	hb := &manager.Heartbeat{
		DeviceID:       hw.DeviceID,
		UptimeSec:      hw.UptimeSec,
		PolicyVersion:  hw.PolicyVersion,
		FWVersion:      hw.FWVersion,
		DeniedCount:    hw.DeniedCount,
		AllowedCount:   hw.AllowedCount,
		WarnedCount:    hw.WarnedCount,
		EscalatedCount: hw.EscalatedCount,
		CacheHitPct:    hw.CacheHitPct,
		SessionCount:   hw.SessionCount,
		AuditHeadHMAC:  hw.AuditHeadHMAC,
		Flags:          hw.Flags,
		Capabilities:   hw.Capabilities,
	}

	b.fleet.ProcessHeartbeat(parts.TenantID, parts.FleetID, parts.DeviceID, hb)

	b.mu.Lock()
	b.heartbeatsProcessed++
	b.mu.Unlock()
}

// handleRegistration processes a registration message from an edge device.
// The payload uses the same 32-byte heartbeat wire format. Registration is
// idempotent: if the device already exists, RegisterDevice updates safe fields
// and returns ErrDeviceExists, which we silently ignore.
func (b *Bridge) handleRegistration(msg Message) {
	b.wg.Add(1)
	defer b.wg.Done()

	parts, err := ParseTopic(msg.Topic)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] bad registration topic: %v", err)
		b.incErrors()
		return
	}

	// NEW-5 fix: Reject messages from decommissioned devices.
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

	// P0-2 fix: Validate that the device_id in the payload matches the topic's
	// device_id. A mismatch indicates a forged registration — an attacker
	// publishing to another device's topic to impersonate it.
	if hw.DeviceID != parts.DeviceID {
		b.logger.Printf("[mqtt-bridge] WARNING: registration rejected — topic device_id=%d does not match payload device_id=%d (possible spoofing attempt)",
			parts.DeviceID, hw.DeviceID)
		b.incErrors()
		return
	}

	// P1-06 fix (HMAC): Verify the HMAC-SHA256 tag on signed registrations.
	// Without this check, an attacker could overwrite a device's inventory
	// (policy version, firmware, capabilities) by sending an unsigned
	// registration payload to an already-keyed device's topic.
	if err := b.verifyMessageHMAC(msg, parts, hw); err != nil {
		b.logger.Printf("[mqtt-bridge] WARNING: registration rejected — %v", err)
		b.incErrors()
		return
	}

	// P0-6 fix: When AllowAutoRegistration is false (production default),
	// unknown devices are logged but NOT registered. Operators must register
	// devices via CLI/API. This prevents any MQTT client from registering
	// rogue devices by publishing matching topic+payload.
	//
	// Check if the device already exists first — re-registration of known
	// devices is always allowed (idempotent update of safe fields).
	_, existsAlready := b.fleet.GetDevice(manager.ComposeID(
		parts.TenantID, parts.FleetID, parts.DeviceID))

	if !existsAlready && !b.AllowAutoRegistration {
		b.logger.Printf("[mqtt-bridge] WARNING: auto-registration denied for unknown device %d (tenant=%d fleet=%d) — set DCLAW_FLEET_AUTO_REGISTER=true or register via CLI/API",
			parts.DeviceID, parts.TenantID, parts.FleetID)
		return
	}

	_, regErr := b.fleet.RegisterDevice(
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
		b.logger.Printf("[mqtt-bridge] device %d re-registered (idempotent)", parts.DeviceID)
	} else {
		b.logger.Printf("[mqtt-bridge] device %d registered via MQTT (tenant=%d fleet=%d fw=%d policy=%d)",
			parts.DeviceID, parts.TenantID, parts.FleetID, hw.FWVersion, hw.PolicyVersion)
	}
}

// handleVerdictRequest processes a verdict request from an edge device.
// It evaluates the tool hash via the verdict cache and publishes the response
// back to the device on its verdict/resp topic.
func (b *Bridge) handleVerdictRequest(msg Message) {
	b.wg.Add(1)
	defer b.wg.Done()

	parts, err := ParseTopic(msg.Topic)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] bad verdict topic: %v", err)
		b.incErrors()
		return
	}

	// NEW-5 fix: Reject messages from decommissioned devices.
	fullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
	if b.isDecommissioned(fullID) {
		b.logger.Printf("[mqtt-bridge] rejected verdict request from decommissioned device %d", parts.DeviceID)
		b.incErrors()
		return
	}

	// CRT-1 fix: Reject verdict requests from unregistered devices and
	// check device status before evaluating. Also fetch the device record
	// for the H-1 lockdown check below.
	dev, registered := b.fleet.GetDevice(fullID)
	if !registered {
		b.logger.Printf("[mqtt-bridge] rejected verdict request from unregistered device %d (tenant=%d fleet=%d)",
			parts.DeviceID, parts.TenantID, parts.FleetID)
		b.incErrors()
		return
	}

	// H-1 fix: If the device is in lockdown, return BLOCK immediately
	// without evaluating through the pipeline. Lockdown devices must not
	// be able to obtain ALLOW verdicts.
	// NEW-2 fix: Pass the raw CBOR payload so we can extract the real
	// RequestID and ToolHash instead of using sentinel 0 values.
	if dev.Status == manager.StatusLockdown {
		b.logger.Printf("[mqtt-bridge] verdict request from lockdown device %d — returning BLOCK",
			parts.DeviceID)
		b.sendLockdownBlockResponse(parts, msg.Payload)
		b.incErrors()
		return
	}

	// CRT-1 fix: Per-device rate limiting to prevent cache probing and DoS.
	// Allow up to verdictRateLimit requests per device per 1-second window.
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
		b.verdictRateMu.Unlock()

		if overLimit {
			b.logger.Printf("[mqtt-bridge] WARNING: verdict request rate-limited for device %d (%d req/s exceeds limit %d)",
				parts.DeviceID, entry.count, verdictRateLimit)
			b.mu.Lock()
			b.rateLimitDrops++
			b.mu.Unlock()
			return
		}
	}

	// M-7 fix: Validate payload length is at least 32 bytes (minimum CBOR + HMAC)
	// before attempting to split payload/HMAC. Variable-length CBOR payloads
	// shorter than this cannot contain a valid verdict request.
	if len(msg.Payload) < 32 {
		b.logger.Printf("[mqtt-bridge] verdict request from device %d too short (%d bytes, need >= 32)",
			parts.DeviceID, len(msg.Payload))
		b.incErrors()
		return
	}

	vr, err := DecodeVerdictRequest(msg.Payload)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] decode verdict request from device %d: %v", parts.DeviceID, err)
		b.incErrors()
		return
	}

	// H-2 fix: Verify HMAC on verdict requests to prevent a malicious device from
	// probing another device's verdict cache by publishing to its topic. The verdict
	// request CBOR does not carry a device_id field, so we verify identity via HMAC
	// over the topic + payload — the same mechanism as heartbeats/registrations.
	// A device without the per-device key cannot forge a valid HMAC.
	if b.keyProvider != nil {
		vrFullID := manager.ComposeID(parts.TenantID, parts.FleetID, parts.DeviceID)
		vrDeviceKey := b.keyProvider.KeyForDevice(vrFullID)
		if vrDeviceKey == nil {
			b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — key lookup returned nil for device %d (fail closed)", parts.DeviceID)
			b.incErrors()
			return
		}
		if checker, ok := b.keyProvider.(DeviceKeyChecker); ok {
			hasKey, err := checker.HasDeviceKey(vrFullID)
			if err != nil {
				b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — key store error for device %d: %v (fail closed)", parts.DeviceID, err)
				b.incErrors()
				return
			}
			if hasKey {
				// Keyed device: HMAC must be appended as last 32 bytes of payload
				if len(msg.Payload) < 32 {
					b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — keyed device %d sent unsigned verdict request (too short)", parts.DeviceID)
					b.incErrors()
					return
				}
				payloadBody := msg.Payload[:len(msg.Payload)-32]
				payloadHMAC := msg.Payload[len(msg.Payload)-32:]
				mac := hmac.New(sha256.New, vrDeviceKey)
				mac.Write([]byte(msg.Topic))
				mac.Write(payloadBody)
				expected := mac.Sum(nil)
				if !hmac.Equal(expected, payloadHMAC) {
					b.logger.Printf("[mqtt-bridge] WARNING: verdict request rejected — HMAC verification failed for device %d (possible cache probing)", parts.DeviceID)
					b.incErrors()
					return
				}
			} else {
				// M-8 fix: Log when processing verdict requests from unkeyed devices.
				// CRT-1 rate limiting is already applied above, but the absence of a
				// per-device key means HMAC cannot authenticate the sender.
				b.logger.Printf("[mqtt-bridge] WARNING: processing verdict request from unkeyed device %d (no per-device key provisioned)", parts.DeviceID)
			}
		}
	}

	// Evaluate via the verdict cache (cache hit or pipeline execution)
	action, severity := b.cache.Evaluate(vr.ToolHash)

	// Wire block count metric
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
	// NEW-6 fix: HMAC covers all response fields, not just action+request_id+hash prefix.
	resp.HMACTag = computeVerdictHMACFull(deviceKey, sessionID,
		vr.RequestID, resp.Action, resp.Severity, resp.TTL,
		resp.Reason, resp.Flags, resp.ServerTS, vr.ToolHash)

	// Publish the response to the device's verdict/resp topic
	respTopic := fmt.Sprintf("defenseclaw/%d/%d/%d/verdict/resp",
		parts.TenantID, parts.FleetID, parts.DeviceID)

	payload := EncodeVerdictResponse(resp)

	// Use a background context with timeout for the publish since the message
	// handler context may not be the bridge's long-lived context.
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pubCancel()
	if err := b.client.Publish(pubCtx, respTopic, 1, payload); err != nil {
		b.logger.Printf("[mqtt-bridge] publish verdict response to %s: %v", respTopic, err)
		b.incErrors()
		return
	}

	b.mu.Lock()
	b.verdictsProcessed++
	b.mu.Unlock()
}

func (b *Bridge) incErrors() {
	b.mu.Lock()
	b.decodeErrors++
	b.mu.Unlock()
}

// sendLockdownBlockResponse sends a BLOCK verdict response to a device that
// is in lockdown status. H-1 fix: lockdown devices must receive BLOCK for
// every verdict request without going through the evaluation pipeline.
// NEW-2 fix: Accepts the raw CBOR payload and decodes it to extract the real
// RequestID and ToolHash. The C agent discards responses with RequestID==0
// because 0 is its sentinel for "unused slot."
func (b *Bridge) sendLockdownBlockResponse(parts *TopicParts, rawPayload []byte) {
	// Decode the verdict request to get the real RequestID and ToolHash.
	var requestID uint16
	var toolHash [32]byte
	if vr, err := DecodeVerdictRequest(rawPayload); err == nil {
		requestID = vr.RequestID
		toolHash = vr.ToolHash
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
	resp.HMACTag = computeVerdictHMACFull(deviceKey, sessionID,
		resp.RequestID, resp.Action, resp.Severity, resp.TTL,
		resp.Reason, resp.Flags, resp.ServerTS, toolHash)

	respTopic := fmt.Sprintf("defenseclaw/%d/%d/%d/verdict/resp",
		parts.TenantID, parts.FleetID, parts.DeviceID)
	payload := EncodeVerdictResponse(resp)

	pubCtx, pubCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pubCancel()
	if err := b.client.Publish(pubCtx, respTopic, 1, payload); err != nil {
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
		return nil
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
		mac.Write(msg.Payload[:32])
		expected := mac.Sum(nil)

		if !hmac.Equal(expected, hw.HMACTag) {
			return fmt.Errorf("HMAC verification failed for device %d (possible spoofing attempt)", parts.DeviceID)
		}
	} else {
		// Unsigned (legacy) message: check whether this device has a
		// per-device key provisioned. If it does, reject -- an attacker
		// could bypass HMAC by sending a shorter (unsigned) payload.
		// P1-06 fix (fail-closed): key-store errors are treated as
		// "key exists" -- we reject rather than accept on error.
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

// computeVerdictHMACFull computes the 16-byte HMAC tag covering all verdict
// response fields plus the tool hash. BLK-1: extended from 4 to 16 bytes.
func computeVerdictHMACFull(deviceKey []byte, sessionID string,
	requestID uint16, action, severity uint8, ttl uint16,
	reason, flags uint8, serverTS uint32, toolHash [32]byte) [16]byte {

	mac := hmac.New(sha256.New, deviceKey)

	// session_id (string bytes, no NUL terminator — matches C strlen)
	mac.Write([]byte(sessionID))

	// request_id: 2 bytes little-endian (matches C-side)
	var rid [2]byte
	binary.LittleEndian.PutUint16(rid[:], requestID)
	mac.Write(rid[:])

	// action: 1 byte
	mac.Write([]byte{action})

	// NEW-6: severity (1 byte)
	mac.Write([]byte{severity})

	// NEW-6: ttl (2 bytes little-endian)
	var ttlBuf [2]byte
	binary.LittleEndian.PutUint16(ttlBuf[:], ttl)
	mac.Write(ttlBuf[:])

	// NEW-6: reason (1 byte)
	mac.Write([]byte{reason})

	// NEW-6: flags (1 byte)
	mac.Write([]byte{flags})

	// NEW-6: server_ts (4 bytes little-endian)
	var tsBuf [4]byte
	binary.LittleEndian.PutUint32(tsBuf[:], serverTS)
	mac.Write(tsBuf[:])

	// L-1 fix: Use full 32-byte tool_hash (was truncated to 8 bytes)
	mac.Write(toolHash[:])

	full := mac.Sum(nil)
	var tag [16]byte
	copy(tag[:], full[:16])
	return tag
}
