package mqtt

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

// Bridge connects the MQTT subscriber to the fleet manager and verdict cache.
// It subscribes to device heartbeat and verdict-request topics, decodes the
// binary/CBOR payloads, and routes them to the appropriate handlers.
type Bridge struct {
	client  Client
	fleet   *manager.FleetManager
	cache   *verdict.Cache
	logger  *log.Logger
	cancelMu sync.Mutex
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopped  chan struct{}

	// Stats for observability
	mu                  sync.RWMutex
	heartbeatsProcessed uint64
	verdictsProcessed   uint64
	decodeErrors        uint64
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
		client:  client,
		fleet:   fleet,
		cache:   cache,
		logger:  log.Default(),
		stopped: make(chan struct{}),
	}
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

	b.logger.Printf("[mqtt-bridge] subscribed to %s and %s", TopicHeartbeat, TopicVerdictReq)

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
	}

	b.fleet.ProcessHeartbeat(parts.TenantID, parts.FleetID, parts.DeviceID, hb)

	b.mu.Lock()
	b.heartbeatsProcessed++
	b.mu.Unlock()
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

	vr, err := DecodeVerdictRequest(msg.Payload)
	if err != nil {
		b.logger.Printf("[mqtt-bridge] decode verdict request from device %d: %v", parts.DeviceID, err)
		b.incErrors()
		return
	}

	// Evaluate via the verdict cache (cache hit or pipeline execution)
	action, severity := b.cache.Evaluate(vr.ToolHash)

	// Build a response
	resp := &VerdictResponse{
		RequestID: vr.RequestID,
		Action:    uint8(action),
		Severity:  severity,
		TTL:       60, // 60 minutes default TTL
		ServerTS:  uint32(time.Now().Unix()),
	}

	// Publish the response to the device's verdict/resp topic
	respTopic := fmt.Sprintf("defenseclaw/%d/%d/%d/verdict/resp",
		parts.TenantID, parts.FleetID, parts.DeviceID)

	payload := EncodeVerdictResponse(resp)

	// Use a background context for the publish since the message handler
	// context may not be the bridge's long-lived context.
	if err := b.client.Publish(context.Background(), respTopic, 1, payload); err != nil {
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
