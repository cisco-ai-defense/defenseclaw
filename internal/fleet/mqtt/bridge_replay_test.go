// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mqtt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

func signedReplayFrame(topic string, key []byte, uptime, boot uint32) []byte {
	body := makeHeartbeatPayload(42, 0, 0, 0)
	binary.BigEndian.PutUint32(body[4:8], uptime)
	binary.BigEndian.PutUint32(body[32:36], boot)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(topic))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

func TestBridgeReplayOnlyOnFreshSignedDeviceFrames(t *testing.T) {
	const register = "defenseclaw/1/2/42/register"
	const heartbeat = "defenseclaw/1/2/42/heartbeat"
	key := []byte("12345678901234567890123456789012")
	fleet := manager.New(nil)
	fleet.RegisterDevice(1, 2, 42, "sbc", "1", 0, 0)
	bridge := newTestBridge(t, newMockClient(), fleet, verdict.NewCache(10, nil))
	bridge.SetHeartbeatRateLimit(0)
	bridge.SetKeyProvider(&fixedKeyProvider{key: key})
	var calls, lastSeen int
	bridge.SetReplayForDevice(func(_ context.Context, tenant, fleetID uint64, version uint16, lastSeq uint32) (uint32, error) {
		if tenant != 1 || fleetID != 2 || version != 0 {
			t.Fatalf("wrong replay scope/version: %d/%d/%d", tenant, fleetID, version)
		}
		calls++
		lastSeen = int(lastSeq)
		return 7, nil
	})
	first := signedReplayFrame(register, key, 3600, 1)
	bridge.handleRegistration(Message{Topic: register, Payload: first})
	bridge.replayPending.Wait()
	bridge.handleRegistration(Message{Topic: register, Payload: first})
	bridge.replayPending.Wait()
	if calls != 1 {
		t.Fatalf("captured registration replay amplified OTA: %d callback calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 3600, 1)})
	bridge.replayPending.Wait()
	if calls != 1 {
		t.Fatalf("same-time heartbeat duplicated OTA replay: %d calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 3601, 1)})
	bridge.replayPending.Wait()
	if calls != 2 || lastSeen != 0 {
		t.Fatalf("fresh heartbeat did not use signed device emergency sequence: calls=%d lastSeq=%d", calls, lastSeen)
	}
	bridge.handleRegistration(Message{Topic: register, Payload: first})
	bridge.replayPending.Wait()
	if calls != 2 {
		t.Fatalf("registration older than durable heartbeat caused OTA replay: %d calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 10, 2)})
	bridge.replayPending.Wait()
	if calls != 3 {
		t.Fatalf("new boot did not trigger catch-up: %d calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 9999, 1)})
	bridge.replayPending.Wait()
	if calls != 3 {
		t.Fatalf("old boot replay triggered catch-up: %d calls", calls)
	}
	bridge.handleRegistration(Message{Topic: register, Payload: makeHeartbeatPayload(42, 0, 0, 0)})
	bridge.replayPending.Wait()
	if calls != 3 {
		t.Fatalf("unsigned development frame triggered catch-up: %d calls", calls)
	}
}

// The bridge must tell the manager whether a heartbeat was HMAC-verified so
// only signed frames update the operator-visible emergency sequence.
func TestBridgeHeartbeatEmergencySeqOnlyFromSignedFrames(t *testing.T) {
	const heartbeat = "defenseclaw/1/2/42/heartbeat"
	key := []byte("12345678901234567890123456789012")
	fleet := manager.New(nil)
	fleet.RegisterDevice(1, 2, 42, "sbc", "1", 0, 0)
	bridge := newTestBridge(t, newMockClient(), fleet, verdict.NewCache(10, nil))
	bridge.SetHeartbeatRateLimit(0)
	bridge.SetKeyProvider(&fixedKeyProvider{key: key})
	seq := func() uint32 {
		dev, ok := fleet.GetDevice(manager.ComposeID(1, 2, 42))
		if !ok {
			t.Fatal("device missing")
		}
		return dev.LastEmergencySeq
	}

	unsigned := makeHeartbeatPayload(42, 0, 0, 0)
	binary.BigEndian.PutUint32(unsigned[36:40], 9)
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: unsigned})
	if hb, _, _ := bridge.Stats(); hb != 1 {
		t.Fatalf("unsigned development heartbeat not processed: %d", hb)
	}
	if got := seq(); got != 0 {
		t.Fatalf("unsigned heartbeat set LastEmergencySeq = %d, want 0", got)
	}

	body := makeHeartbeatPayload(42, 0, 0, 0)
	binary.BigEndian.PutUint32(body[4:8], 3700)
	binary.BigEndian.PutUint32(body[36:40], 5)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(heartbeat))
	mac.Write(body)
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: append(body, mac.Sum(nil)...)})
	bridge.replayPending.Wait()
	if got := seq(); got != 5 {
		t.Fatalf("signed heartbeat LastEmergencySeq = %d, want 5", got)
	}
}

// waitOrFail fails the test if wg does not reach zero promptly.
func waitOrFail(t *testing.T, wg *sync.WaitGroup, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s still pending after shutdown", what)
	}
}

// A job queued after the workers exited on shutdown must be discarded:
// its pending count released and the device's catch-up no longer in flight.
func TestBridgeShutdownDrainsQueuedReplayAndResponseJobs(t *testing.T) {
	const heartbeat = "defenseclaw/1/2/42/heartbeat"
	key := []byte("12345678901234567890123456789012")
	fleet := manager.New(nil)
	fleet.RegisterDevice(1, 2, 42, "sbc", "1", 0, 0)
	bridge := newTestBridge(t, newMockClient(), fleet, verdict.NewCache(10, nil))
	bridge.SetHeartbeatRateLimit(0)
	bridge.SetKeyProvider(&fixedKeyProvider{key: key})
	bridge.SetReplayForDevice(func(context.Context, uint64, uint64, uint16, uint32) (uint32, error) {
		return 0, nil
	})

	// Start both worker pools, then shut down and let them exit.
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 100, 1)})
	bridge.replayPending.Wait()
	bridge.enqueueResponse(responseJob{topic: "defenseclaw/1/2/42/verdict/resp", payload: []byte{1}})
	bridge.responsePending.Wait()
	bridge.stopOnce.Do(func() { close(bridge.stopped) })
	time.Sleep(50 * time.Millisecond)

	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 200, 1)})
	bridge.enqueueResponse(responseJob{topic: "defenseclaw/1/2/42/verdict/resp", payload: []byte{2}})
	waitOrFail(t, &bridge.replayPending, "replay job")
	waitOrFail(t, &bridge.responsePending, "response job")
	bridge.replayMu.Lock()
	inFlight := bridge.replayState[manager.ComposeID(1, 2, 42)].inFlight
	bridge.replayMu.Unlock()
	if inFlight {
		t.Fatal("discarded replay job left device catch-up in flight")
	}
}
