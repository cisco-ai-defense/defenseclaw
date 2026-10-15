// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mqtt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

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
	bridge.handleRegistration(Message{Topic: register, Payload: first})
	if calls != 1 {
		t.Fatalf("captured registration replay amplified OTA: %d callback calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 3600, 1)})
	if calls != 1 {
		t.Fatalf("same-time heartbeat duplicated OTA replay: %d calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 3601, 1)})
	if calls != 2 || lastSeen != 0 {
		t.Fatalf("fresh heartbeat did not use signed device emergency sequence: calls=%d lastSeq=%d", calls, lastSeen)
	}
	bridge.handleRegistration(Message{Topic: register, Payload: first})
	if calls != 2 {
		t.Fatalf("registration older than durable heartbeat caused OTA replay: %d calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 10, 2)})
	if calls != 3 {
		t.Fatalf("new boot did not trigger catch-up: %d calls", calls)
	}
	bridge.handleHeartbeat(Message{Topic: heartbeat, Payload: signedReplayFrame(heartbeat, key, 9999, 1)})
	if calls != 3 {
		t.Fatalf("old boot replay triggered catch-up: %d calls", calls)
	}
	bridge.handleRegistration(Message{Topic: register, Payload: makeHeartbeatPayload(42, 0, 0, 0)})
	if calls != 3 {
		t.Fatalf("unsigned development frame triggered catch-up: %d calls", calls)
	}
}
