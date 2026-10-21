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

package fleet

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	fleetmqtt "github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

// routerClient records subscriptions so the test can drive the bridge's
// handlers the way the MQTT router does, and counts emergency publishes.
type routerClient struct {
	mu         sync.Mutex
	handlers   map[string]func(fleetmqtt.Message)
	subscribed chan struct{}
	emergency  int
}

func (c *routerClient) Connect(context.Context) error { return nil }
func (c *routerClient) Subscribe(_ context.Context, filter string, _ byte, h func(fleetmqtt.Message)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[filter] = h
	if len(c.handlers) == 3 {
		close(c.subscribed)
	}
	return nil
}
func (c *routerClient) Publish(_ context.Context, topic string, _ byte, _ []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.HasSuffix(topic, "/ota/emergency") {
		c.emergency++
	}
	return nil
}
func (c *routerClient) Disconnect() error { return nil }

func (c *routerClient) emergencyCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.emergency
}

type sameKeyProvider struct{ key []byte }

func (p sameKeyProvider) KeyForDevice(uint64) []byte { return p.key }

func signedHeartbeat(topic string, key []byte, deviceID, uptime, boot, lastEmergency uint32) []byte {
	body := make([]byte, 40)
	binary.BigEndian.PutUint32(body[0:4], deviceID)
	binary.BigEndian.PutUint32(body[4:8], uptime)
	binary.BigEndian.PutUint16(body[10:12], 1)
	binary.BigEndian.PutUint32(body[32:36], boot)
	binary.BigEndian.PutUint32(body[36:40], lastEmergency)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(topic))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

// N devices of one fleet reporting a stale emergency sequence cause one
// catch-up pass (O(1) publishes), and catch-up runs off the router.
func TestLaggingHeartbeatsCoalesceEmergencyCatchup(t *testing.T) {
	t.Setenv("DCLAW_DEV_MODE", "")
	t.Setenv("DCLAW_PRODUCTION", "")
	key := bytes.Repeat([]byte{0x5a}, 32)
	client := &routerClient{handlers: map[string]func(fleetmqtt.Message){}, subscribed: make(chan struct{})}
	signer, err := policy.NewHMACSigner(bytes.Repeat([]byte{0xA7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := policy.NewService(policy.NewMemoryPolicyStore(), signer, client, &policy.Config{
		EmergencyKeyHex: strings.Repeat("ab", 32),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 40; i++ {
		if err := svc.DistributeEmergency(ctx, 1, 2, policy.EmergencyForceSync); err != nil {
			t.Fatal(err)
		}
	}
	base := client.emergencyCount()

	const N = 100
	mgr := manager.New(nil)
	for d := uint32(1); d <= N; d++ {
		if _, err := mgr.RegisterDevice(1, 2, d, "sbc", "1", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	bridge := fleetmqtt.NewBridge(client, mgr, verdict.NewCache(10, nil))
	bridge.SetKeyProvider(sameKeyProvider{key: key})
	bridge.SetHeartbeatRateLimit(0)
	bridge.SetReplayForDevice(svc.ReplayLatestForDevice)
	go func() { _ = bridge.Start(ctx) }()
	<-client.subscribed
	client.mu.Lock()
	handle := client.handlers[fleetmqtt.TopicHeartbeat]
	client.mu.Unlock()

	for round := uint32(0); round < 3; round++ {
		for d := uint32(1); d <= N; d++ {
			topic := fmt.Sprintf("defenseclaw/1/2/%d/heartbeat", d)
			handle(fleetmqtt.Message{Topic: topic, Payload: signedHeartbeat(topic, key, d, 100+round, 1, 0)})
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for client.emergencyCount()-base < 32 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := client.emergencyCount() - base; n != 32 {
		t.Fatalf("%d lagging heartbeats caused %d emergency publishes, want one 32-command page", 3*N, n)
	}
}
