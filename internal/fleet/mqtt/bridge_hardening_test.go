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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
	"github.com/eclipse/paho.golang/paho"
)

// mapKeyStore implements DeviceKeyLookup with rotation support.
type mapKeyStore struct {
	mu   sync.Mutex
	keys map[uint64][]byte
}

func (m *mapKeyStore) LoadDeviceKey(id uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), k...), nil
}

// productionEnv clears every development override so isProductionMode()
// takes its fail-closed default.
func productionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DCLAW_DEV_MODE", "")
	t.Setenv("DCLAW_PRODUCTION", "")
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DCLAW_DEVICE_KEY", "")
}

func quietBridge(b *Bridge) { b.logger = log.New(io.Discard, "", 0) }

func signedHB(topic string, key []byte, deviceID, uptime, boot uint32, flags uint8) []byte {
	body := makeHeartbeatPayload(deviceID, 1, 0, flags)
	binary.BigEndian.PutUint32(body[4:8], uptime)
	binary.BigEndian.PutUint32(body[32:36], boot)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(topic))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

func signedVerdictReq(topic string, key []byte, vr *VerdictRequest) []byte {
	body := EncodeVerdictRequestCBOR(vr)
	body = append(body, encodeCBORBytes(vr.RequestNonce[:])...)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(topic))
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

func newVR(id uint16, boot [16]byte, rn [4]byte) *VerdictRequest {
	return &VerdictRequest{RequestID: id, ToolHash: [32]byte{0xAA}, ToolName: "shell",
		Destination: "x", Content: "c", BootNonce: boot, RequestNonce: rn}
}

func verdictPublishes(b *Bridge, c *mockClient) []Message {
	b.responsePending.Wait()
	var out []Message
	for _, m := range c.getPublished() {
		if strings.HasSuffix(m.Topic, "/verdict/resp") {
			out = append(out, m)
		}
	}
	return out
}

func allowCache() *verdict.Cache {
	return verdict.NewCache(10, func(_, _ uint16, _ [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})
}

// Outside development mode a fleet-wide DCLAW_DEVICE_KEY must never stand in
// for a missing per-device key: unsigned verdict requests from such a device
// are refused, and a heartbeat signed with the shared key is rejected.
func TestProductionIgnoresSharedDeviceKeyFallback(t *testing.T) {
	productionEnv(t)
	fleetKey := []byte("FLEETWIDE-KEY-0123456789abcdef!!")
	t.Setenv("DCLAW_DEVICE_KEY", hex.EncodeToString(fleetKey))
	if !isProductionMode() {
		t.Fatal("setup: expected production mode")
	}
	if k := newStoreBackedKeyProvider(nil).KeyForDevice(1); k != nil {
		t.Fatal("store provider returned the shared fleet key in production")
	}
	if k := newEnvDeviceKeyProvider().KeyForDevice(1); k != nil {
		t.Fatal("legacy env provider returned the shared fleet key in production")
	}

	fm := manager.New(nil)
	fm.RegisterDevice(2, 1, 7, "sbc", "1", 1, 0)
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetDeviceKeyStore(&mapKeyStore{keys: map[uint64][]byte{}}) // no per-device key
	b.SetHeartbeatRateLimit(0)

	unsigned := EncodeVerdictRequestCBOR(newVR(9, [16]byte{1}, [4]byte{1}))
	unsigned = append(unsigned, make([]byte, 32)...)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/2/1/7/verdict/req", Payload: unsigned})
	if n := len(verdictPublishes(b, c)); n != 0 {
		t.Fatalf("unsigned verdict request from an unkeyed device answered in production: %d", n)
	}

	topic := "defenseclaw/2/1/7/heartbeat"
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, fleetKey, 7, 500, 1, 0x04)})
	if d, _ := fm.GetDevice(manager.ComposeID(2, 1, 7)); d.Status == manager.StatusLockdown {
		t.Fatal("heartbeat signed with the shared fleet key accepted in production")
	}
}

// A custom key provider that reports an all-zero key cannot make a production
// gateway answer unsigned verdict requests.
func TestProductionVerdictRequiresHMACWithZeroKeyProvider(t *testing.T) {
	productionEnv(t)
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetKeyProvider(&fixedKeyProvider{key: make([]byte, 32)})
	unsigned := EncodeVerdictRequestCBOR(newVR(9, [16]byte{1}, [4]byte{1}))
	unsigned = append(unsigned, make([]byte, 32)...)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/1/2/42/verdict/req", Payload: unsigned})
	if n := len(verdictPublishes(b, c)); n != 0 {
		t.Fatalf("unsigned verdict request answered in production: %d", n)
	}
	b.SetKeyProvider(nil)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/1/2/42/verdict/req", Payload: unsigned})
	if n := len(verdictPublishes(b, c)); n != 0 {
		t.Fatalf("verdict request answered without a key provider: %d", n)
	}
}

// A forged frame on a device's heartbeat topic must not consume the rate-limit
// slot of the genuine, correctly signed heartbeat that follows it.
func TestForgedHeartbeatDoesNotConsumeRateLimitSlot(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	ks := &mapKeyStore{keys: map[uint64][]byte{manager.ComposeID(1, 2, 42): key}}
	b := NewBridge(newMockClient(), fm, verdict.NewCache(10, nil))
	quietBridge(b)
	b.SetDeviceKeyStore(ks)
	b.SetHeartbeatRateLimit(time.Second)
	topic := "defenseclaw/1/2/42/heartbeat"

	b.handleHeartbeat(Message{Topic: topic, Payload: []byte{1, 2, 3}})
	forged := signedHB(topic, []byte("WRONGKEYWRONGKEYWRONGKEYWRONGKEY"), 42, 90, 1, 0)
	b.handleHeartbeat(Message{Topic: topic, Payload: forged})
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, key, 42, 100, 1, 0)})
	if hb, _, _ := b.Stats(); hb != 1 {
		t.Fatalf("genuine heartbeat suppressed by forged frames: processed=%d", hb)
	}
	// The authenticated heartbeat does consume the slot.
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, key, 42, 101, 1, 0)})
	if hb, _, _ := b.Stats(); hb != 1 {
		t.Fatalf("second heartbeat within the interval was not rate limited: processed=%d", hb)
	}
}

// Frames on unregistered IDs must not allocate rate-limit state, so they
// cannot fill the map and block heartbeats fleet-wide.
func TestUnregisteredHeartbeatsDoNotFillRateLimitMap(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	ks := &mapKeyStore{keys: map[uint64][]byte{manager.ComposeID(1, 2, 42): key}}
	b := NewBridge(newMockClient(), fm, verdict.NewCache(10, nil))
	quietBridge(b)
	b.SetDeviceKeyStore(ks)
	for i := uint32(1); i <= maxHeartbeatEntries+10; i++ {
		b.handleHeartbeat(Message{Topic: fmt.Sprintf("defenseclaw/9/9/%d/heartbeat", i), Payload: []byte{0}})
	}
	b.lastHeartbeatMu.Lock()
	n := len(b.lastHeartbeat)
	b.lastHeartbeatMu.Unlock()
	if n != 0 {
		t.Fatalf("unauthenticated frames allocated %d rate-limit entries", n)
	}
	topic := "defenseclaw/1/2/42/heartbeat"
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, key, 42, 100, 1, 0)})
	if hb, _, _ := b.Stats(); hb != 1 {
		t.Fatalf("registered device's heartbeat dropped: processed=%d", hb)
	}
}

// A full map of stale entries is swept rather than blocking new devices.
func TestHeartbeatRateMapSweepsStaleEntriesWhenFull(t *testing.T) {
	b := NewBridge(newMockClient(), manager.New(nil), verdict.NewCache(10, nil))
	quietBridge(b)
	b.SetHeartbeatRateLimit(time.Second)
	old := time.Now().Add(-time.Minute)
	for i := uint64(0); i < maxHeartbeatEntries; i++ {
		b.lastHeartbeat[i+1_000_000] = old
	}
	if !b.allowHeartbeat(7, 7, time.Now()) {
		t.Fatal("heartbeat dropped although every map entry was stale")
	}
	if n := len(b.lastHeartbeat); n != 1 {
		t.Fatalf("stale entries not swept: %d", n)
	}
}

// Unauthenticated frames on the verdict topic must not exhaust the device's
// per-second verdict budget.
func TestForgedVerdictRequestsDoNotExhaustBudget(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	ks := &mapKeyStore{keys: map[uint64][]byte{manager.ComposeID(1, 2, 42): key}}
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetDeviceKeyStore(ks)
	topic := "defenseclaw/1/2/42/verdict/req"
	junk := make([]byte, 64)
	for i := 0; i < 5*verdictRateLimit; i++ {
		b.handleVerdictRequest(Message{Topic: topic, Payload: junk})
	}
	good := signedVerdictReq(topic, key, newVR(7, [16]byte{1}, [4]byte{1, 2, 3, 4}))
	b.handleVerdictRequest(Message{Topic: topic, Payload: good})
	if n := len(verdictPublishes(b, c)); n != 1 {
		t.Fatalf("genuine request starved by forged frames: responses=%d", n)
	}
}

// A device in lockdown gets a signed BLOCK only for an authenticated request:
// the gateway must not sign responses over attacker-chosen fields, and the
// lockdown path is rate limited like any other.
func TestLockdownBlockRequiresAuthenticatedRequest(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	full := manager.ComposeID(1, 2, 42)
	ks := &mapKeyStore{keys: map[uint64][]byte{full: key}}
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetDeviceKeyStore(ks)
	b.SetHeartbeatRateLimit(0)
	hbTopic := "defenseclaw/1/2/42/heartbeat"
	b.handleHeartbeat(Message{Topic: hbTopic, Payload: signedHB(hbTopic, key, 42, 100, 1, 0x04)})
	if d, _ := fm.GetDevice(full); d.Status != manager.StatusLockdown {
		t.Fatalf("setup: status=%s", d.Status)
	}
	topic := "defenseclaw/1/2/42/verdict/req"
	chosenNonce := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}
	vr := newVR(0x1234, [16]byte{0xB0, 0x07}, chosenNonce)
	unsigned := append(EncodeVerdictRequestCBOR(vr), encodeCBORBytes(chosenNonce[:])...)
	unsigned = append(unsigned, make([]byte, 32)...)
	for i := 0; i < 50; i++ {
		b.handleVerdictRequest(Message{Topic: topic, Payload: unsigned})
	}
	if n := len(verdictPublishes(b, c)); n != 0 {
		t.Fatalf("lockdown path signed %d responses for unauthenticated requests", n)
	}

	good := signedVerdictReq(topic, key, vr)
	for i := 0; i < 2*verdictRateLimit; i++ {
		b.handleVerdictRequest(Message{Topic: topic, Payload: good})
	}
	pubs := verdictPublishes(b, c)
	if len(pubs) != verdictRateLimit {
		t.Fatalf("lockdown responses=%d, want %d (rate limited)", len(pubs), verdictRateLimit)
	}
	p := pubs[0].Payload
	if p[2] != uint8(verdict.ActionBlock) || binary.BigEndian.Uint16(p[0:2]) != 0x1234 {
		t.Fatalf("lockdown response is not a BLOCK for the request: % x", p[:12])
	}
	want := computeVerdictHMACFull(key, "42", 0x1234, p[2], p[3], binary.BigEndian.Uint16(p[4:6]), p[6], p[7],
		binary.BigEndian.Uint32(p[8:12]), vr.ToolHash, vr.BootNonce, chosenNonce)
	if !hmac.Equal(want[:], p[12:44]) {
		t.Fatal("lockdown BLOCK not signed over the authenticated request")
	}
}

// An emergency lockdown reported in a heartbeat (flag 0x40) shows as status
// lockdown but must not make the gateway answer BLOCK: the device enforces it
// and may already have released it before its next heartbeat.
func TestEmergencyLockdownFlagDoesNotForceGatewayBlock(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	full := manager.ComposeID(1, 2, 42)
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetDeviceKeyStore(&mapKeyStore{keys: map[uint64][]byte{full: key}})
	b.SetHeartbeatRateLimit(0)
	hbTopic := "defenseclaw/1/2/42/heartbeat"
	b.handleHeartbeat(Message{Topic: hbTopic, Payload: signedHB(hbTopic, key, 42, 100, 1, 0x40)})
	if d, _ := fm.GetDevice(full); d.Status != manager.StatusLockdown || !d.EmergencyLockdown {
		t.Fatalf("setup: status=%s emergency_lockdown=%v", d.Status, d.EmergencyLockdown)
	}
	topic := "defenseclaw/1/2/42/verdict/req"
	vr := newVR(0x2222, [16]byte{0xB0, 0x07}, [4]byte{1, 2, 3, 4})
	b.handleVerdictRequest(Message{Topic: topic, Payload: signedVerdictReq(topic, key, vr)})
	pubs := verdictPublishes(b, c)
	if len(pubs) != 1 || pubs[0].Payload[2] != uint8(verdict.ActionAllow) {
		t.Fatalf("emergency-lockdown device got %d responses (action % x), want the normal ALLOW", len(pubs), pubs)
	}
}

// Outside development mode a signed verdict request without boot/request
// nonces is rejected; one carrying both is answered.
func TestProductionRejectsSignedVerdictRequestWithoutNonces(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	ks := &mapKeyStore{keys: map[uint64][]byte{manager.ComposeID(1, 2, 42): key}}
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	b.SetDeviceKeyStore(ks)
	topic := "defenseclaw/1/2/42/verdict/req"
	sign := func(body []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(topic))
		mac.Write(body)
		return append(body, mac.Sum(nil)...)
	}
	noNonce := EncodeVerdictRequestCBOR(&VerdictRequest{RequestID: 5, ToolHash: [32]byte{0xAA}})
	b.handleVerdictRequest(Message{Topic: topic, Payload: sign(noNonce)})
	bootOnly := EncodeVerdictRequestCBOR(&VerdictRequest{RequestID: 6, ToolHash: [32]byte{0xAA}, BootNonce: [16]byte{1}})
	b.handleVerdictRequest(Message{Topic: topic, Payload: sign(bootOnly)})
	zeroBoot := EncodeVerdictRequestCBOR(&VerdictRequest{RequestID: 7, ToolHash: [32]byte{0xAA}})
	zeroBoot = append(zeroBoot, encodeCBORBytes(make([]byte, 16))...)
	zeroBoot = append(zeroBoot, encodeCBORBytes([]byte{1, 2, 3, 4})...)
	b.handleVerdictRequest(Message{Topic: topic, Payload: sign(zeroBoot)})
	if n := len(verdictPublishes(b, c)); n != 0 {
		t.Fatalf("nonce-less signed requests answered in production: %d", n)
	}
	b.handleVerdictRequest(Message{Topic: topic, Payload: signedVerdictReq(topic, key, newVR(8, [16]byte{9}, [4]byte{}))})
	if n := len(verdictPublishes(b, c)); n != 1 {
		t.Fatalf("request with both nonces not answered: %d", n)
	}
}

func TestDecodeVerdictRequestReportsNonces(t *testing.T) {
	full := append(EncodeVerdictRequestCBOR(newVR(1, [16]byte{1}, [4]byte{})), encodeCBORBytes(make([]byte, 4))...)
	vr, err := DecodeVerdictRequest(full)
	if err != nil || !vr.HasNonces {
		t.Fatalf("full request: HasNonces=%v err=%v", vr != nil && vr.HasNonces, err)
	}
	vr, err = DecodeVerdictRequest(EncodeVerdictRequestCBOR(newVR(1, [16]byte{1}, [4]byte{})))
	if err != nil || vr.HasNonces {
		t.Fatalf("boot nonce only: HasNonces=%v err=%v", vr != nil && vr.HasNonces, err)
	}
}

// Catch-up runs off the MQTT router: a slow replay must not block the
// heartbeat handler (and so every other device's traffic).
func TestReplayDoesNotBlockHeartbeatHandler(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 0, 0)
	b := newTestBridge(t, newMockClient(), fm, verdict.NewCache(10, nil))
	quietBridge(b)
	b.SetHeartbeatRateLimit(0)
	b.SetKeyProvider(&fixedKeyProvider{key: key})
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	b.SetReplayForDevice(func(ctx context.Context, _, _ uint64, _ uint16, _ uint32) (uint32, error) {
		started <- struct{}{}
		<-release
		return 0, nil
	})
	topic := "defenseclaw/1/2/42/heartbeat"
	done := make(chan struct{})
	go func() {
		b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, key, 42, 100, 1, 0)})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("heartbeat handler blocked on catch-up")
	}
	<-started
	// While the replay is in flight a fresh heartbeat is processed without
	// queuing a duplicate replay for the same device.
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, key, 42, 101, 1, 0)})
	if hb, _, _ := b.Stats(); hb != 2 {
		t.Fatalf("heartbeats processed=%d, want 2", hb)
	}
	close(release)
	b.replayPending.Wait()
}

// After a key change the bridge's catch-up baseline is reset, so a device
// whose boot counter restarted still gets OTA catch-up.
func TestResetDeviceLineageRestoresCatchup(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 0, 0)
	b := newTestBridge(t, newMockClient(), fm, verdict.NewCache(10, nil))
	quietBridge(b)
	b.SetHeartbeatRateLimit(0)
	b.SetKeyProvider(&fixedKeyProvider{key: key})
	var mu sync.Mutex
	calls := 0
	b.SetReplayForDevice(func(context.Context, uint64, uint64, uint16, uint32) (uint32, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return 0, nil
	})
	topic := "defenseclaw/1/2/42/heartbeat"
	b.handleHeartbeat(Message{Topic: topic, Payload: signedHB(topic, key, 42, 7200, 5, 0)})
	b.replayPending.Wait()
	full := manager.ComposeID(1, 2, 42)
	// The API calls this after a new key; the manager-side reset is covered
	// by the fleet package tests.
	b.ResetDeviceLineage(full)
	b.replayMu.Lock()
	_, kept := b.replayState[full]
	b.replayMu.Unlock()
	if kept {
		t.Fatal("replay baseline kept after lineage reset")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("catch-up calls=%d, want 1", calls)
	}
}

type countingKeyProvider struct {
	mu    sync.Mutex
	calls int
	key   []byte
}

func (p *countingKeyProvider) KeyForDevice(uint64) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.key
}

// Oversized verdict frames are dropped before any key lookup or HMAC.
func TestOversizedVerdictFrameRejectedBeforeHMAC(t *testing.T) {
	productionEnv(t)
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	c := newMockClient()
	b := NewBridge(c, fm, allowCache())
	quietBridge(b)
	kp := &countingKeyProvider{key: []byte("0123456789abcdef0123456789abcdef")}
	b.SetKeyProvider(kp)
	b.handleVerdictRequest(Message{Topic: "defenseclaw/1/2/42/verdict/req", Payload: make([]byte, maxVerdictFrame+1)})
	if kp.calls != 0 {
		t.Fatalf("oversized frame reached key lookup (%d calls)", kp.calls)
	}
	if _, _, errs := b.Stats(); errs != 1 {
		t.Fatalf("oversized frame not counted as an error: %d", errs)
	}
	if n := len(verdictPublishes(b, c)); n != 0 {
		t.Fatalf("oversized frame answered: %d", n)
	}
}

// A slow broker publish does not block the verdict handler.
func TestVerdictResponsePublishDoesNotBlockHandler(t *testing.T) {
	productionEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0)
	slow := &blockingClient{mockClient: newMockClient(), release: make(chan struct{})}
	b := NewBridge(slow, fm, allowCache())
	quietBridge(b)
	b.SetKeyProvider(&fixedKeyProvider{key: key})
	topic := "defenseclaw/1/2/42/verdict/req"
	done := make(chan struct{})
	go func() {
		for i := 0; i < 3; i++ {
			b.handleVerdictRequest(Message{Topic: topic, Payload: signedVerdictReq(topic, key, newVR(uint16(i+1), [16]byte{1}, [4]byte{1}))})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("verdict handler blocked on a slow publish")
	}
	close(slow.release)
	if n := len(verdictPublishes(b, slow.mockClient)); n != 3 {
		t.Fatalf("responses=%d, want 3", n)
	}
}

type blockingClient struct {
	*mockClient
	release chan struct{}
}

func (c *blockingClient) Publish(ctx context.Context, topic string, qos byte, payload []byte) error {
	select {
	case <-c.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return c.mockClient.Publish(ctx, topic, qos, payload)
}

func TestConnectAdvertisesMaximumPacketSize(t *testing.T) {
	cp, err := limitInboundPacketSize(&paho.Connect{Properties: &paho.ConnectProperties{SessionExpiryInterval: new(uint32)}}, nil)
	if err != nil || cp.Properties.MaximumPacketSize == nil || *cp.Properties.MaximumPacketSize != maxInboundPacketSize ||
		cp.Properties.SessionExpiryInterval == nil {
		t.Fatalf("connect properties not limited correctly: %+v err=%v", cp.Properties, err)
	}
	cp, _ = limitInboundPacketSize(&paho.Connect{}, nil)
	if cp.Properties == nil || cp.Properties.MaximumPacketSize == nil {
		t.Fatal("maximum packet size not set on a bare CONNECT")
	}
}

func TestProductionFlagParsedCaseInsensitively(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "True", " true ", "yes", "on", "typo"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DCLAW_DEV_MODE", "ON")
			t.Setenv("DCLAW_PRODUCTION", v)
			if !isProductionMode() {
				t.Fatalf("DCLAW_PRODUCTION=%q with DCLAW_DEV_MODE=ON selected development mode", v)
			}
		})
	}
	for _, v := range []string{"", "0", "false", "FALSE", "no", "off"} {
		t.Run("explicit-off-"+v, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DCLAW_DEV_MODE", "ON")
			t.Setenv("DCLAW_PRODUCTION", v)
			if isProductionMode() {
				t.Fatalf("DCLAW_PRODUCTION=%q overrode explicit development mode", v)
			}
		})
	}
}

// The fallback key comes from the caller (fleet.device_key_env), and is used
// only in development mode.
func TestDeviceKeyFallbackFromConfiguredEnv(t *testing.T) {
	custom := strings.Repeat("cd", 32)
	t.Setenv("DCLAW_DEVICE_KEY", strings.Repeat("ef", 32))
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DCLAW_PRODUCTION", "")
	t.Setenv("DCLAW_DEV_MODE", "ON")
	b := NewBridge(newMockClient(), manager.New(nil), verdict.NewCache(10, nil))
	quietBridge(b)
	b.SetDeviceKeyStoreWithFallback(&mapKeyStore{keys: map[uint64][]byte{}}, custom)
	if got := hex.EncodeToString(b.keyProvider.KeyForDevice(1)); got != custom {
		t.Fatalf("development fallback key = %s, want the configured one", got)
	}
	t.Setenv("DCLAW_DEV_MODE", "")
	b.SetDeviceKeyStoreWithFallback(&mapKeyStore{keys: map[uint64][]byte{}}, custom)
	if k := b.keyProvider.KeyForDevice(1); k != nil {
		t.Fatal("configured fallback key used outside development mode")
	}
}
