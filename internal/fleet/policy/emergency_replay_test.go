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

package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
)

// replayDevice mirrors the device-side emergency acceptance rules: HMAC,
// strictly increasing sequence and matching fleet predecessor.
type replayDevice struct {
	key      []byte
	lastSeen uint32
	lockdown bool
}

func (d *replayDevice) apply(msg []byte) bool {
	if len(msg) != EmergencyMsgSize {
		return false
	}
	mac := hmac.New(sha256.New, d.key)
	mac.Write(msg[:48])
	if !hmac.Equal(mac.Sum(nil), msg[48:80]) {
		return false
	}
	seq := binary.BigEndian.Uint32(msg[0:4])
	if seq <= d.lastSeen || binary.BigEndian.Uint32(msg[44:48]) != d.lastSeen {
		return false
	}
	d.lastSeen = seq
	switch EmergencyCommand(msg[8]) {
	case EmergencyBlockAll, EmergencyEnterLockdown:
		d.lockdown = true
	case EmergencyReleaseLockdown:
		d.lockdown = false
	}
	return true
}

var errTestPublish = errors.New("injected publish failure")

func publishedCount(mc *mockMQTTClient) int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return len(mc.published)
}

// N lagging heartbeats from one fleet cause one replay pass, not N.
func TestEmergencyCatchupCoalescesPerFleet(t *testing.T) {
	svc, mc, _ := newTestService()
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		if err := svc.DistributeEmergency(ctx, 1, 2, EmergencyForceSync); err != nil {
			t.Fatal(err)
		}
	}
	before := publishedCount(mc)
	const N = 200
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := publishedCount(mc) - before; n != 32 {
		t.Fatalf("%d lagging heartbeats caused %d publishes, want one 32-command page", N, n)
	}

	// Devices whose position is covered by the recent pass add nothing.
	before = publishedCount(mc)
	for _, seq := range []uint32{0, 1, 10, 31} {
		if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, seq); err != nil {
			t.Fatal(err)
		}
	}
	if n := publishedCount(mc) - before; n != 0 {
		t.Fatalf("covered devices caused %d publishes", n)
	}

	// A device that applied the whole page gets the next page.
	if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 32); err != nil {
		t.Fatal(err)
	}
	if n := publishedCount(mc) - before; n != 8 {
		t.Fatalf("next page published %d commands, want 8", n)
	}

	// Another fleet is not throttled by this one.
	if err := svc.DistributeEmergency(ctx, 1, 3, EmergencyForceSync); err != nil {
		t.Fatal(err)
	}
	before = publishedCount(mc)
	if _, err := svc.ReplayLatestForDevice(ctx, 1, 3, 0, 0); err != nil {
		t.Fatal(err)
	}
	if n := publishedCount(mc) - before; n != 1 {
		t.Fatalf("other fleet replay published %d, want 1", n)
	}
}

// The per-window pass budget bounds publishes even for devices reporting
// positions that no recent pass covers.
func TestEmergencyCatchupBudgetPerWindow(t *testing.T) {
	svc, mc, store := newTestService()
	ctx := context.Background()
	for i := 0; i < 10*32; i++ {
		if err := svc.DistributeEmergency(ctx, 1, 2, EmergencyForceSync); err != nil {
			t.Fatal(err)
		}
	}
	var pageStarts []uint32
	for after := uint32(0); len(pageStarts) < 10; {
		pageStarts = append(pageStarts, after)
		page, err := store.GetEmergenciesAfter(1, 2, after, 32)
		if err != nil || len(page) != 32 {
			t.Fatalf("history page: %d records, err=%v", len(page), err)
		}
		after = page[31].Sequence
	}
	before := publishedCount(mc)
	for _, after := range pageStarts {
		if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, after); err != nil {
			t.Fatal(err)
		}
	}
	if n := publishedCount(mc) - before; n != maxEmergencyReplaysPerWindow*32 {
		t.Fatalf("published %d in one window, want %d", n, maxEmergencyReplaysPerWindow*32)
	}

	// After the window the budget is available again.
	svc.emergencyReplayMu.Lock()
	for _, st := range svc.emergencyReplays {
		for i := range st.passes {
			st.passes[i].at = st.passes[i].at.Add(-emergencyReplayCooldown)
		}
	}
	svc.emergencyReplayMu.Unlock()
	before = publishedCount(mc)
	if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 0); err != nil {
		t.Fatal(err)
	}
	if n := publishedCount(mc) - before; n != 32 {
		t.Fatalf("replay after the window published %d, want 32", n)
	}
}

// A failed pass is not recorded, so the next heartbeat retries it, and the
// replayed page still converges a lagging device in predecessor order.
func TestEmergencyCatchupRetriesFailedPassAndConverges(t *testing.T) {
	svc, mc, _ := newTestService()
	ctx := context.Background()
	for _, c := range []EmergencyCommand{EmergencyEnterLockdown, EmergencyForceSync, EmergencyReleaseLockdown, EmergencyBlockAll} {
		if err := svc.DistributeEmergency(ctx, 1, 2, c); err != nil {
			t.Fatal(err)
		}
		if err := svc.DistributeEmergency(ctx, 1, 3, EmergencyForceSync); err != nil {
			t.Fatal(err)
		}
	}
	mc.mu.Lock()
	mc.published = nil
	mc.pubErr = errTestPublish
	mc.mu.Unlock()
	if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 0); err == nil {
		t.Fatal("expected publish failure")
	}
	mc.mu.Lock()
	mc.pubErr = nil
	mc.mu.Unlock()
	if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 0); err != nil {
		t.Fatal(err)
	}
	mc.mu.Lock()
	msgs := append([]mockMsg(nil), mc.published...)
	mc.mu.Unlock()
	dev := &replayDevice{key: []byte(strings.Repeat("\xab", 32))}
	for _, m := range msgs {
		if !dev.apply(m.Payload) {
			t.Fatalf("replayed command rejected by the device")
		}
	}
	if len(msgs) != 4 || !dev.lockdown {
		t.Fatalf("device did not converge: msgs=%d lockdown=%v", len(msgs), dev.lockdown)
	}
}
