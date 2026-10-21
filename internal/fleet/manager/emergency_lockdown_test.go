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

package manager

import (
	"sync"
	"testing"
)

// Heartbeat flag 0x40 (emergency lockdown active) is reported as
// emergency_lockdown and status "lockdown", without a tamper alert.
func TestEmergencyLockdownFlagMapsToDeviceState(t *testing.T) {
	var mu sync.Mutex
	var alerts []AlertType
	fm := New(func(a Alert) {
		mu.Lock()
		alerts = append(alerts, a.Type)
		mu.Unlock()
	})
	if _, err := fm.RegisterDevice(1, 2, 42, "sbc", "1", 1, 0); err != nil {
		t.Fatal(err)
	}
	id := ComposeID(1, 2, 42)
	hb := func(uptime uint32, flags uint8) {
		t.Helper()
		if !fm.ProcessHeartbeat(1, 2, 42, &Heartbeat{DeviceID: 42, BootCounter: 1, UptimeSec: uptime, Flags: flags}) {
			t.Fatal("heartbeat rejected")
		}
	}
	hb(10, HeartbeatFlagEmergencyLockdown)
	d, _ := fm.GetDevice(id)
	if !d.EmergencyLockdown || d.Status != StatusLockdown {
		t.Fatalf("emergency lockdown not reported: lockdown=%v status=%s", d.EmergencyLockdown, d.Status)
	}
	if h := fm.GetFleetHealth(); h.Lockdown != 1 {
		t.Fatalf("fleet health lockdown=%d", h.Lockdown)
	}
	// Lockdown outranks the degraded flags that accompany it offline.
	hb(11, HeartbeatFlagEmergencyLockdown|HeartbeatFlagOfflineMode|HeartbeatFlagPolicyStale)
	if d, _ = fm.GetDevice(id); d.Status != StatusLockdown {
		t.Fatalf("status=%s", d.Status)
	}
	hb(12, 0)
	if d, _ = fm.GetDevice(id); d.EmergencyLockdown || d.Status != StatusOnline {
		t.Fatalf("release not reported: lockdown=%v status=%s", d.EmergencyLockdown, d.Status)
	}
	// TAMPER_DETECT stays distinct from emergency lockdown.
	hb(13, HeartbeatFlagTamperDetect)
	if d, _ = fm.GetDevice(id); d.EmergencyLockdown || d.Status != StatusLockdown {
		t.Fatalf("tamper: lockdown=%v status=%s", d.EmergencyLockdown, d.Status)
	}
	mu.Lock()
	defer mu.Unlock()
	tamper := 0
	for _, a := range alerts {
		if a == AlertTamperDetect {
			tamper++
		}
	}
	if tamper != 1 {
		t.Fatalf("tamper alerts=%d, want 1 (only for 0x04)", tamper)
	}
}
