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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

func TestFleetMetricsFromManagerAndCache(t *testing.T) {
	GlobalMetrics.Reset()
	t.Cleanup(GlobalMetrics.Reset)

	mgr := manager.New(nil)
	cache := verdict.NewCache(2, func(uint16, uint16, [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})
	WireMetrics(mgr, cache, nil)
	if _, err := mgr.RegisterDevice(1, 2, 42, "rpi4", "1.0", 1, 1); err != nil {
		t.Fatal(err)
	}
	if !mgr.ProcessHeartbeat(1, 2, 42, &manager.Heartbeat{DeviceID: 42, PolicyVersion: 1, BootCounter: 1, UptimeSec: 1}) {
		t.Fatal("first heartbeat rejected")
	}
	if !mgr.ProcessHeartbeat(1, 2, 42, &manager.Heartbeat{DeviceID: 42, PolicyVersion: 1, BootCounter: 1, UptimeSec: 2, Flags: 0x08}) {
		t.Fatal("canary rollback heartbeat rejected")
	}
	hash := [32]byte{1}
	cache.Evaluate(1, 2, hash) // miss and store
	cache.Evaluate(1, 2, hash) // hit

	response := httptest.NewRecorder()
	MetricsHandler(response, httptest.NewRequest("GET", "/api/v1/fleet/metrics", nil))
	if got := response.Code; got != 200 {
		t.Fatalf("metrics HTTP status = %d", got)
	}
	for _, sample := range []string{
		`defenseclaw_fleet_devices_total{status="online"} 1`,
		"defenseclaw_fleet_heartbeats_received_total 2",
		"defenseclaw_fleet_verdict_cache_misses_total 1",
		"defenseclaw_fleet_verdict_cache_hits_total 1",
		"defenseclaw_fleet_verdict_cache_size 1",
		"defenseclaw_fleet_alerts_total 1",
		"defenseclaw_fleet_policy_rollback_total 1",
		"defenseclaw_fleet_ota_rollbacks_total 1",
	} {
		if !strings.Contains(response.Body.String(), sample+"\n") {
			t.Errorf("metrics response missing %q", sample)
		}
	}
	for _, orphaned := range []string{
		"defenseclaw_fleet_audit_chain_breaks_total",
		"defenseclaw_fleet_speculative_blocks_total",
		"defenseclaw_fleet_emergency_seq_gaps_total",
	} {
		if strings.Contains(response.Body.String(), orphaned) {
			t.Errorf("metrics response still exposes orphaned metric %q", orphaned)
		}
	}
}
