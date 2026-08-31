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

package inventory

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// managedInventoryReport builds a mixed-state report: one new, one
// steady-state seen, one gone. Managed mode must ship the full active
// inventory (new + seen), non-managed only lifecycle deltas.
func managedInventoryReport() AIDiscoveryReport {
	return AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-managed"},
		Signals: []AISignal{
			evidenceSignal("a", "pypi", "openai", "1.40.0", "ws-1", AIStateNew, "process"),
			evidenceSignal("b", "pypi", "anthropic", "0.30.0", "ws-1", AIStateSeen, "package_manifest"),
			evidenceSignal("c", "npm", "openai", "1.0.0", "ws-2", AIStateGone, "package_manifest"),
		},
	}
}

// TestEmitGatewayEvents_ManagedEmitsFullInventory pins the managed
// full-snapshot contract: every active signal (new + seen) plus the
// gone delta is emitted as its own ai_discovery event, so AI Defense
// receives the complete endpoint inventory rather than deltas only.
func TestEmitGatewayEvents_ManagedEmitsFullInventory(t *testing.T) {
	t.Parallel()
	captured := newCapturingWriter(t)
	svc := &ContinuousDiscoveryService{
		events: captured.writer,
		opts:   AIDiscoveryOptions{ManagedEnterprise: true},
	}
	svc.emitGatewayEvents(context.Background(), managedInventoryReport(), componentRollupSnapshot{}, true)

	events := captured.events()
	states := map[string]int{}
	for _, ev := range events {
		if ev.EventType != gatewaylog.EventAIDiscovery || ev.AIDiscovery == nil {
			t.Fatalf("unexpected event: %+v", ev)
		}
		states[ev.AIDiscovery.State]++
	}
	if len(events) != 3 {
		t.Fatalf("managed should emit all 3 signals (new+seen+gone), got %d: %+v", len(events), states)
	}
	if states[AIStateSeen] != 1 {
		t.Fatalf("managed must include steady-state 'seen' signal; got states=%+v", states)
	}
	if states[AIStateNew] != 1 || states[AIStateGone] != 1 {
		t.Fatalf("managed must include new + gone deltas; got states=%+v", states)
	}
}

// TestEmitGatewayEvents_NonManagedDeltaOnly pins the unchanged
// non-managed behavior: steady-state 'seen' signals are skipped so
// user-owned SIEMs are not flooded on every full scan.
func TestEmitGatewayEvents_NonManagedDeltaOnly(t *testing.T) {
	t.Parallel()
	captured := newCapturingWriter(t)
	svc := &ContinuousDiscoveryService{
		events: captured.writer,
		opts:   AIDiscoveryOptions{ManagedEnterprise: false},
	}
	svc.emitGatewayEvents(context.Background(), managedInventoryReport(), componentRollupSnapshot{}, true)

	events := captured.events()
	for _, ev := range events {
		if ev.AIDiscovery != nil && ev.AIDiscovery.State == AIStateSeen {
			t.Fatalf("non-managed must skip 'seen' signals, but emitted one: %+v", ev.AIDiscovery)
		}
	}
	// Only the new + gone deltas remain.
	if len(events) != 2 {
		t.Fatalf("non-managed should emit only the 2 deltas (new+gone), got %d", len(events))
	}
}

// TestManagedInventoryEmitHook_FiresOnScan pins that the connector/MCP
// endpoint-inventory hook is invoked once per scan fanout in managed
// mode, and never outside it.
func TestManagedInventoryEmitHook_FiresOnScan(t *testing.T) {
	t.Parallel()
	t.Run("managed fires hook", func(t *testing.T) {
		captured := newCapturingWriter(t)
		var calls int
		svc := &ContinuousDiscoveryService{
			events: captured.writer,
			opts:   AIDiscoveryOptions{ManagedEnterprise: true},
		}
		svc.SetManagedInventoryEmitHook(func(context.Context) { calls++ })
		svc.emitGatewayEvents(context.Background(), managedInventoryReport(), componentRollupSnapshot{}, true)
		if calls != 1 {
			t.Fatalf("managed inventory hook should fire once per scan, got %d", calls)
		}
	})
	t.Run("non-managed never fires hook", func(t *testing.T) {
		captured := newCapturingWriter(t)
		var calls int
		svc := &ContinuousDiscoveryService{
			events: captured.writer,
			opts:   AIDiscoveryOptions{ManagedEnterprise: false},
		}
		svc.SetManagedInventoryEmitHook(func(context.Context) { calls++ })
		svc.emitGatewayEvents(context.Background(), managedInventoryReport(), componentRollupSnapshot{}, true)
		if calls != 0 {
			t.Fatalf("non-managed inventory hook must not fire, got %d", calls)
		}
	})
}

// TestEmitGatewayEvents_ManagedSkipsNonFullTick pins the AI-Defense
// publish cadence: managed_enterprise ships the endpoint inventory on
// the full-scan cadence only (ScanIntervalMin), NOT on the intra-cycle
// process-only tick (ProcessIntervalSec). Prior to this contract every
// process tick re-shipped the full carried-forward inventory + the
// connector/MCP inventory hook, flooding the AID event-ingest endpoint
// at ProcessIntervalSec cadence (default 60 s) instead of the intended
// ScanIntervalMin cadence (default 5 min).
func TestEmitGatewayEvents_ManagedSkipsNonFullTick(t *testing.T) {
	t.Parallel()
	captured := newCapturingWriter(t)
	var hookCalls int
	svc := &ContinuousDiscoveryService{
		events: captured.writer,
		opts:   AIDiscoveryOptions{ManagedEnterprise: true},
	}
	svc.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })

	svc.emitGatewayEvents(context.Background(), managedInventoryReport(), componentRollupSnapshot{}, false)

	if events := captured.events(); len(events) != 0 {
		t.Fatalf("non-full tick in managed_enterprise must not ship ai_discovery events, got %d: %+v", len(events), events)
	}
	if hookCalls != 0 {
		t.Fatalf("non-full tick in managed_enterprise must not fire the connector/MCP inventory hook, got %d calls", hookCalls)
	}
}

// TestEmitGatewayEvents_NonManagedIgnoresFullFlag pins that
// non-managed mode is unaffected by the full flag — it always applies
// the delta-only state filter regardless of whether the tick is a
// full scan or the process-only tick. Non-managed operators rely on
// this to receive new/changed/gone deltas for freshly-launched
// processes on the 60 s cadence without a full inventory replay.
func TestEmitGatewayEvents_NonManagedIgnoresFullFlag(t *testing.T) {
	t.Parallel()
	for _, full := range []bool{true, false} {
		full := full
		t.Run(map[bool]string{true: "full", false: "process"}[full], func(t *testing.T) {
			t.Parallel()
			captured := newCapturingWriter(t)
			svc := &ContinuousDiscoveryService{
				events: captured.writer,
				opts:   AIDiscoveryOptions{ManagedEnterprise: false},
			}
			svc.emitGatewayEvents(context.Background(), managedInventoryReport(), componentRollupSnapshot{}, full)

			events := captured.events()
			if len(events) != 2 {
				t.Fatalf("non-managed should always emit the 2 lifecycle deltas (new+gone) regardless of full=%v, got %d", full, len(events))
			}
			for _, ev := range events {
				if ev.AIDiscovery != nil && ev.AIDiscovery.State == AIStateSeen {
					t.Fatalf("non-managed must skip 'seen' signals for full=%v: %+v", full, ev.AIDiscovery)
				}
			}
		})
	}
}
