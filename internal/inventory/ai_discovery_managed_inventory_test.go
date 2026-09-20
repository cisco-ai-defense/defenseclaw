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
)

func managedInventoryReport() AIDiscoveryReport {
	return AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-managed"},
		Signals: []AISignal{
			{SignalID: "a", Category: SignalPackageDependency, State: AIStateNew},
			{SignalID: "b", Category: SignalPackageDependency, State: AIStateSeen},
			{SignalID: "c", Category: SignalPackageDependency, State: AIStateGone},
		},
	}
}

// TestManagedInventoryEmitHookTracksLiveModeTransitions pins the reload
// boundary without changing AI-discovery options: installing the callback on
// unmanaged->managed enables every later cadence, and clearing it on
// managed->unmanaged disables the cadence immediately.
func TestManagedInventoryEmitHookTracksLiveModeTransitions(t *testing.T) {
	var calls int
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}

	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if calls != 0 {
		t.Fatalf("unmanaged cadence calls=%d want=0", calls)
	}

	service.SetManagedInventoryEmitHook(func(context.Context) { calls++ })
	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if calls != 2 {
		t.Fatalf("managed cadences after live install=%d want=2", calls)
	}

	service.SetManagedInventoryEmitHook(nil)
	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if calls != 2 {
		t.Fatalf("unmanaged cadence after live clear=%d want=2", calls)
	}
}

// TestFanoutReport_ManagedSkipsNonFullTick pins the AI-Defense publish
// cadence: in managed_enterprise the fanout — both the canonical v8
// EmitReport (which carries the endpoint inventory to AI Defense) and
// the connector/MCP inventory hook — runs on the FULL-scan cadence
// only (ScanIntervalMin). The intra-cycle process-only tick
// (ProcessIntervalSec) is a local refresh and must not re-publish.
// Prior to this contract every process tick re-shipped the full
// endpoint inventory, flooding the AID event-ingest endpoint at
// ProcessIntervalSec cadence instead of ScanIntervalMin cadence.
func TestFanoutReport_ManagedSkipsNonFullTick(t *testing.T) {
	var hookCalls int
	capture := &captureAIDiscoveryV8{}
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: true}}
	service.BindObservabilityV8(capture)
	service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })

	service.fanoutReport(t.Context(), managedInventoryReport(), false)

	if hookCalls != 0 {
		t.Fatalf("non-full tick in managed_enterprise must not fire the connector/MCP inventory hook, got %d calls", hookCalls)
	}
	if len(capture.reports) != 0 {
		t.Fatalf("non-full tick in managed_enterprise must not publish an AI Defense report, got %d", len(capture.reports))
	}

	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if hookCalls != 1 {
		t.Fatalf("full tick in managed_enterprise must fire the hook exactly once, got %d", hookCalls)
	}
	if len(capture.reports) != 1 {
		t.Fatalf("full tick in managed_enterprise must publish one report, got %d", len(capture.reports))
	}
}

// TestFanoutReport_NonManagedIgnoresFullFlag pins that non-managed
// mode (live: no managedInventoryEmit hook installed) publishes on
// every tick regardless of full. The cadence gate must key on the
// live hook presence — not on any construction-time hint — so a
// service without a managed callback keeps feeding local v8 sinks on
// the intra-cycle process tick.
func TestFanoutReport_NonManagedIgnoresFullFlag(t *testing.T) {
	for _, full := range []bool{true, false} {
		full := full
		t.Run(map[bool]string{true: "full", false: "process"}[full], func(t *testing.T) {
			capture := &captureAIDiscoveryV8{}
			service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}
			service.BindObservabilityV8(capture)
			// No managed hook installed => live unmanaged. Both tick kinds
			// must emit the v8 report to local sinks.
			service.fanoutReport(t.Context(), managedInventoryReport(), full)
			if len(capture.reports) != 1 {
				t.Fatalf("non-managed (no hook) must emit v8 report for full=%v, got %d", full, len(capture.reports))
			}
		})
	}
}

// TestFanoutReport_LiveTransitionsGateNonFullTick pins that the
// fanoutReport cadence gate follows the live managed-mode signal
// (hook presence), not the construction-time opts.ManagedEnterprise
// hint. On unmanaged->managed the process tick begins to skip
// immediately after SetManagedInventoryEmitHook is called; on
// managed->unmanaged the process tick resumes emitting as soon as
// the hook is cleared. Guards against drift when a config reload
// swaps the hook without rebuilding the discovery service.
func TestFanoutReport_LiveTransitionsGateNonFullTick(t *testing.T) {
	t.Run("unmanaged_to_managed_live_install_skips_non_full_tick", func(t *testing.T) {
		capture := &captureAIDiscoveryV8{}
		var hookCalls int
		// Construction-time opts flag is intentionally the OPPOSITE of
		// the live-managed target below, to prove the gate does not key
		// on it.
		service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}
		service.BindObservabilityV8(capture)

		// Baseline: no hook (live unmanaged). Process tick emits.
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 1 {
			t.Fatalf("baseline live-unmanaged process tick must emit v8 report, got %d", len(capture.reports))
		}

		// Live install: managed callback wired without a service
		// rebuild. Subsequent process ticks must skip both v8 emission
		// and the callback fire.
		service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 1 {
			t.Fatalf("after live managed install, process tick must skip v8 emission (still %d reports); got %d", 1, len(capture.reports))
		}
		if hookCalls != 0 {
			t.Fatalf("after live managed install, process tick must skip hook fire, got %d calls", hookCalls)
		}

		// Full-scan tick after live install must both emit and fire.
		service.fanoutReport(t.Context(), managedInventoryReport(), true)
		if len(capture.reports) != 2 {
			t.Fatalf("full tick after live managed install must emit v8 report, got %d", len(capture.reports))
		}
		if hookCalls != 1 {
			t.Fatalf("full tick after live managed install must fire hook once, got %d", hookCalls)
		}
	})

	t.Run("managed_to_unmanaged_live_clear_resumes_non_full_tick", func(t *testing.T) {
		capture := &captureAIDiscoveryV8{}
		var hookCalls int
		// Construction-time opts flag is intentionally the OPPOSITE of
		// the live-unmanaged target below.
		service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: true}}
		service.BindObservabilityV8(capture)
		service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })

		// Baseline: hook installed (live managed). Process tick skips.
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 0 || hookCalls != 0 {
			t.Fatalf("baseline live-managed process tick must skip: reports=%d hookCalls=%d", len(capture.reports), hookCalls)
		}

		// Live clear: hook removed without a service rebuild. Process
		// ticks must resume emitting the v8 report; no hook to fire.
		service.SetManagedInventoryEmitHook(nil)
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 1 {
			t.Fatalf("after live managed clear, process tick must resume v8 emission, got %d", len(capture.reports))
		}
		if hookCalls != 0 {
			t.Fatalf("after live managed clear, hook must not fire, got %d calls", hookCalls)
		}
	})
}
