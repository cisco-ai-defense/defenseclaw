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
// mode publishes on every tick (full or process) — its state filter
// downstream already keeps per-tick emission delta-only. The non-full
// gate must not accidentally suppress non-managed emitters.
func TestFanoutReport_NonManagedIgnoresFullFlag(t *testing.T) {
	var hookCalls int
	capture := &captureAIDiscoveryV8{}
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}
	service.BindObservabilityV8(capture)
	service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })

	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	service.fanoutReport(t.Context(), managedInventoryReport(), false)

	if hookCalls != 2 {
		t.Fatalf("non-managed must fire the installed hook on every tick regardless of full, got %d calls", hookCalls)
	}
	if len(capture.reports) != 2 {
		t.Fatalf("non-managed must publish on every tick regardless of full, got %d reports", len(capture.reports))
	}
}
