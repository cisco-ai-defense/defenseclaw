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

	service.fanoutReport(t.Context(), managedInventoryReport())
	if calls != 0 {
		t.Fatalf("unmanaged cadence calls=%d want=0", calls)
	}

	service.SetManagedInventoryEmitHook(func(context.Context) { calls++ })
	service.fanoutReport(t.Context(), managedInventoryReport())
	service.fanoutReport(t.Context(), managedInventoryReport())
	if calls != 2 {
		t.Fatalf("managed cadences after live install=%d want=2", calls)
	}

	service.SetManagedInventoryEmitHook(nil)
	service.fanoutReport(t.Context(), managedInventoryReport())
	if calls != 2 {
		t.Fatalf("unmanaged cadence after live clear=%d want=2", calls)
	}
}
