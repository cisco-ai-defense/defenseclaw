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
	"path/filepath"
	"testing"
)

// The skill inventory hook of a gateway outside managed_enterprise fires on
// full scans only, and leaves the managed cadence rules off.
func TestSkillInventoryHookFiresOnFullScansOnly(t *testing.T) {
	home := t.TempDir()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	skills, managed := 0, 0
	svc.SetSkillInventoryEmitHook(func(context.Context) { skills++ })
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "scan-1", Result: "ok"}}

	svc.fanoutReport(t.Context(), report, false)
	if skills != 0 {
		t.Fatalf("a process-only tick fired the skill hook %d times", skills)
	}
	svc.fanoutReport(t.Context(), report, true)
	if skills != 1 {
		t.Fatalf("a full scan fired the skill hook %d times, want 1", skills)
	}
	if svc.managedInventoryEmitActive() {
		t.Fatal("the skill hook turned on the managed cadence rules")
	}

	// Where the managed hook is installed, it alone runs.
	svc.SetManagedInventoryEmitHook(func(context.Context) { managed++ })
	svc.fanoutReport(t.Context(), report, true)
	if skills != 1 || managed != 1 {
		t.Fatalf("skills=%d managed=%d, want 1 and 1", skills, managed)
	}
	svc.SetSkillInventoryEmitHook(nil)
	svc.SetManagedInventoryEmitHook(nil)
	svc.fanoutReport(t.Context(), report, true)
	if skills != 1 || managed != 1 {
		t.Fatalf("cleared hooks fired: skills=%d managed=%d", skills, managed)
	}
}
