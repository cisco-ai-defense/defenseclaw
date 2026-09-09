// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package sensor

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
)

// TestPartialPlaneCoverageIsDegraded pins the distinction a real Linux host
// surfaced: a plane delivering process events but not file events is running,
// and is also missing a whole tactic class. A snapshot that called that
// complete would let an operator read reduced coverage as a clean host.
func TestPartialPlaneCoverageIsDegraded(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		health      PlaneHealth
		wantReason  string
		wantNoEntry bool
	}{
		{
			name: "fully covered plane adds nothing",
			health: PlaneHealth{
				Plane: platform.PlaneA, Available: true, Running: true, Mechanism: "/proc",
			},
			wantNoEntry: true,
		},
		{
			name: "running with a limitation is partial",
			health: PlaneHealth{
				Plane: platform.PlaneC, Available: true, Running: true,
				Mechanism: "cn_proc only",
				Reason:    "file events need fanotify, which needs CAP_SYS_ADMIN",
			},
			wantReason: "partially covered",
		},
		{
			name: "available but stopped",
			health: PlaneHealth{
				Plane: platform.PlaneB, Available: true, Running: false,
				Reason: "connection table unreadable",
			},
			wantReason: "available but not running",
		},
		{
			name: "unavailable",
			health: PlaneHealth{
				Plane: platform.PlaneC, Available: false, Reason: "eslogger not found",
			},
			wantReason: "unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := Snapshot{Planes: []PlaneHealth{test.health}}
			reasons := degradedReasonsFor(snapshot)
			if test.wantNoEntry {
				if len(reasons) != 0 {
					t.Fatalf("a fully covered plane produced %v", reasons)
				}
				return
			}
			if len(reasons) != 1 {
				t.Fatalf("got %d reasons, want 1: %v", len(reasons), reasons)
			}
			if !strings.Contains(reasons[0], test.wantReason) {
				t.Fatalf("reason = %q, want it to say %q", reasons[0], test.wantReason)
			}
			if !strings.Contains(reasons[0], test.health.Plane.Name()) {
				t.Errorf("reason = %q, want it to name the plane", reasons[0])
			}
		})
	}
}

// TestDegradationEntryNeverHasAnEmptyReason pins that a degradation the
// operator cannot act on is never emitted.
func TestDegradationEntryNeverHasAnEmptyReason(t *testing.T) {
	t.Parallel()
	snapshot := Snapshot{Planes: []PlaneHealth{
		{Plane: platform.PlaneC, Available: true, Running: false},
	}}
	reasons := degradedReasonsFor(snapshot)
	if len(reasons) != 1 {
		t.Fatalf("got %v", reasons)
	}
	if strings.HasSuffix(strings.TrimSpace(reasons[0]), ":") {
		t.Fatalf("reason = %q, want a fallback rather than a dangling colon", reasons[0])
	}
	if !strings.Contains(reasons[0], "not started") {
		t.Fatalf("reason = %q, want the documented fallback", reasons[0])
	}
}
