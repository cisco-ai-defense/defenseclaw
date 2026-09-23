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

package platform

import (
	"runtime"
	"strings"
	"testing"
)

// TestCurrentPlatformDeclaresEveryPlane is the build-failing check the
// capability model exists for: a backend may not claim a plane it has no
// source for, and may not silently omit one either.
func TestCurrentPlatformDeclaresEveryPlane(t *testing.T) {
	t.Parallel()
	host, err := Current()
	if err != nil {
		t.Fatalf("Current(): %v", err)
	}
	if err := ValidateCapabilities(host); err != nil {
		t.Fatal(err)
	}
	if host.OSType() != runtime.GOOS {
		t.Errorf("OSType() = %q, want %q", host.OSType(), runtime.GOOS)
	}
	if strings.TrimSpace(host.Name()) == "" {
		t.Error("Name() is empty")
	}
}

// TestBlindPlaneIsNeverSilent is the degradation contract. Every plane the
// host cannot observe must carry a reason an operator can act on, because a
// detector reporting clean because it was never able to look is
// indistinguishable, on a dashboard, from a host that is genuinely clean.
func TestBlindPlaneIsNeverSilent(t *testing.T) {
	t.Parallel()
	host, err := Current()
	if err != nil {
		t.Fatalf("Current(): %v", err)
	}
	for plane, capability := range host.Capabilities() {
		if capability.Available {
			continue
		}
		if strings.TrimSpace(capability.Reason) == "" {
			t.Errorf("plane %s is unavailable with no reason", plane)
		}
		summary := capability.Summary()
		if !strings.Contains(summary, "unavailable") || !strings.Contains(summary, capability.Reason) {
			t.Errorf("plane %s summary hides the reason: %q", plane, summary)
		}
	}
}

// TestCapabilityRejectsUninformativeDeclarations pins both halves of the
// invariant that makes a summary worth reading.
func TestCapabilityRejectsUninformativeDeclarations(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		input Capability
		want  string
	}{
		{
			name:  "available without a mechanism",
			input: Capability{Plane: PlaneA, Available: true},
			want:  "without naming a mechanism",
		},
		{
			name:  "unavailable without a reason",
			input: Capability{Plane: PlaneB, Available: false},
			want:  "without giving a reason",
		},
		{
			name:  "unknown plane",
			input: Capability{Plane: "d", Available: true, Mechanism: "invented"},
			want:  "unknown plane",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewCapability(test.input); err == nil {
				t.Fatalf("NewCapability(%+v) accepted an uninformative declaration", test.input)
			} else if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

// TestCapabilityLinesCoverEveryPlaneInOrder pins the operator-facing rendering
// used by `agent discovery runtime selftest` and the TUI plane-health strip.
func TestCapabilityLinesCoverEveryPlaneInOrder(t *testing.T) {
	t.Parallel()
	host, err := Current()
	if err != nil {
		t.Fatalf("Current(): %v", err)
	}
	lines := CapabilityLines(host)
	if len(lines) != len(Planes) {
		t.Fatalf("CapabilityLines() = %d lines, want %d", len(lines), len(Planes))
	}
	for index, plane := range Planes {
		if !strings.HasPrefix(lines[index], plane.Name()) {
			t.Errorf("line %d = %q, want it to describe %s", index, lines[index], plane.Name())
		}
	}
}

// TestAvailablePlanesIsASubsetInPlaneOrder guards the ordering contract that
// keeps a capability summary reading the same on every host.
func TestAvailablePlanesIsASubsetInPlaneOrder(t *testing.T) {
	t.Parallel()
	host, err := Current()
	if err != nil {
		t.Fatalf("Current(): %v", err)
	}
	available := AvailablePlanes(host)
	capabilities := host.Capabilities()
	previous := -1
	for _, plane := range available {
		if !capabilities[plane].Available {
			t.Errorf("plane %s is listed available but declared unavailable", plane)
		}
		index := -1
		for i, candidate := range Planes {
			if candidate == plane {
				index = i
				break
			}
		}
		if index <= previous {
			t.Fatalf("available planes are out of plane order: %v", available)
		}
		previous = index
	}
}

// TestPlaneCapabilityDistinguishesOmissionFromBlindness pins that an
// undeclared plane is reported as a bug rather than read as "unavailable".
func TestPlaneCapabilityDistinguishesOmissionFromBlindness(t *testing.T) {
	t.Parallel()
	incomplete := stubPlatform{capabilities: map[Plane]Capability{
		PlaneA: {Plane: PlaneA, Available: true, Mechanism: "stub"},
	}}
	if _, ok := PlaneCapability(incomplete, PlaneC); ok {
		t.Fatal("PlaneCapability reported an undeclared plane as declared")
	}
	if err := ValidateCapabilities(incomplete); err == nil {
		t.Fatal("ValidateCapabilities accepted a platform missing two planes")
	}
	lines := CapabilityLines(incomplete)
	if !strings.Contains(lines[2], "undeclared") {
		t.Fatalf("undeclared plane rendered as %q, want it to say so", lines[2])
	}
}

type stubPlatform struct{ capabilities map[Plane]Capability }

func (stubPlatform) OSType() string                       { return "stub" }
func (stubPlatform) Name() string                         { return "stub" }
func (stubPlatform) WideCoverage() bool                   { return false }
func (s stubPlatform) Capabilities() map[Plane]Capability { return s.capabilities }
