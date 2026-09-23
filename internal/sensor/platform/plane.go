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

// Package platform is the operating-system seam for the AI Discovery runtime
// planes.
//
// Three things vary between operating systems and nothing else may:
//
//   - Acquisition -- how a plane is observed. ps/lsof and Endpoint Security on
//     macOS, /proc and cn_proc/fanotify on Linux, Toolhelp32 and ETW on
//     Windows. Every backend produces the same neutral records, so everything
//     downstream of acquisition is platform-blind and stays that way.
//   - Locations -- where evidence and per-user state live.
//   - Indicators -- what counts as suspicious. This is the layer people
//     forget. /Library/LaunchAgents is how a Mac gains persistence; a systemd
//     unit or a crontab is how Linux does it. A detector that ports its
//     acquisition but not its indicators reports a clean host because it is
//     looking in the wrong place, which is worse than refusing to run.
//
// # Capability is declared, not assumed
//
// A platform states what it cannot see, and that statement is telemetry rather
// than a comment. The one thing that must not happen is for blindness to read
// as calm: a plane a platform cannot observe is reported unavailable and
// lowers observation coverage. It never silently scores zero.
//
// That is why Capability is a value rather than prose in a doc comment: a
// reviewer can check that an unimplemented plane is declared, and a test can
// fail the build if a platform claims a plane it has no source for.
package platform

import "fmt"

// Plane identifies one of the three detection planes.
type Plane string

const (
	// PlaneA is the inference heartbeat: sustained compute in a scriptable
	// runtime, plus resident memory large enough to hold model weights.
	PlaneA Plane = "a"
	// PlaneB is shadow egress: per-process socket attribution to a provider,
	// and the DNS answers that name the peer.
	PlaneB Plane = "b"
	// PlaneC is agent actions: kernel process, file, and identity events,
	// gated on an AI agent appearing in the process lineage.
	PlaneC Plane = "c"
)

// Planes is every plane in a stable order. Reports iterate this rather than a
// map so a capability summary reads the same on every host.
var Planes = [...]Plane{PlaneA, PlaneB, PlaneC}

// planeNames keeps a plane described identically everywhere it is mentioned.
var planeNames = map[Plane]string{
	PlaneA: "inference heartbeat",
	PlaneB: "shadow egress",
	PlaneC: "agent actions",
}

// Name is the human description used in reports and capability summaries.
func (p Plane) Name() string { return planeNames[p] }

// Valid reports whether p is one of the three known planes.
func (p Plane) Valid() bool {
	_, ok := planeNames[p]
	return ok
}

// Capability says whether a plane can be observed on this host, and what it
// costs to observe it.
//
// Available is the load-bearing field. Reason exists because "no" without a
// reason sends an operator to the source.
//
// RequiresRoot and RequiresGrant are separate because they fail differently.
// Root is something an operator can decide in a script. A grant -- Full Disk
// Access on macOS, an audit policy on Windows, a kernel facility on Linux --
// is a human at a settings pane or a reboot. Telling someone to "run as root"
// when the real answer is a grant wastes an afternoon.
type Capability struct {
	Plane         Plane
	Available     bool
	Mechanism     string
	Reason        string
	RequiresRoot  bool
	RequiresGrant bool
}

// NewCapability validates the invariant that makes a capability summary worth
// reading: an available plane has to say how, and a blind one has to say why.
// Neither is optional.
func NewCapability(c Capability) (Capability, error) {
	if !c.Plane.Valid() {
		return Capability{}, fmt.Errorf("sensor/platform: unknown plane %q", string(c.Plane))
	}
	if c.Available && c.Mechanism == "" {
		return Capability{}, fmt.Errorf(
			"sensor/platform: plane %s claims to be available without naming a mechanism", c.Plane)
	}
	if !c.Available && c.Reason == "" {
		return Capability{}, fmt.Errorf(
			"sensor/platform: plane %s claims to be unavailable without giving a reason", c.Plane)
	}
	return c, nil
}

// Summary is the one-line operator rendering of a capability.
func (c Capability) Summary() string {
	if !c.Available {
		return fmt.Sprintf("%s unavailable: %s", c.Plane.Name(), c.Reason)
	}
	note := ""
	switch {
	case c.RequiresRoot && c.RequiresGrant:
		note = " (root + grant)"
	case c.RequiresRoot:
		note = " (root)"
	case c.RequiresGrant:
		note = " (grant)"
	}
	return fmt.Sprintf("%s via %s%s", c.Plane.Name(), c.Mechanism, note)
}
