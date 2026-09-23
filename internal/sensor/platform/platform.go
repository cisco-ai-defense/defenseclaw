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
	"fmt"
	"runtime"
	"sort"
)

// Platform is one operating system's answers to the questions that vary.
//
// Nothing else in internal/sensor may branch on the operating system. If it
// does, the branch belongs behind this interface instead.
type Platform interface {
	// OSType matches OpenTelemetry's os.type vocabulary -- "darwin", "linux",
	// "windows" -- because that is where the value is ultimately used. It is
	// not runtime.GOOS-with-hope: GOOS says "windows" already, but the mapping
	// is stated here so a backend cannot drift from the wire vocabulary.
	OSType() string

	// Name is what a human calls it.
	Name() string

	// Capabilities reports one entry per plane, always all three. A plane this
	// platform cannot observe appears with Available false and a Reason, never
	// missing.
	Capabilities() map[Plane]Capability

	// WideCoverage reports whether this run can see past the user it runs as
	// -- the platform-neutral form of "can this process read other users'
	// processes, sockets, and home directories".
	//
	// Callers ask this instead of comparing euid to zero, because the question
	// survives the port and the comparison does not. macOS and Linux answer it
	// with exactly euid == 0; Windows has no uid, so its answer is an elevated
	// token. Asking for root on Windows is false even when the run is
	// Administrator, and false in the expensive direction: it would report the
	// widest coverage a run has as the narrowest.
	WideCoverage() bool
}

// PlaneCapability returns the capability for one plane, or a zero value and
// false when the platform did not declare it. A platform that omits a plane is
// a bug the caller should surface rather than read as "unavailable" --
// omission and declared blindness are different facts.
func PlaneCapability(p Platform, plane Plane) (Capability, bool) {
	capability, ok := p.Capabilities()[plane]
	return capability, ok
}

// AvailablePlanes lists the planes this platform can observe, in plane order.
func AvailablePlanes(p Platform) []Plane {
	capabilities := p.Capabilities()
	available := make([]Plane, 0, len(Planes))
	for _, plane := range Planes {
		if capabilities[plane].Available {
			available = append(available, plane)
		}
	}
	return available
}

// CapabilityLines renders one summary line per plane, in plane order. This is
// what `defenseclaw agent discovery runtime selftest` prints and what the TUI
// plane-health strip reads.
func CapabilityLines(p Platform) []string {
	capabilities := p.Capabilities()
	lines := make([]string, 0, len(Planes))
	for _, plane := range Planes {
		capability, ok := capabilities[plane]
		if !ok {
			lines = append(lines, fmt.Sprintf(
				"%s undeclared: %s did not report this plane", plane.Name(), p.Name()))
			continue
		}
		lines = append(lines, capability.Summary())
	}
	return lines
}

// ValidateCapabilities checks the contract every backend owes: exactly one
// entry per plane, each internally consistent. It exists so a test can fail
// the build when a platform claims a plane it has no source for.
func ValidateCapabilities(p Platform) error {
	capabilities := p.Capabilities()
	if len(capabilities) != len(Planes) {
		declared := make([]string, 0, len(capabilities))
		for plane := range capabilities {
			declared = append(declared, string(plane))
		}
		sort.Strings(declared)
		return fmt.Errorf("sensor/platform: %s declared %d planes %v, want all %d",
			p.Name(), len(capabilities), declared, len(Planes))
	}
	for _, plane := range Planes {
		capability, ok := capabilities[plane]
		if !ok {
			return fmt.Errorf("sensor/platform: %s did not declare plane %s", p.Name(), plane)
		}
		if capability.Plane != plane {
			return fmt.Errorf("sensor/platform: %s keyed plane %s under %s",
				p.Name(), capability.Plane, plane)
		}
		if _, err := NewCapability(capability); err != nil {
			return err
		}
	}
	return nil
}

// ErrUnsupported is returned for an operating system with no backend.
//
// Deliberately an error rather than a degraded default. A detector that starts
// on an unknown platform and reports nothing is indistinguishable from one
// watching a quiet host, and the whole point of the capability model is to
// make that confusion impossible.
type ErrUnsupported struct{ GOOS string }

func (e *ErrUnsupported) Error() string {
	return fmt.Sprintf(
		"sensor/platform: no runtime-plane backend for %s; supported: darwin, linux, windows", e.GOOS)
}

// Current returns the backend for the host this process is running on.
func Current() (Platform, error) {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return current(), nil
	default:
		return nil, &ErrUnsupported{GOOS: runtime.GOOS}
	}
}
