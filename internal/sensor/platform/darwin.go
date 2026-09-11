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

//go:build darwin

package platform

import (
	"os"
	"os/exec"
)

// eslogger is the Endpoint Security client that ships with macOS 13 and later.
// It is the only Plane C source that does not require a signed system
// extension entitlement, which is why it is the one this sensor uses.
const esloggerPath = "/usr/bin/eslogger"

type darwinPlatform struct{}

func current() Platform { return darwinPlatform{} }

func (darwinPlatform) OSType() string { return "darwin" }
func (darwinPlatform) Name() string   { return "macOS" }

// WideCoverage is euid == 0 on macOS.
//
// The asymmetry this gates is real and large. An unprivileged ps returns RSS
// and CPU time for the entire process table, while an unprivileged lsof
// returns established sockets only for the invoking user. So without root the
// sensor watches the whole machine compute and only its own share of it talk,
// and a Plane A/B finding needs both halves for the same pid.
func (darwinPlatform) WideCoverage() bool { return os.Geteuid() == 0 }

func (p darwinPlatform) Capabilities() map[Plane]Capability {
	return map[Plane]Capability{
		PlaneA: {
			Plane: PlaneA, Available: true, Mechanism: "ps(1)",
		},
		PlaneB: {
			Plane: PlaneB, Available: true, Mechanism: "lsof(8) and BPF DNS capture",
			// Root is what makes this plane machine-wide, not what makes it
			// work at all, so RequiresRoot stays false: an unprivileged run
			// still attributes its own user's sockets and says so.
			RequiresRoot: false,
		},
		PlaneC: p.planeC(),
	}
}

// planeC probes rather than assumes, because it is the one plane that can be
// present or absent on the same host depending on a grant.
func (darwinPlatform) planeC() Capability {
	if _, err := os.Stat(esloggerPath); err != nil {
		if _, lookErr := exec.LookPath("eslogger"); lookErr != nil {
			return Capability{
				Plane:     PlaneC,
				Available: false,
				Reason: "eslogger not found; needs macOS 13+ and Full Disk Access granted " +
					"to the process that launches the gateway",
				RequiresRoot:  true,
				RequiresGrant: true,
			}
		}
	}
	return Capability{
		Plane:         PlaneC,
		Available:     true,
		Mechanism:     "Endpoint Security (eslogger)",
		RequiresRoot:  true,
		RequiresGrant: true,
	}
}
