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

//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
)

type windowsPlatform struct{}

func current() Platform { return windowsPlatform{} }

func (windowsPlatform) OSType() string { return "windows" }
func (windowsPlatform) Name() string   { return "Windows" }

// WideCoverage is an elevated token on Windows, not a uid comparison.
//
// This is the reason WideCoverage exists on the seam instead of every caller
// reaching for a root check: euid == 0 is false on Windows even when the run
// is Administrator, and false in the expensive direction. It would send a
// machine-wide record to a per-user store and report the widest coverage a run
// has as the narrowest.
func (windowsPlatform) WideCoverage() bool {
	var sid *windows.SID
	// S-1-5-32-544, the built-in Administrators group.
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid,
	); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	// A nil token means "the calling thread's effective token", which is what
	// answers the elevation question for the running gateway service.
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

func (p windowsPlatform) Capabilities() map[Plane]Capability {
	return map[Plane]Capability{
		PlaneA: {
			Plane: PlaneA, Available: true,
			Mechanism: "Toolhelp32 snapshot, GetProcessTimes, GetProcessMemoryInfo",
		},
		PlaneB: {
			Plane: PlaneB, Available: true,
			Mechanism: "GetExtendedTcpTable and GetExtendedUdpTable",
			// Windows hands back the owning pid in every row, so unlike
			// macOS and Linux no privilege is needed to attribute a socket to
			// a pid at all. Per-process detail -- image path, owner -- can
			// still be refused for another user's or an elevated process, the
			// same asymmetry ps/lsof and /proc already have.
			RequiresRoot: false,
		},
		PlaneC: p.planeC(),
	}
}

// planeC reports the two Windows sources, which fail for two different reasons
// and are therefore reported as two different reasons.
//
// An ETW session needs an elevated token. The Security log additionally needs
// Advanced Audit Policy enabled, which is a policy grant no amount of
// elevation supplies. Collapsing those into one "needs admin" message sends an
// operator to the wrong fix.
func (windowsPlatform) planeC() Capability {
	if !(windowsPlatform{}).WideCoverage() {
		return Capability{
			Plane:     PlaneC,
			Available: false,
			Reason: "an ETW session needs an elevated token, and this process is not " +
				"elevated. Security-log events additionally need Advanced Audit Policy " +
				"enabled, which elevation alone does not supply",
			RequiresRoot:  true,
			RequiresGrant: true,
		}
	}
	return Capability{
		Plane:     PlaneC,
		Available: true,
		Mechanism: "ETW (Microsoft-Windows-Kernel-Process) and the Security event log; " +
			"Security-log events additionally need Advanced Audit Policy enabled",
		RequiresRoot:  true,
		RequiresGrant: true,
	}
}
