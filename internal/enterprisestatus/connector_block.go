// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"regexp"
	"sort"
	"strings"
)

// The status v2 blocks (connectors, openshell, identity) are optional
// members of status and verify on the standalone profile. They carry codes,
// connector ids, counts, versions and ages only: never an account, SID, uid,
// pid, path, group or free text from a user home. Absent on builds before
// 1.0.3 and under the Secure Client integration.

// CodeStatusDetailUnavailable warns that a status v2 block could not read one
// of its inputs; the block leaves out the members that input feeds.
const CodeStatusDetailUnavailable = "status_detail_unavailable"

// Hooks-installed states of a ConnectorState, from the guardian's last
// reconcile.
const (
	HooksInstalledAll     = "all"
	HooksInstalledPartial = "partial"
	HooksInstalledNone    = "none"
	HooksInstalledUnknown = "unknown"
)

// connectorVersionsMax bounds ConnectorState.Versions.
const connectorVersionsMax = 8

var (
	connectorIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	// versionTokenPattern is every version string status v2 prints: an agent
	// binary in a user home can report any string, so anything else is
	// dropped, never printed.
	versionTokenPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
)

// ValidVersionToken reports whether version may be printed in a status v2
// block.
func ValidVersionToken(version string) bool { return versionTokenPattern.MatchString(version) }

// ConnectorState is one connector of the connectors block.
type ConnectorState struct {
	// Enabled: the installed config enables the connector's hooks.
	Enabled bool `json:"enabled"`
	// Detected: the enumerator found the agent for at least one eligible
	// account. Absent when the connector is not enabled or the enumerator
	// has not run.
	Detected *bool `json:"detected,omitempty"`
	// Versions are the distinct agent versions of the detected installs.
	Versions []string `json:"versions,omitempty"`
	// HooksInstalled is HooksInstalledAll, Partial, None or Unknown.
	HooksInstalled string `json:"hooks_installed"`
	// Targets are the connector's guardian targets; absent when
	// HooksInstalled is unknown.
	Targets *ConnectorTargets `json:"targets,omitempty"`
	// EffectiveMode is the connector's default guardrail mode (observe or
	// action); absent when the config cannot be loaded.
	EffectiveMode string `json:"effective_mode,omitempty"`
	// EffectiveHookFailMode is the fail mode the managed hooks are rendered
	// with (open or closed); absent when the config cannot be loaded.
	EffectiveHookFailMode string `json:"effective_hook_fail_mode,omitempty"`
	// ManagedHook: the DefenseClaw hook is in administrator-owned vendor
	// machine policy rather than a per-user registration. Absent when the
	// connector is not enabled.
	ManagedHook *bool `json:"managed_hook,omitempty"`
}

// ConnectorTargets counts one connector's guardian targets: Total is
// Protected + Pending + Failed.
type ConnectorTargets struct {
	Total     int `json:"total"`
	Protected int `json:"protected"`
	Pending   int `json:"pending"`
	Failed    int `json:"failed"`
}

// ConnectorInstall is one install the enumerator listed: a manifest target
// (Enabled says whether it is enrolled) or an unprotected-agent row. It has
// no account member on purpose.
type ConnectorInstall struct {
	Connector string
	Version   string
	Enabled   bool
}

// ConnectorTarget is one row of the guardian's last reconcile, without its
// account.
type ConnectorTarget struct {
	Connector string
	OK        bool
	// Pending: the target waits for its account's session.
	Pending bool
}

// ConnectorInputs are the plain facts BuildConnectors counts.
type ConnectorInputs struct {
	// ConfigLoaded says the installed config was loaded; Enabled are the
	// connectors it enables and Mode its connector default mode.
	ConfigLoaded bool
	Enabled      []string
	Mode         func(connector string) string
	// ManifestRead says the enumerator's manifest was read; Manifest are
	// its targets.
	ManifestRead bool
	Manifest     []ConnectorInstall
	// Unprotected are the installs the enumerator could not enroll.
	Unprotected []ConnectorInstall
	// GuardianKnown says the guardian state was read and is the one the
	// root-only attestation vouches for; Guardian are its rows.
	GuardianKnown bool
	Guardian      []ConnectorTarget
	// MachinePolicy are the connectors whose DefenseClaw hook is in vendor
	// machine policy.
	MachinePolicy []string
	// Known reports a connector id of the registry; nil accepts every id
	// of the connector-id form.
	Known func(connector string) bool
}

// BuildConnectors is the connectors block: the enabled connectors and those
// that still have targets or unprotected rows. failMode is the resolver the
// managed hook renderer passes to every hook it writes
// (enterprisehooks.ManagedHookFailMode); the block reports what it returns
// and never reads a fail mode from the config itself. hidden counts the
// agent versions dropped because they are not version tokens. nil when
// there is no connector.
func BuildConnectors(in ConnectorInputs, failMode func(connector string) string) (block map[string]ConnectorState, hidden int) {
	id := func(name string) (string, bool) {
		name = strings.ToLower(strings.TrimSpace(name))
		if !connectorIDPattern.MatchString(name) || (in.Known != nil && !in.Known(name)) {
			return "", false
		}
		return name, true
	}
	enabled := map[string]bool{}
	if in.ConfigLoaded {
		for _, name := range in.Enabled {
			if name, ok := id(name); ok {
				enabled[name] = true
			}
		}
	} else {
		// Without the config, a connector the manifest enrolls is enabled.
		for _, row := range in.Manifest {
			if name, ok := id(row.Connector); ok && row.Enabled {
				enabled[name] = true
			}
		}
	}
	listed := map[string]bool{}
	for name := range enabled {
		listed[name] = true
	}
	detected := map[string]bool{}
	versions := map[string]map[string]bool{}
	note := func(rows []ConnectorInstall) {
		for _, row := range rows {
			name, ok := id(row.Connector)
			if !ok {
				continue
			}
			listed[name], detected[name] = true, true
			version := strings.TrimSpace(row.Version)
			switch {
			case version == "":
			case !ValidVersionToken(version):
				hidden++
			default:
				if versions[name] == nil {
					versions[name] = map[string]bool{}
				}
				versions[name][version] = true
			}
		}
	}
	if in.ManifestRead {
		note(in.Manifest)
	}
	note(in.Unprotected)
	counts := map[string]*ConnectorTargets{}
	if in.GuardianKnown {
		for _, row := range in.Guardian {
			name, ok := id(row.Connector)
			if !ok {
				continue
			}
			listed[name] = true
			c := counts[name]
			if c == nil {
				c = &ConnectorTargets{}
				counts[name] = c
			}
			c.Total++
			switch {
			case row.OK:
				c.Protected++
			case row.Pending:
				c.Pending++
			default:
				c.Failed++
			}
		}
	}
	machine := map[string]bool{}
	for _, name := range in.MachinePolicy {
		if name, ok := id(name); ok {
			machine[name] = true
		}
	}
	if len(listed) == 0 {
		return nil, hidden
	}
	block = make(map[string]ConnectorState, len(listed))
	for name := range listed {
		state := ConnectorState{Enabled: enabled[name], HooksInstalled: HooksInstalledUnknown}
		if state.Enabled && (in.ManifestRead || len(in.Unprotected) > 0) {
			found := detected[name]
			state.Detected = &found
		}
		state.Versions = sortedVersions(versions[name])
		if in.GuardianKnown {
			targets := ConnectorTargets{}
			if c := counts[name]; c != nil {
				targets = *c
			}
			state.Targets = &targets
			switch {
			case targets.Protected > 0 && targets.Protected == targets.Total:
				state.HooksInstalled = HooksInstalledAll
			case targets.Protected > 0:
				state.HooksInstalled = HooksInstalledPartial
			default:
				state.HooksInstalled = HooksInstalledNone
			}
		}
		if in.ConfigLoaded {
			if in.Mode != nil {
				state.EffectiveMode = oneOf(in.Mode(name), "observe", "action")
			}
			if failMode != nil {
				state.EffectiveHookFailMode = oneOf(failMode(name), "open", "closed")
			}
		}
		if state.Enabled {
			managed := machine[name]
			state.ManagedHook = &managed
		}
		block[name] = state
	}
	return block, hidden
}

// sortedVersions lists set in order, at most connectorVersionsMax of them.
func sortedVersions(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for version := range set {
		out = append(out, version)
	}
	sort.Strings(out)
	if len(out) > connectorVersionsMax {
		out = out[:connectorVersionsMax]
	}
	return out
}

// oneOf is value in lower case when it is one of allowed, else "".
func oneOf(value string, allowed ...string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, want := range allowed {
		if value == want {
			return value
		}
	}
	return ""
}
