// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"sync"
)

// Host prerequisite check ids. Each missing prerequisite is logged as
// `defenseclaw_prereq check=<id> remedy=<text>` once per streak. A missing
// prerequisite never fails install, purge or a service: the affected
// component runs degraded and the check repeats, so the host heals as soon as
// the condition clears.
const (
	// PrereqBinaryExecAllowed: application control or EDR lets the gateway
	// binary execute (and has not quarantined it).
	PrereqBinaryExecAllowed = "binary_exec_allowed"
	// PrereqSystemImmutableFlag: a DefenseClaw object carries schg or sappnd
	// while kern.securelevel is above 0, so no running component can clear it.
	PrereqSystemImmutableFlag = "system_immutable_flag"
	// PrereqGatewayLoopbackPort: the gateway's loopback ports are not held by
	// another process and are reachable over loopback.
	PrereqGatewayLoopbackPort = "gateway_loopback_port"
	// PrereqHookTransportTools: /usr/bin/curl runs, and jq or a usable python3
	// is on the hook PATH for structured agent responses.
	PrereqHookTransportTools = "hook_transport_tools"
	// PrereqCMIDLibraryValidation: the managed identity library loads under the
	// gateway's code-signing policy.
	PrereqCMIDLibraryValidation = "cmid_library_validation"
	// PrereqEndpointSecurityDenied: an Endpoint Security client denied a
	// DefenseClaw file operation.
	PrereqEndpointSecurityDenied = "endpoint_security_denied"
	// PrereqTCCFullDiskAccess: AI inventory cannot read a TCC-protected scan
	// root. Inventory only; enforcement never needs Full Disk Access.
	PrereqTCCFullDiskAccess = "tcc_full_disk_access"
)

// PrereqFinding is one missing host prerequisite.
type PrereqFinding struct {
	Check  string
	Path   string
	Detail string
	Remedy string
}

func (f PrereqFinding) key() string {
	return f.Check + "\x00" + f.Path + "\x00" + f.Detail
}

func (f PrereqFinding) fields() map[string]string {
	fields := map[string]string{"check": f.Check, "remedy": f.Remedy}
	if f.Path != "" {
		fields["path"] = f.Path
	}
	if f.Detail != "" {
		fields["detail"] = f.Detail
	}
	return fields
}

// PrereqReporter logs each finding of a repeated check once per streak: a
// finding is logged when it first appears, stays quiet while it persists, and
// is logged again only after a pass where it was absent.
type PrereqReporter struct {
	mu     sync.Mutex
	active map[string]struct{}
}

// Report logs the findings that are new since the previous call and forgets
// the ones that cleared. It returns the findings it logged.
func (r *PrereqReporter) Report(findings []PrereqFinding) []PrereqFinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := make(map[string]struct{}, len(findings))
	var logged []PrereqFinding
	for _, finding := range findings {
		key := finding.key()
		current[key] = struct{}{}
		if _, seen := r.active[key]; seen {
			continue
		}
		EmitResilienceEvent(MarkerPrereq, finding.fields())
		logged = append(logged, finding)
	}
	r.active = current
	return logged
}

// prereqOnce logs one-off prerequisite events (denials observed by writers,
// a library load failure) once per key for the life of the process, until
// the key is cleared.
var prereqOnce sync.Map

func reportPrereqOnce(key string, finding PrereqFinding) bool {
	if _, seen := prereqOnce.LoadOrStore(key, struct{}{}); seen {
		return false
	}
	EmitResilienceEvent(MarkerPrereq, finding.fields())
	return true
}

func clearPrereqOnce(prefix string) {
	prereqOnce.Range(func(key, _ any) bool {
		if k, ok := key.(string); ok && strings.HasPrefix(k, prefix) {
			prereqOnce.Delete(key)
		}
		return true
	})
}

// cmidLibraryPolicyMarkers are the dyld messages macOS uses when the code
// signing policy refuses a library: library validation under the hardened
// runtime, or a signature that does not match the loading process.
var cmidLibraryPolicyMarkers = []string{
	"library load disallowed by system policy",
	"not valid for use in process",
	"code signature in",
	"mapping process and mapped file (non-platform) have different team ids",
}

// CMIDLibraryLoadFinding classifies a managed identity library load error. It
// returns a finding only when the error is the code-signing policy refusing
// the library; a missing library or any other failure is not a prerequisite.
func CMIDLibraryLoadFinding(err error) (PrereqFinding, bool) {
	if err == nil {
		return PrereqFinding{}, false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range cmidLibraryPolicyMarkers {
		if strings.Contains(message, marker) {
			return PrereqFinding{
				Check:  PrereqCMIDLibraryValidation,
				Detail: err.Error(),
				Remedy: "The managed identity library could not be loaded under the gateway's code-signing policy. The gateway and libcmidapi.dylib must be signed by the same Team ID.",
			}, true
		}
	}
	return PrereqFinding{}, false
}

// ReportCMIDLibraryLoadError logs cmid_library_validation once per streak
// when err is a code-signing refusal, and ends the streak when err is nil (the
// library loaded). The gateway calls it wherever it records the library build
// outcome.
func ReportCMIDLibraryLoadError(err error) {
	const prefix = PrereqCMIDLibraryValidation + "\x00"
	if err == nil {
		clearPrereqOnce(prefix)
		return
	}
	if finding, ok := CMIDLibraryLoadFinding(err); ok {
		reportPrereqOnce(prefix, finding)
	}
}
