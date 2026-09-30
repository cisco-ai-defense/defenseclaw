// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Desktop apps and editor extensions (standalone profile only). Discovery
// reports each app or extension install as a connector.AgentSurface; a
// surface enrolls the user when its engine version resolves a hook contract
// and enterprise.enrollment.unverified_versions admits it. Every surface
// that is not admitted is reported in the unprotected-agents record with
// its surface and host version.

// UnprotectedCodeSurfaceUnverified: an app or extension surface was not
// admitted (no engine version, no hook contract for it, or refused by
// unverified_versions: refuse).
const UnprotectedCodeSurfaceUnverified = "surface_unverified"

// Refusal states of a surface refused under unverified_versions: refuse.
const (
	// RefusalEnforced: the route refuses the surface's hook calls (a
	// machine-policy connector whose unenrolled users the gateway or the
	// machine hooks refuse).
	RefusalEnforced = "enforced"
	// RefusalMissing: nothing refuses the surface (a per-user connector
	// the surface runs without hooks, or a user enrolled through another
	// surface of the same connector, whose hook calls look the same).
	// verify fails on it.
	RefusalMissing = "missing"
)

var (
	surfacePolicyMu sync.RWMutex
	surfacePolicy   func(connector string) string
)

// SetUnverifiedVersionsPolicy installs the standalone profile's
// enterprise.enrollment.unverified_versions lookup. nil means report.
func SetUnverifiedVersionsPolicy(policy func(connector string) string) {
	surfacePolicyMu.Lock()
	defer surfacePolicyMu.Unlock()
	surfacePolicy = policy
}

// UnverifiedVersionsFor is the installed policy for connectorName.
func UnverifiedVersionsFor(connectorName string) string {
	surfacePolicyMu.RLock()
	policy := surfacePolicy
	surfacePolicyMu.RUnlock()
	if policy == nil {
		return connector.UnverifiedVersionsReport
	}
	if value := strings.ToLower(strings.TrimSpace(policy(connectorName))); value == connector.UnverifiedVersionsRefuse {
		return value
	}
	return connector.UnverifiedVersionsReport
}

// surfaceRejection is one surface that was not admitted.
type surfaceRejection struct {
	surface connector.AgentSurface
	reason  string
	refused bool // unverified_versions is refuse for the connector
}

// surfaceAdmission is the decision over one user's surfaces of one
// connector.
type surfaceAdmission struct {
	// version is the oldest admitted engine version ("" when none): the
	// row follows the surface with the oldest contract, so its hooks are
	// rendered for every admitted surface.
	version  string
	surface  string
	admitted []connector.AgentSurface
	rejected []surfaceRejection
}

// admitSurfaces decides which of connectorName's surfaces enroll the user
// under policy (connector.UnverifiedVersionsReport or ...Refuse).
func admitSurfaces(connectorName, policy string, surfaces []connector.AgentSurface) surfaceAdmission {
	var out surfaceAdmission
	for _, surface := range surfaces {
		if surface.Surface == "" || surface.Surface == connector.HostSurfaceCLI {
			continue
		}
		resolution := connector.ResolveSurfaceHookContract(connectorName, surface.Surface, surface.EngineVersion)
		ok, reason := resolution.Admitted(policy)
		if !ok {
			out.rejected = append(out.rejected, surfaceRejection{surface: surface, reason: reason, refused: policy == connector.UnverifiedVersionsRefuse})
			continue
		}
		out.admitted = append(out.admitted, surface)
		if out.version == "" || connector.CompareAgentVersions(surface.EngineVersion, out.version) < 0 {
			out.version, out.surface = surface.EngineVersion, surface.Surface
		}
	}
	return out
}

// rowVersion is the version a (user, connector) row is enrolled at: the
// older of the CLI version and the oldest admitted surface's engine
// version, so its hooks are rendered for every admitted install.
func (a surfaceAdmission) rowVersion(cliVersion string) string {
	switch {
	case a.version == "":
		return cliVersion
	case cliVersion == "" || connector.CompareAgentVersions(a.version, cliVersion) < 0:
		return a.version
	}
	return cliVersion
}

// surfaceUnprotected is the unprotected-agent entry for a rejected
// surface. refusal is RefusalEnforced or RefusalMissing when the surface
// is refused, and ignored otherwise.
func (r surfaceRejection) unprotected(user, sid string, uid *int, connectorName, consequence, refusal string) UnprotectedAgent {
	agent := UnprotectedAgent{
		User:        user,
		SID:         sid,
		UID:         uid,
		Connector:   strings.ToLower(strings.TrimSpace(connectorName)),
		Version:     r.surface.EngineVersion,
		Surface:     r.surface.Surface,
		Host:        r.surface.Host,
		HostVersion: r.surface.HostVersion,
		Code:        UnprotectedCodeSurfaceUnverified,
		Reason:      r.reason + "; " + consequence,
	}
	if r.refused {
		agent.Refusal = refusal
	}
	return agent
}
