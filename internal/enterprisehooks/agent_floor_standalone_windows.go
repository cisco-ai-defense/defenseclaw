// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsEnterpriseStandalonePlatformAgentMinimums are Windows floors that sit above
// what the hook contracts alone require.
var windowsEnterpriseStandalonePlatformAgentMinimums = map[string]string{
	"codex":  "0.131.0",
	"cursor": "1.7.0",
}

// windowsEnterpriseStandaloneProcess reports whether this process serves the
// standalone profile, from the protected profile pin every standalone service
// and lifecycle helper carries. Secure Client processes never carry it.
var windowsEnterpriseStandaloneProcess = func() bool {
	return managed.IsStandaloneProfile(managed.NormalizeEnterpriseProfile(os.Getenv(managed.EnterpriseProfileEnv)))
}

// windowsEnterpriseStandaloneAgentMinimum is the standalone profile's floor
// for a connector: its Windows platform floor, raised to the lowest
// MinAgentVersion in the hook-contract table. A version below the lowest
// contract has no contract to render or verify a managed hook policy for, so
// the floor comes from the same table the renderer uses. Empty means ungated.
func windowsEnterpriseStandaloneAgentMinimum(connectorName string) string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	minimum := windowsEnterpriseStandalonePlatformAgentMinimums[name]
	contractMinimum := ""
	for _, contract := range connector.KnownHookContracts(name) {
		floor := connector.NormalizeAgentVersion(name, contract.MinAgentVersion)
		if floor == "" {
			continue
		}
		if contractMinimum == "" || compareWindowsEnterpriseVersion(floor, contractMinimum) < 0 {
			contractMinimum = floor
		}
	}
	if contractMinimum != "" && (minimum == "" || compareWindowsEnterpriseVersion(contractMinimum, minimum) > 0) {
		minimum = contractMinimum
	}
	return minimum
}

// requireWindowsEnterpriseStandaloneAgentFloor enforces the standalone floor
// for one target at install and verify time. It is per target on purpose:
// a row below the floor fails alone instead of rejecting the whole manifest
// at load. Secure Client processes return nil and keep their historical
// floors in requireWindowsEnterpriseManagedAgentVersion.
func requireWindowsEnterpriseStandaloneAgentFloor(connectorName, raw string) error {
	if !windowsEnterpriseStandaloneProcess() {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	minimum := windowsEnterpriseStandaloneAgentMinimum(name)
	if minimum == "" {
		return nil
	}
	normalized := connector.NormalizeAgentVersion(name, raw)
	if normalized == "" {
		return fmt.Errorf("enterprise hooks: connector %s agent_version %q is malformed", name, raw)
	}
	if compareWindowsEnterpriseVersion(normalized, minimum) < 0 {
		return fmt.Errorf(
			"enterprise hooks: connector %s agent_version %s is below the lowest hook contract %s",
			name,
			normalized,
			minimum,
		)
	}
	return nil
}
