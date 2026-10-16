// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"

	fleetpolicy "github.com/defenseclaw/defenseclaw/internal/fleet/policy"
)

// The managed macOS gateway runs under launchd's restricted PATH. Test the
// same absolute, isolated interpreter that Fleet policy pushes will execute,
// before accepting a Fleet-enabled config and starting services. Non-Fleet
// deployments do not need Python.
func (e *Env) checkMacFleetPython() error {
	check := e.MacFleetPythonCheck
	if check == nil {
		check = fleetpolicy.CheckManagedMacOSPython
	}
	if _, err := check(); err != nil {
		return fmt.Errorf("managed macOS: Fleet requires a protected Python.org Python 3.10+ with PyYAML; provision it before enabling fleet.enabled: %w", err)
	}
	return nil
}
