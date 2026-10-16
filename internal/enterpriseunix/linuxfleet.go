// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"

	fleetpolicy "github.com/defenseclaw/defenseclaw/internal/fleet/policy"
)

// The distro interpreter is an optional Fleet prerequisite. Check it when
// Fleet is enabled, before the lifecycle writes config or starts services.
// Runtime compilation uses this same trust and isolated PyYAML admission.
func (e *Env) checkLinuxFleetPython() error {
	check := e.LinuxFleetPythonCheck
	if check == nil {
		check = fleetpolicy.CheckManagedLinuxPython
	}
	if _, err := check(); err != nil {
		return fmt.Errorf("managed Linux: Fleet requires protected /usr/bin/python3 with PyYAML; provision the distribution's python3 and Python YAML packages before enabling fleet.enabled: %w", err)
	}
	return nil
}
