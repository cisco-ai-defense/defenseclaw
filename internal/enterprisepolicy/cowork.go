// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"strings"
)

const (
	CoworkPackageValue = "coworkEDRIntegration"
	CoworkVendorValue  = "coworkEDRIntegrationVendor"
)

// CheckWindowsCoworkSettings applies the same whole-hive and local 3P
// configuration safeguards as the existing Claude Desktop WSL gate. It never
// writes: the enterprise lifecycle writes both values in its transaction.
func CheckWindowsCoworkSettings(opts Options, packagePath, vendor string, owned []RegValue) (ready bool, refusal string, err error) {
	return checkWindowsCoworkSettings(wslRegistry(), opts, packagePath, vendor, owned)
}

func checkWindowsCoworkSettings(reg WSLRegistry, opts Options, packagePath, vendor string, owned []RegValue) (bool, string, error) {
	values, exists, err := reg.MachineValues(ClaudeDesktopPolicyKey)
	if err != nil {
		return false, "", err
	}
	others := append([]RegValue(nil), values...)
	mine := false
	ready := true
	for name, want := range map[string]string{CoworkPackageValue: packagePath, CoworkVendorValue: vendor} {
		current := findRegValue(values, name)
		previous := findRegValue(owned, name)
		ours := previous != nil && current != nil && sameRegValue(*previous, *current)
		if ours {
			mine = true
			others = withoutRegValue(others, name)
		}
		if current == nil || current.Type != RegSZ || current.String != want {
			ready = false
			if current != nil && !ours {
				return false, fmt.Sprintf("HKLM\\%s\\%s is administrator-owned and differs from the requested REG_SZ; reconcile it in machine policy first", ClaudeDesktopPolicyKey, name), nil
			}
		}
	}
	policy := wslPolicy(opts)
	gap, err := claudeDesktopGateConditions(reg, mine || policy.ClaudeDesktopKey == "create", others, exists)
	if err != nil {
		return false, "", err
	}
	if gap.text != "" {
		return false, strings.ReplaceAll(gap.text, "the gate", "the Cowork settings"), nil
	}
	return ready, "", nil
}
