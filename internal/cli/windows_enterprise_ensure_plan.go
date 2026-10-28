// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// windowsEnterpriseEnsurePlan is the action ensure selected and why.
type windowsEnterpriseEnsurePlan struct {
	Action string // "", install, upgrade, repair
	Reason string
	Detail string // the failed read-only check behind a verify_failed repair
}

// windowsEnterpriseGenerationRecoveryDetail names why ensure repaired a
// compliant deployment after it recovered the config generation record.
const windowsEnterpriseGenerationRecoveryDetail = "config generation record required recovery"

// planWindowsEnterpriseEnsureAfterGenerationRecovery selects ensure's action
// after it recovered a damaged config generation record from the approved
// config. The recovery rewrites only that record, so the deployment still
// gets the action the planner selects: a newer Setup over an older release
// upgrades, and drift is reapplied. Forcing a repair instead kept this
// run's payload as if it were the installed release, put the newer binaries
// in place and recorded the older version. Only a deployment the planner
// finds compliant (the same release and no drift, so this run's payload is
// the installed one) gets the repair that restarts the gateway on the
// recovered record. A planner refusal stays a refusal.
func planWindowsEnterpriseEnsureAfterGenerationRecovery(plan func() (windowsEnterpriseEnsurePlan, error)) (windowsEnterpriseEnsurePlan, error) {
	planned, err := plan()
	if err != nil {
		return windowsEnterpriseEnsurePlan{}, err
	}
	if planned.Action != "" {
		return planned, nil
	}
	return windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed", Detail: windowsEnterpriseGenerationRecoveryDetail}, nil
}
