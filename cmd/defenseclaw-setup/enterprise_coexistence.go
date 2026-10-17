// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winenterprise"
)

// refuseSetupBesideEnterprise stops a per-user install, upgrade, or repair on
// a computer that has an administrator-managed enterprise deployment. The
// per-user gateway would take the local port the enterprise managed hooks
// use. Uninstall is not gated, so an existing per-user copy can be removed.
var refuseSetupBesideEnterprise = func() error {
	return winenterprise.RefusePerUser("be installed, upgraded, or repaired")
}

// refuseRuntimeRestoreBesideEnterprise stops a setup rollback, recovery, or
// committed convergence from restarting the per-user gateway and watchdog
// beside an enterprise deployment. A restored gateway from this release
// refuses to start there, and one from an earlier release would take the port
// the managed hooks use. Setup leaves them stopped instead of failing on the
// refusal, so the journal still closes and uninstall stays available.
var refuseRuntimeRestoreBesideEnterprise = func() error {
	return winenterprise.RefusePerUser("restart its gateway")
}

// Only the exact-owned per-user Run value may be removed after an enterprise
// service appears during rollback. Keeping it would restart a restored older
// gateway at the next logon, even though the current rollback left it stopped.
var disableAutoStartOnEnterpriseRollback = func(gatewayPath string) error {
	_, _, err := configureGatewayAutoStart(gatewayPath, false)
	return err
}

// setupNoticeOutput receives notices about steps Setup skipped on purpose.
var setupNoticeOutput io.Writer = os.Stderr

func reportRuntimeRestoreSkipped(refusal error) {
	fmt.Fprintf(setupNoticeOutput, "DefenseClaw setup left the per-user gateway stopped: %v\n", refusal)
}
