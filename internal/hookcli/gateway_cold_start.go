// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const (
	// hookColdStartFlag marks a start requested by a connector hook.
	HookColdStartFlag = "hook-cold-start"
)

// hookInstallInProgress reports an install or upgrade of this account's
// DefenseClaw (install.sh or install.ps1 hold .install.lock in the data
// directory while they run), or an interrupted one whose recovery waits for
// the next installer run: a start would run the half-done install
// (hookexec.InstallRecoveryPending, GAP-2082).
func HookInstallInProgress(dataDir string) bool {
	return hookexec.InstallLockHeld(dataDir) || hookexec.InstallRecoveryPending(dataDir)
}
