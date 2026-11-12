// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A configured Windows machine hook is required even with no enrolled SIDs.
// An absent vendor policy is a protection failure, not an enrollment state.
// The two %s at the end are the reconcile and repair commands: Setup puts no
// DefenseClaw command on PATH (cowork-1-0-8 GAP-0076).
const windowsMissingMachineHookReason = "%s's configured machine hook is missing; this is a protection failure even with zero enrolled users. Stop %s use until repaired. From an elevated PowerShell prompt, run `%s` or `%s`"

func windowsMissingMachineHookDiagnostic(connector string) string {
	return fmt.Sprintf(windowsMissingMachineHookReason, connector, connector,
		managed.WindowsAdminCommand("enterprise", "windows", "reconcile", "--profile", "standalone"),
		managed.WindowsAdminCommand("enterprise", "windows", "repair", "--profile", "standalone"))
}

// A direct Windows hook command can remain registered after the executable is
// quarantined. A policy file alone cannot prove that the command will run.
func verifyWindowsHookExecutable(opts Options, connector string, state *State) {
	if opts.goos() != "windows" {
		return
	}
	info, err := os.Lstat(opts.HookBinary)
	reason := ""
	if err != nil {
		reason = fmt.Sprintf("is unavailable: %v", err)
	} else if !info.Mode().IsRegular() || info.Size() == 0 {
		reason = "is not a non-empty regular file"
	}
	if reason != "" {
		state.conflict("%s hook executable %s %s. Stop %s use, repair the installation, then run `%s` from an elevated PowerShell prompt before allowing agent use",
			connector, opts.HookBinary, reason, connector, managed.WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone", "--json"))
	}
}
