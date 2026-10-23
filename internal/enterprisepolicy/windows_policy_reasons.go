// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
)

// A configured Windows machine hook is required even with no enrolled SIDs.
// An absent vendor policy is a protection failure, not an enrollment state.
const windowsMissingMachineHookReason = "%s's configured machine hook is missing; this is a protection failure even with zero enrolled users. Stop %s use until repaired. From an elevated session, run 'defenseclaw enterprise windows reconcile --profile standalone' or 'defenseclaw enterprise windows repair --profile standalone'"

func windowsMissingMachineHookDiagnostic(connector string) string {
	return fmt.Sprintf(windowsMissingMachineHookReason, connector, connector)
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
		state.conflict("%s hook executable %s %s. Stop %s use, repair the installation, then run 'defenseclaw enterprise windows verify --profile standalone --json' from an elevated session before allowing agent use", connector, opts.HookBinary, reason, connector)
	}
}
