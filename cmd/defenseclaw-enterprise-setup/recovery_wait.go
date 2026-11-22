// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"
)

// enterpriseSetupRecoveryWaitLimit is the longest a standalone Setup waits,
// before it changes anything, for the uninstall recovery an earlier Setup
// armed (--internal-recover-after-parent) to finish. A rerun issued the moment
// a program let go of a file the earlier /uninstall met held ran next to that
// recovery, met its lifecycle lock after 30 s and ended 1618 lifecycle_busy,
// leaving the clean-up to finish in the background (rel-1-0-6:GAP-1080). A
// rerun that waits finds the clean-up done, or finishes what is left, and
// ends 0. The recovery runs under its own 30 minute limit; past this wait the
// rerun is the same retryable 1618 with nothing changed. Replaceable in
// tests.
var enterpriseSetupRecoveryWaitLimit = 10 * time.Minute

// standaloneSetupWaitsForRecovery reports a standalone Setup run that waits
// for an armed uninstall recovery: every action that changes the deployment
// (the mutations and /uninstall, FORCE=1 included). Read-only actions do not
// wait, and the recovery's own Recover run never does: it is the run the
// others wait for.
func standaloneSetupWaitsForRecovery(opts enterpriseSetupOptions) bool {
	return opts.Standalone && (enterpriseSetupMutation(opts.Action, true) || opts.Action == "uninstall")
}

// standaloneRecoveryWaitBound is how long such a run waits: the limit, or
// less so that the action keeps at least half of TIMEOUTSECONDS (and never
// under minimumEnterpriseLifecycleStart) once the wait ends. A run that waited
// until only the 60-second start minimum was left started an upgrade it could
// not finish, timed out midway and rolled back, where without the wait it
// ended 1618 with nothing changed (1.0.10 T1 review). Past the bound the run
// is that 1618. Zero means it only checks.
func standaloneRecoveryWaitBound(opts enterpriseSetupOptions, now time.Time) time.Duration {
	bound := enterpriseSetupRecoveryWaitLimit
	if opts.LifecycleTimeout > 0 {
		reserve := max(opts.LifecycleTimeout/2, minimumEnterpriseLifecycleStart)
		left := enterpriseSetupLifecycleDeadline(opts, now).Sub(now) - reserve
		if left < bound {
			bound = left
		}
	}
	if bound < 0 {
		return 0
	}
	return bound
}

// enterpriseSetupRecoveryBusy is the refusal of a run whose wait for an armed
// uninstall recovery ended with the recovery still running. It is the
// retryable lifecycle_busy (1618); nothing was changed.
type enterpriseSetupRecoveryBusy struct {
	action string
	waited time.Duration
}

func (e enterpriseSetupRecoveryBusy) Error() string {
	return fmt.Sprintf("lifecycle_busy: the recovery an earlier Setup /uninstall started on this computer is still finishing its clean-up; "+
		"Setup waited %s for it and changed nothing. Next step: run Setup /%s again after it finishes (an MDM retries exit 1618 by itself)",
		e.waited.Truncate(time.Second), e.action)
}

// Is makes the refusal the retryable busy result (exit 1618, lifecycle_busy).
func (enterpriseSetupRecoveryBusy) Is(target error) bool {
	return target == errEnterpriseSetupEnsureBusy
}
