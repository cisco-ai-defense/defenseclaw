// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "fmt"

// A configured Windows machine hook is required even with no enrolled SIDs.
// An absent vendor policy is a protection failure, not an enrollment state.
const windowsMissingMachineHookReason = "%s's configured machine hook is missing; this is a protection failure even with zero enrolled users. Stop %s use until repaired. From an elevated session, run 'defenseclaw enterprise windows reconcile --profile standalone' or 'defenseclaw enterprise windows repair --profile standalone'"

func windowsMissingMachineHookDiagnostic(connector string) string {
	return fmt.Sprintf(windowsMissingMachineHookReason, connector, connector)
}
