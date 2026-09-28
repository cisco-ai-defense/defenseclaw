// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/defenseclaw/defenseclaw/internal/winenterprise"

// refuseSetupBesideEnterprise stops a per-user install, upgrade, or repair on
// a computer that has an administrator-managed enterprise deployment. The
// per-user gateway would take the local port the enterprise managed hooks
// use. Uninstall is not gated, so an existing per-user copy can be removed.
var refuseSetupBesideEnterprise = func() error {
	return winenterprise.RefusePerUser("be installed, upgraded, or repaired")
}
