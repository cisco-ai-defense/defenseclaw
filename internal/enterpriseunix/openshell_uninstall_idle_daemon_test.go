// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"slices"
	"testing"
)

// GAP-0181: with sandboxes never turned on, a signed-in account's sandbox
// command still started its daemon through the package's socket unit. The
// uninstall without purge left that daemon running, unable to answer once
// the launcher was gone, and the package's pre-install guard refused the
// next install for it. The uninstall now stops DefenseClaw's own units in
// every signed-in account, as for an account the subsystem never served.
func TestUninstallStopsTheSandboxDaemonOfASignedInAccountWhenSandboxesWereNeverOn(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", false, nil)))
	h.ops.loggedIn = []SandboxAccount{h.alice}
	h.ops.stops = nil
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if !slices.Contains(h.ops.stops, h.alice.Name+":daemon+gateway+socket") {
		t.Fatalf("the signed-in account's units were not stopped: %v", h.ops.stops)
	}
}
