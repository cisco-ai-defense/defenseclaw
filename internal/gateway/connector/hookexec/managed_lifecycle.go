// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "time"

// managedLifecycleActive reports a managed hook outside Secure Client (the
// standalone profile) while the enterprise lifecycle of its computer has
// DefenseClaw in a transition: an install, upgrade, repair, uninstall or
// another lifecycle run that stops or restarts the gateway, from before it
// stops the gateway until the gateway it starts is ready. The lifecycle
// already keeps one marker for exactly that window (managedLifecycleHeld):
// on Windows the gateway service's start type is not automatic (the
// lifecycle disables every service before it stops it, starts the gateway
// on demand and makes it automatic again only after its readiness proof);
// on Linux and macOS its run marker exists (/run, /var/run on macOS;
// managed.StandaloneLayout.LifecycleMarkerPath), which it holds with its
// lock. Like the per-user install lock, it closes the call
// (closeDuringInstall): an administrator's open covers an outage, never a
// transition, and only the gateway decides a call then (GAP-0993,
// GAP-1074, GAP-1075).
func managedLifecycleActive(opts Options) bool {
	return managedNativeDecision(opts) && managedLifecycleHeld(opts)
}

// managedLifecycleHeldWithin is managedLifecycleHeld bounded by wait, for
// the answer watchdog's look at its deadline: a look that takes longer
// counts as held.
func managedLifecycleHeldWithin(opts Options, wait time.Duration) bool {
	// The look is taken now, as installLockHeldWithin's.
	held := managedLifecycleHeld
	return heldWithin(func() bool { return held(opts) }, wait)
}
