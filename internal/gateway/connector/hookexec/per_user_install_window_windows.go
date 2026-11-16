// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

// perUserInstallWindowListening reads the TCP listener table for an IPv4
// endpoint (managedGatewayPortListening); tests replace it.
var perUserInstallWindowListening = managedGatewayPortListening

// perUserInstallWindowWithoutListener reports a per-user call made while this
// account's install or upgrade holds installLockName and nothing listens on
// the gateway's IPv4 loopback endpoint (the one newPerUserHookHTTPClient
// dials). Windows reports a loopback port nobody listens on only after its
// SYN retries (about 2 s, longer under the installer's load; hookDialTimeout),
// and the hook then waited out its restart budget while the installer, not
// the hook, decides when the gateway starts: every call in the window took
// 2-4 s inside the hook, and behind a slow bridge start past the answer
// budget (GAP-1150). With a listener (the new gateway has started and the
// lock is not yet released), with a table that cannot be read, or outside the
// window, the call dials as before: a cold start relies on the refusal.
func perUserInstallWindowWithoutListener(opts Options) bool {
	if !opts.perUserLoopbackDial || !perUserInstallWindow(opts) {
		return false
	}
	targets, err := perUserLoopbackTargets(opts.APIAddr)
	if err != nil {
		return false
	}
	for _, target := range targets {
		if target.Addr().Is4() {
			listening, known := perUserInstallWindowListening(target.String())
			return known && !listening
		}
	}
	return false
}
