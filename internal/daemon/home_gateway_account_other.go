// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import "os"

// holderAccount reports whether the process holding the port runs as this
// account: the socket table's UID, or the process UID when the table gave
// none. Any lookup error is holderOtherAccount: the agents are parked. The
// UID of any process is readable here, so it is never
// holderAccountUnreadable.
func holderAccount(holder PortHolder) holderAccountMatch {
	if holder.PID <= 0 {
		return holderOtherAccount
	}
	uid := holder.UID
	if uid < 0 {
		var err error
		if uid, err = gatewayProcessUID(holder.PID); err != nil {
			return holderOtherAccount
		}
	}
	if uid >= 0 && uid == os.Getuid() {
		return holderThisAccount
	}
	return holderOtherAccount
}

// holderStartIdentity is processStartIdentity: any process's start identity
// is readable here.
func holderStartIdentity(pid int) (string, error) { return processStartIdentity(pid) }
