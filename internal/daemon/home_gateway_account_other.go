// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import "os"

// holderIsThisAccount reports whether the process holding the port runs as
// this account: the socket table's UID, or the process UID when the table
// gave none. Any lookup error is false: the agents are parked.
func holderIsThisAccount(holder PortHolder) bool {
	if holder.PID <= 0 {
		return false
	}
	uid := holder.UID
	if uid < 0 {
		var err error
		if uid, err = gatewayProcessUID(holder.PID); err != nil {
			return false
		}
	}
	return uid >= 0 && uid == os.Getuid()
}
