// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// holderIsThisAccount reports whether the process holding the port runs as
// this account. The Windows socket table names a PID only (UID -1), so the
// process is opened and its token user SID compared with this process's.
// Any open or token query error is false: the agents are parked.
func holderIsThisAccount(holder PortHolder) bool {
	if holder.PID <= 0 {
		return false
	}
	theirs, err := peercred.ProcessSID(uint32(holder.PID))
	if err != nil {
		return false
	}
	mine, err := peercred.CurrentProcessSID()
	if err != nil {
		return false
	}
	return strings.TrimSpace(theirs) != "" && strings.EqualFold(theirs, mine)
}
