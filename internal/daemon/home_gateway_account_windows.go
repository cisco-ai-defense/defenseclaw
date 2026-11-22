// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// holderAccount reports whether the process holding the port runs as this
// account. The Windows socket table names a PID only (UID -1), so the
// process is opened and its token user SID compared with this process's.
// Access denied to the process or to its token is holderAccountUnreadable: a
// gateway of this account started elevated, or in another logon session
// (a scheduled task, an administrator's SSH session), looks like that to a
// non-elevated caller, and so does another account's process;
// HomeGatewayHoldsPort then needs the creation time the gateway recorded.
// Any other error is holderOtherAccount: the agents are parked.
func holderAccount(holder PortHolder) holderAccountMatch {
	if holder.PID <= 0 {
		return holderOtherAccount
	}
	theirs, err := peercred.ProcessSID(uint32(holder.PID))
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return holderAccountUnreadable
		}
		return holderOtherAccount
	}
	mine, err := peercred.CurrentProcessSID()
	if err != nil {
		return holderOtherAccount
	}
	if strings.TrimSpace(theirs) != "" && strings.EqualFold(theirs, mine) {
		return holderThisAccount
	}
	return holderOtherAccount
}

// holderStartIdentity is processStartIdentity (the creation time through a
// limited-query handle) or, when the process does not open for this
// caller, the creation time the kernel's process list gives without a
// handle, in the same text.
func holderStartIdentity(pid int) (string, error) {
	if identity, err := processStartIdentity(pid); err == nil && identity != "" {
		return identity, nil
	}
	created, ok := procprobe.CreationTime(pid)
	if !ok {
		return "", fmt.Errorf("daemon: no creation time for pid %d", pid)
	}
	return strconv.FormatInt(created.UnixNano(), 10), nil
}
