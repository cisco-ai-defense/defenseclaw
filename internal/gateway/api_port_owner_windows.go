// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// apiPortHolderOf reads the owner TCP listener table for a listener that
// blocks a bind of addr (S1 DESIGN 16.2, REVIEW-code-delta-d962 P2-1/P2-2).
// The bind error alone names no holder on Windows: another account's
// listener on the same address fails with WSAEADDRINUSE, its wildcard
// listener with WSAEACCES, and a port inside an excluded range (Hyper-V,
// WinNAT, Docker reservations) also with WSAEACCES. The table does:
//   - no listener row blocks addr: a reservation, or a holder already gone
//     (Found false: nothing is marked, the next conflict looks again);
//   - a listener of this process or of a process whose token names this
//     account (its own gateway still exiting): Found, not Other;
//   - any other listener: another account. A process this account cannot
//     open or whose token it cannot read (another user, a service, a
//     system listener such as http.sys, an elevated process) counts as
//     another account: a needless key rotation is safe, a missed one is not.
func apiPortHolderOf(addr string) (apiPortHolderInfo, error) {
	ip, port, ok := apiBindIP(addr)
	if !ok {
		return apiPortHolderInfo{}, fmt.Errorf("api address %q", addr)
	}
	listeners, err := peercred.TCPListeners(port)
	if err != nil {
		return apiPortHolderInfo{}, err
	}
	self, err := peercred.CurrentProcessSID()
	if err != nil {
		return apiPortHolderInfo{}, err
	}
	var info apiPortHolderInfo
	for _, l := range listeners {
		if !apiBindBlockedBy(l.IP, l.Port, ip, port) {
			continue
		}
		info.Found = true
		if l.PID == windows.GetCurrentProcessId() {
			continue
		}
		sid, err := peercred.ProcessSID(l.PID)
		if err != nil {
			return apiPortHolderInfo{Found: true, Other: true}, nil
		}
		if sid != self {
			return apiPortHolderInfo{Found: true, Other: true, SID: sid}, nil
		}
	}
	return info, nil
}
