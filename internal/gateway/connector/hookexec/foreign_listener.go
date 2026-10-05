// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"net"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// foreignListenerPID is the listener-ownership check (a seam for tests).
var foreignListenerPID = daemon.ForeignListenerPID

// foreignListenerReasonPrefix starts the reason of a call blocked because
// another account's process holds this account's gateway port.
const foreignListenerReasonPrefix = "another account's process"

// perUserForeignListener returns the PID of another account's process that
// holds this per-user hook's gateway port, or 0. The hook then sends it no
// token or payload (GAP-1343): on Windows such a listener collected every
// connector's bearer, and its 401 was reported as token drift. Managed hooks
// verify the service listener with their own transport.
func perUserForeignListener(opts Options) int {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return 0
	}
	host, rawPort, err := net.SplitHostPort(opts.APIAddr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return foreignListenerPID(host, port, opts.Home)
}

func foreignListenerReason(addr string, pid int) string {
	return fmt.Sprintf(
		"%s (PID %d) holds this account's gateway port %s, so DefenseClaw sent it nothing. "+
			"Run `defenseclaw-gateway start` to see how to move this account's gateway to a free port",
		foreignListenerReasonPrefix, pid, addr,
	)
}
