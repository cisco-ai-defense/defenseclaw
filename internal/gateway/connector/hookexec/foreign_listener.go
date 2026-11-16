// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// foreignListenerPID is the listener-ownership check (a seam for tests).
var foreignListenerPID = daemon.ForeignListenerPID

var perUserPortHolder = daemon.FindPortHolder
var perUserListenerClass = daemon.ClassifyPerUserListener

// foreignListenerReasonPrefix starts the reason of a call blocked because
// another account's process holds this account's gateway port.
const foreignListenerReasonPrefix = "another account's process"

// unprovenListenerReasonPrefix starts the reason of a call blocked because a
// listener on this account's gateway port did not answer as this account's
// own gateway and DefenseClaw could not prove it is that gateway. It does not
// say whose process it is: only a listener whose owner was read names another
// account's process.
const unprovenListenerReasonPrefix = "the listener on this account's gateway port did not answer, and DefenseClaw could not prove it is this account's own gateway"

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

// perUserPeerUnverifiedReason is the reason of a per-user call whose
// connected listener the transport refused: it names the other account's
// process while it holds the port, and still says what happened once it has
// closed or unbound. A listener it could not read the owner of is not called
// another account's.
func perUserPeerUnverifiedReason(opts Options) string {
	if pid := perUserForeignListener(opts); pid > 0 {
		return foreignListenerReason(opts.APIAddr, pid)
	}
	if reason := perUserRootGatewayReason(opts); reason != "" {
		return reason
	}
	return unprovenListenerReasonPrefix + " (" + opts.APIAddr + "), so DefenseClaw sent it nothing. " +
		"Check this account's gateway with `defenseclaw-gateway status`"
}

func perUserRootGatewayReason(opts Options) string {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" || opts.SecureClient || opts.Home == "" {
		return ""
	}
	host, rawPort, err := net.SplitHostPort(opts.APIAddr)
	if err != nil {
		return ""
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	holder, holderErr := perUserPortHolder(host, port)
	if holderErr != nil {
		holder = daemon.PortHolder{UID: -1}
	}
	for _, home := range perUserRecordHomes(opts) {
		if perUserListenerClass(host, port, home, holder, holderErr, true) == daemon.PerUserListenerOwnGatewayRunAsRoot {
			return daemon.RootGatewayListenerReason + " " + daemon.RootGatewayListenerRemedy(home)
		}
	}
	return ""
}

// PerUserRootGatewayReason returns the verified root-gateway diagnosis for a
// shell hook's current data store. It only describes the listener; the hook's
// connected-peer check continues to decide whether a call can be sent.
func PerUserRootGatewayReason(apiAddr, dataDir string) string {
	return perUserRootGatewayReason(Options{APIAddr: apiAddr, Home: dataDir})
}

// perUserRootReasonFrame starts the stdout of a per-user post transport that
// refused a root-run gateway of the calling account. The shell hooks read it
// back from exit status PerUserPostPeerUnverifiedExit (_hardening.sh).
const perUserRootReasonFrame = "DCPOSTROOT1:"

// PerUserPeerRefusalOutput is what a per-user post transport prints on stdout
// when err is a refused connected listener (PerUserPostPeerUnverified): the
// framed root-gateway diagnosis, or "" when the listener is not a root-run
// gateway of the calling account. Both transports, the gateway CLI hook-post
// and the small defenseclaw-hook-post helper, print this one text, so the
// message a hook shows does not depend on which of them the install has
// beside the gateway (rel-1-0-6 GAP-0712).
func PerUserPeerRefusalOutput(err error, apiAddr, dataDir string) string {
	if !PerUserPostPeerUnverified(err) {
		return ""
	}
	if reason := PerUserRootGatewayReason(apiAddr, dataDir); reason != "" {
		return perUserRootReasonFrame + reason
	}
	return ""
}

func perUserPeerRefusal(reason string) bool {
	return strings.HasPrefix(reason, foreignListenerReasonPrefix) ||
		strings.HasPrefix(reason, unprovenListenerReasonPrefix) ||
		strings.HasPrefix(reason, daemon.RootGatewayListenerReason)
}

func foreignListenerReason(addr string, pid int) string {
	return fmt.Sprintf(
		"%s (PID %d) holds this account's gateway port %s, so DefenseClaw sent it nothing. "+
			"Run `defenseclaw-gateway start` to see how to move this account's gateway to a free port",
		foreignListenerReasonPrefix, pid, addr,
	)
}
