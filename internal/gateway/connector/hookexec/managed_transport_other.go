// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"net"
	"net/http"
	"time"
)

// managedEnterpriseHTTPClient on macOS / Linux returns a plain
// loopback-friendly HTTP client. The Windows sibling performs an
// SCM-based peer-verification because Windows managed_enterprise
// runs the gateway as a named SCM service (`DefenseClawGateway`) and
// SCM lets a client resolve "what PID owns this exact registered
// service" at connect time — a check the Windows path uses to
// refuse a malicious replacement that briefly bound the same
// loopback port.
//
// macOS has no equivalent primitive on TCP loopback (LOCAL_PEERCRED
// is UDS-only), and the equivalent invariants come from a different
// mechanism: the launchd LaunchDaemon plist that binds
// `<APIAddr>` (loopback `127.0.0.1:<PORT>`) lives in
// /Library/LaunchDaemons/ which is root:wheel 0644 — a non-root
// process cannot install a replacement service or rebind an
// already-bound port. The gateway's own codesign identity is
// verified separately by the macOS IPC accept path (spec 004
// peerauth_darwin.go) at accept-time via LOCAL_PEERCRED + codesign
// on the peer. This client is the reverse leg (hook → gateway)
// where the loopback-plus-admin-plist trust chain suffices.
//
// Prior behaviour returned errManagedGatewayPeerUnverified
// unconditionally on non-Windows, which broke every Codex / Claude
// hook call on macOS managed_enterprise (the caller's fail-closed
// branch fires with reason enterprise_managed_gateway_peer_unverified
// before any request bytes leave the process). See spec 006 code-
// review Tier 1 finding T1.1 (Agent E "wrapper/proxy correctness").
//
// The standalone managed profile on Linux and macOS does not use this
// client: hooks bound to the root-owned runtime descriptor select
// managedStandaloneHTTPClient (managed_standalone_transport.go), which
// verifies the listener's uid before sending a byte. This function remains
// the unchanged path for the Secure Client macOS deployment.
func managedEnterpriseHTTPClient(
	timeout time.Duration,
	_ string,
	_ string,
) (*http.Client, error) {
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Match the Windows sibling's transport shape:
			// DisableKeepAlives so each hook call reuses the
			// full dial-and-connect discipline; DialContext with
			// a 2-second dial timeout to bound a busy loopback.
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
