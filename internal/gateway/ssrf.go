// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// SSRF guard helpers
//
// Closes:
//   - F-1225: scoped IPv6 literals ("fe80::1%lo0", "::1%lo0") were treated
//     as harmless by isPrivateHost because net.ParseIP returns nil on the
//     zone-qualified form. The fix strips the "%zone" suffix before the
//     ParseIP call. Affects shape-passthrough where allow_unknown_llm_
//     domains is on.
//   - F-1306: the webhook delivery client used Go's default DNS resolution
//     and redirect handling, so DNS rebinding between config-time validation
//     and dial-time, and HTTP redirects to private hosts, both bypassed the
//     SSRF allowlist. The fix installs a secureDialContext that re-resolves
//     and re-classifies every dial, plus a CheckRedirect at the http.Client
//     layer (wired from webhook.go) that re-validates each redirect target.
// ---------------------------------------------------------------------------

// stripIPv6Zone removes the "%zone" suffix from an IPv6 literal so that
// net.ParseIP can recognise the underlying address.
//
// Accepts both the bare ("::1%lo0") and bracketed ("[::1%lo0]:8080") forms;
// the bracketed form is unwrapped by the caller (e.g. isPrivateHost) before
// reaching this helper, so this function only sees the bare host portion.
//
// IPv4 addresses are passed through unchanged. The "%" character is not
// valid in IPv4 literals or DNS hostnames, so it is safe to strip
// unconditionally; a hostname that legitimately contains "%" is malformed.
func stripIPv6Zone(host string) string {
	h := strings.TrimSpace(host)
	if i := strings.Index(h, "%"); i >= 0 {
		return h[:i]
	}
	return h
}

// errPrivateAddress is returned by secureDialContext when a destination
// resolves to a private/loopback/link-local/cloud-metadata address.
var errPrivateAddress = errors.New("destination resolves to private address")

// ssrfDialResolver is the resolver used by secureDialContext. Tests swap it
// out via secureDialContextWithResolver to drive private/public IP outcomes
// without needing a real network. The default points at the system resolver.
type ssrfDialResolver func(ctx context.Context, host string) ([]net.IP, error)

func defaultSSRFDialResolver(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// ssrfBaseDialer is the underlying net.Dialer used to actually establish the
// TCP connection once secureDialContext has selected a safe IP. Pulled out
// as a function so tests can stub it.
var ssrfBaseDialer = func(timeout time.Duration) interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
} {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
}

// secureDialContext wraps net.Dialer.DialContext so that every TCP dial
// re-resolves the destination, rejects any private/loopback/link-local/
// cloud-metadata IP, and pins the dial to a single resolved public address.
// This narrows the DNS-rebinding window between preflight LookupHost (in
// isPrivateHost / validateWebhookURL) and the actual dial: an attacker who
// returns a public IP at preflight and a private IP at dial time is rejected
// here regardless of what the validator at config time saw.
//
// allowLoopback is consumed by the webhook dispatcher when
// DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1 to keep dev workflows functional;
// the proxy/shape-passthrough caller always passes false.
//
// dialTimeout is the per-dial timeout; the caller is expected to also apply
// a request-level timeout via context.
func secureDialContext(allowLoopback bool, dialTimeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return secureDialContextWithResolver(allowLoopback, dialTimeout, defaultSSRFDialResolver)
}

// secureDialContextWithResolver is the test hook for secureDialContext.
func secureDialContextWithResolver(allowLoopback bool, dialTimeout time.Duration, resolve ssrfDialResolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if resolve == nil {
		resolve = defaultSSRFDialResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf-dial: split host:port %q: %w", addr, err)
		}
		host = stripIPv6Zone(host)

		// If the host is an IP literal we classify it directly; this
		// handles both IPv4 ("127.0.0.1") and IPv6 ("::1", "fe80::1")
		// forms after the zone strip above.
		var candidates []net.IP
		if ip := net.ParseIP(host); ip != nil {
			candidates = []net.IP{ip}
		} else {
			ips, rerr := resolve(ctx, host)
			if rerr != nil {
				return nil, fmt.Errorf("ssrf-dial: lookup %s: %w", host, rerr)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("ssrf-dial: no addresses for %s", host)
			}
			candidates = ips
		}

		// Reject if ANY returned address is private. Multi-A-record
		// rebinding is defeated here: an attacker who serves
		// (203.0.113.10, 127.0.0.1) cannot pick the public answer for
		// our preflight and the private one for our dial. Failing on
		// the first private hit is intentional.
		for _, ip := range candidates {
			if isPrivateIP(ip) {
				if allowLoopback && ip.IsLoopback() {
					continue
				}
				return nil, fmt.Errorf("%w: %s -> %s", errPrivateAddress, host, ip)
			}
		}

		// Pick the first eligible IP and pin the dial. Pinning here
		// removes the second OS-level resolve net.Dialer.DialContext
		// would otherwise perform on the addr string.
		var chosen net.IP
		for _, ip := range candidates {
			if allowLoopback && ip.IsLoopback() {
				chosen = ip
				break
			}
			if !isPrivateIP(ip) {
				chosen = ip
				break
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("%w: %s (all candidates private)", errPrivateAddress, host)
		}
		pinned := net.JoinHostPort(chosen.String(), port)
		return ssrfBaseDialer(dialTimeout).DialContext(ctx, network, pinned)
	}
}
