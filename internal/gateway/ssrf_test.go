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
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// isPrivateIP — IPv4-mapped IPv6 widening (defense in depth for F-1225).
// ---------------------------------------------------------------------------

func TestIsPrivateIP_IPv4MappedIPv6(t *testing.T) {
	cases := map[string]bool{
		// Pre-widening, the v6-mapped form of a v4 private literal
		// would not match any of the explicit /8 /12 /16 CIDRs because
		// the dotted-quad bytes lived in the v6 representation. After
		// the To4()-collapse, every mapped form is rejected.
		"::ffff:127.0.0.1":       true,
		"::ffff:10.0.0.1":        true,
		"::ffff:192.168.0.10":    true,
		"::ffff:169.254.169.254": true, // cloud IMDS via v6-mapped
		"::ffff:172.16.0.1":      true,
		// Public v4-mapped — still public.
		"::ffff:8.8.8.8": false,
		"::ffff:1.2.3.4": false,
		// Native v4 / v6 still classified correctly.
		"127.0.0.1":       true,
		"169.254.169.254": true,
		"::1":             true,
		"fe80::1":         true,
		"fc00::1":         true,
		"2001:db8::1":     false,
		"8.8.8.8":         false,
	}
	for s, want := range cases {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test fixture %q is not a valid IP literal", s)
		}
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", s, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// secureDialContext — F-1225 (proxy/shape-passthrough) and F-1306 (webhook)
// dial-time SSRF defense.
//
// Tests stub the resolver so we can drive private/public outcomes without
// making real DNS queries, and they short-circuit before the actual TCP
// connect by relying on the private-IP rejection happening synchronously
// inside the DialContext closure.
// ---------------------------------------------------------------------------

func dialAndCheck(t *testing.T, allowLoopback bool, addr string, ips []net.IP) error {
	t.Helper()
	resolver := func(_ context.Context, _ string) ([]net.IP, error) {
		out := make([]net.IP, len(ips))
		copy(out, ips)
		return out, nil
	}
	dial := secureDialContextWithResolver(allowLoopback, 100*time.Millisecond, resolver)
	// Use a context with a short deadline so the test never blocks on a
	// real connect even if a fixture sneaks past the private-IP filter
	// (we rely on the deadline expiring rather than reaching a server).
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "tcp", addr)
	return err
}

func TestSecureDialContext_RejectsPrivateLiterals(t *testing.T) {
	// Any literal that's already private must be rejected without ever
	// touching the resolver.
	cases := []string{
		"127.0.0.1:80",
		"10.0.0.1:443",
		"169.254.169.254:80", // cloud IMDS
		"[::1]:80",
		"[fe80::1]:80",
		"[::1%lo0]:80", // F-1225 — scoped IPv6 zone
		"[fe80::1%lo0]:80",
		"[::ffff:127.0.0.1]:80", // F-1225 parity — IPv4-mapped IPv6
		"[::ffff:169.254.169.254]:80",
	}
	for _, addr := range cases {
		err := dialAndCheck(t, false, addr, nil)
		if err == nil {
			t.Errorf("secureDialContext(%q) = nil, want errPrivateAddress", addr)
			continue
		}
		if !errors.Is(err, errPrivateAddress) {
			// dialAndCheck stub never touches the resolver for a
			// literal, so the only legitimate error path is the
			// private-address rejection.
			t.Errorf("secureDialContext(%q) err = %v, want errPrivateAddress", addr, err)
		}
	}
}

func TestSecureDialContext_RejectsPrivateResolution(t *testing.T) {
	// Hostname that resolves to a private IP — DNS rebinding window.
	err := dialAndCheck(t, false, "evil.example.com:443", []net.IP{
		net.ParseIP("127.0.0.1"),
	})
	if !errors.Is(err, errPrivateAddress) {
		t.Errorf("secureDialContext(public-host private-IP) err = %v, want errPrivateAddress", err)
	}
}

func TestSecureDialContext_RejectsMultiAnswerWithAnyPrivate(t *testing.T) {
	// Multi-A-record rebinding: the validator may have seen only the
	// public record at preflight; at dial time the resolver returns
	// (203.0.113.10, 127.0.0.1). We must reject because the second
	// answer is private.
	err := dialAndCheck(t, false, "evil.example.com:443", []net.IP{
		net.ParseIP("203.0.113.10"),
		net.ParseIP("127.0.0.1"),
	})
	if !errors.Is(err, errPrivateAddress) {
		t.Errorf("secureDialContext(multi-answer with private) err = %v, want errPrivateAddress", err)
	}
}

func TestSecureDialContext_AllowLoopbackBypassesLoopbackOnly(t *testing.T) {
	// allowLoopback=true is the dev-mode webhook escape hatch
	// (DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1). It should let loopback
	// through but still reject other private classes.
	type tc struct {
		ip      string
		wantErr bool
	}
	cases := []tc{
		{"127.0.0.1", false},      // loopback — allowed
		{"::1", false},            // loopback v6 — allowed
		{"10.0.0.1", true},        // RFC1918 — still blocked
		{"192.168.1.5", true},     // RFC1918 — still blocked
		{"169.254.169.254", true}, // cloud IMDS — still blocked
		{"fe80::1", true},         // link-local v6 — still blocked
	}
	for _, c := range cases {
		// We can't actually complete a TCP connect in unit tests; we
		// observe whether the dialer reached the post-classification
		// stage by checking the error mode. allowLoopback=true on a
		// loopback IP will return the OS connect error (refused or
		// timeout), NOT errPrivateAddress.
		err := dialAndCheck(t, true, net.JoinHostPort(c.ip, "1"), []net.IP{net.ParseIP(c.ip)})
		isPrivate := errors.Is(err, errPrivateAddress)
		if c.wantErr && !isPrivate {
			t.Errorf("secureDialContext(allowLoopback=true, %q) err = %v, want errPrivateAddress", c.ip, err)
		}
		if !c.wantErr && isPrivate {
			t.Errorf("secureDialContext(allowLoopback=true, %q) blocked loopback unexpectedly", c.ip)
		}
	}
}

func TestSecureDialContext_PassesThroughPublic(t *testing.T) {
	// Public IPs must pass the private-IP filter and reach the dialer.
	// The actual dial will fail (we use a non-routable test address with
	// a 100ms timeout), but the failure must NOT be errPrivateAddress.
	err := dialAndCheck(t, false, "203.0.113.5:1", []net.IP{net.ParseIP("203.0.113.5")})
	if errors.Is(err, errPrivateAddress) {
		t.Errorf("secureDialContext rejected public IP as private: %v", err)
	}
	// We still expect SOME error because there's no listener on the
	// fixture address; the point is just that it isn't an SSRF block.
	if err == nil {
		t.Errorf("secureDialContext unexpectedly connected to fixture address — test environment may be too permissive")
	}
}

func TestSecureDialContext_LookupFailureFailsClosed(t *testing.T) {
	resolver := func(_ context.Context, _ string) ([]net.IP, error) {
		return nil, errors.New("nxdomain")
	}
	dial := secureDialContextWithResolver(false, 100*time.Millisecond, resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := dial(ctx, "tcp", "evil.example.com:443"); err == nil {
		t.Errorf("secureDialContext(NXDOMAIN) = nil, want lookup error")
	} else if !strings.Contains(err.Error(), "lookup") {
		t.Errorf("secureDialContext(NXDOMAIN) err = %v, want lookup error", err)
	}
}

func TestSecureDialContext_EmptyAnswerFailsClosed(t *testing.T) {
	resolver := func(_ context.Context, _ string) ([]net.IP, error) {
		return nil, nil
	}
	dial := secureDialContextWithResolver(false, 100*time.Millisecond, resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := dial(ctx, "tcp", "evil.example.com:443"); err == nil {
		t.Errorf("secureDialContext(empty answer) = nil, want failure")
	} else if !strings.Contains(err.Error(), "no addresses") {
		t.Errorf("secureDialContext(empty answer) err = %v, want 'no addresses' error", err)
	}
}
