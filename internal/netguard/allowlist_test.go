// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"net"
	"testing"
)

func TestIsAllowedPrivateIP_EmptyList(t *testing.T) {
	SetAllowedPrivateIPs(nil)
	if IsAllowedPrivateIP(net.ParseIP("10.50.2.100")) {
		t.Error("expected false when allowlist is empty")
	}
}

func TestIsAllowedPrivateIP_Allowed(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("10.50.2.100")})
	defer SetAllowedPrivateIPs(nil)

	if !IsAllowedPrivateIP(net.ParseIP("10.50.2.100")) {
		t.Error("expected true for allowed IP")
	}
}

func TestIsAllowedPrivateIP_NotInList(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("10.50.2.100")})
	defer SetAllowedPrivateIPs(nil)

	if IsAllowedPrivateIP(net.ParseIP("10.50.2.101")) {
		t.Error("expected false for IP not in list")
	}
}

func TestIsAllowedPrivateIP_NilIP(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("10.50.2.100")})
	defer SetAllowedPrivateIPs(nil)

	if IsAllowedPrivateIP(nil) {
		t.Error("expected false for nil IP")
	}
}

func TestIsAllowedPrivateIP_IPv6(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("fd12::1")})
	defer SetAllowedPrivateIPs(nil)

	if !IsAllowedPrivateIP(net.ParseIP("fd12::1")) {
		t.Error("expected true for allowed IPv6 ULA address")
	}
}

func TestIsAllowedPrivateIP_MultipleIPs(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{
		net.ParseIP("10.50.2.100"),
		net.ParseIP("172.16.0.5"),
		net.ParseIP("192.168.1.10"),
	})
	defer SetAllowedPrivateIPs(nil)

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.50.2.100", true},
		{"172.16.0.5", true},
		{"192.168.1.10", true},
		{"10.50.2.101", false},
		{"172.16.0.6", false},
		{"8.8.8.8", false},
	}
	for _, tc := range cases {
		got := IsAllowedPrivateIP(net.ParseIP(tc.ip))
		if got != tc.want {
			t.Errorf("IsAllowedPrivateIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsPrivateOrReserved_AllowedIPPassesThrough(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("10.50.2.100")})
	defer SetAllowedPrivateIPs(nil)

	if IsPrivateOrReserved(net.ParseIP("10.50.2.100")) {
		t.Error("expected false for allowed private IP")
	}
}

func TestIsPrivateOrReserved_LoopbackNeverExempted(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("127.0.0.1")})
	defer SetAllowedPrivateIPs(nil)

	if !IsPrivateOrReserved(net.ParseIP("127.0.0.1")) {
		t.Error("expected true: loopback must never be exempted")
	}
}

func TestIsPrivateOrReserved_LinkLocalNeverExempted(t *testing.T) {
	SetAllowedPrivateIPs([]net.IP{net.ParseIP("169.254.1.1")})
	defer SetAllowedPrivateIPs(nil)

	if !IsPrivateOrReserved(net.ParseIP("169.254.1.1")) {
		t.Error("expected true: link-local must never be exempted")
	}
}

func TestIsPrivateOrReserved_IPv6MetadataNeverExempted(t *testing.T) {
	metadata := net.ParseIP("fd00:ec2::254")
	SetAllowedPrivateIPs([]net.IP{metadata})
	defer SetAllowedPrivateIPs(nil)

	if !IsPrivateOrReserved(metadata) {
		t.Error("expected true: IPv6 cloud metadata must never be exempted")
	}
}

func TestIsHardDeniedIP_NormalizesIPv4MappedIPv6(t *testing.T) {
	for _, raw := range []string{"::ffff:127.0.0.1", "::ffff:169.254.169.254"} {
		if !IsHardDeniedIP(net.ParseIP(raw)) {
			t.Errorf("IsHardDeniedIP(%s) = false, want true", raw)
		}
	}
}

func TestParseAllowedPrivateUpstreams_Empty(t *testing.T) {
	ips := ParseAllowedPrivateUpstreams(nil)
	if len(ips) != 0 {
		t.Errorf("expected empty, got %v", ips)
	}
}

func TestParseAllowedPrivateUpstreams_ValidIPs(t *testing.T) {
	ips := ParseAllowedPrivateUpstreams([]string{"10.50.2.100", "172.16.0.5"})
	if len(ips) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(ips))
	}
}

func TestParseAllowedPrivateUpstreams_Dedup(t *testing.T) {
	ips := ParseAllowedPrivateUpstreams([]string{"10.50.2.100", "10.50.2.100"})
	if len(ips) != 1 {
		t.Errorf("expected 1 IP after dedup, got %d", len(ips))
	}
}

func TestParseAllowedPrivateUpstreams_InvalidSkipped(t *testing.T) {
	ips := ParseAllowedPrivateUpstreams([]string{"not-an-ip", "10.50.2.100"})
	if len(ips) != 1 {
		t.Errorf("expected 1 valid IP, got %d", len(ips))
	}
}
