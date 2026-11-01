// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package launchdstandalone

import (
	"net"
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0963: launchd, not the gateway, binds the gateway's API address, so
// the port stays held while the gateway restarts and a native exporter's
// connection waits for the gateway instead of reaching another account. The
// plist must declare exactly the address every standalone gateway serves.
func TestGatewayPlistHoldsTheStandaloneAPIAddress(t *testing.T) {
	data, err := ReadPlist("com.cisco.defenseclaw.gateway")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?s)<key>Sockets</key>\s*<dict>\s*<key>api</key>\s*<dict>(.*?)</dict>\s*</dict>`).FindSubmatch(data)
	if match == nil {
		t.Fatal("the gateway plist declares no launchd socket named api")
	}
	values := map[string]string{}
	for _, pair := range regexp.MustCompile(`<key>(\w+)</key>\s*<string>([^<]*)</string>`).FindAllSubmatch(match[1], -1) {
		values[string(pair[1])] = string(pair[2])
	}
	host, port, err := net.SplitHostPort(managed.StandaloneAPIAddr)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"SockFamily": "IPv4", "SockNodeName": host, "SockServiceName": port, "SockType": "stream"}
	if len(values) != len(want) {
		t.Fatalf("api socket = %v, want %v", values, want)
	}
	for key, value := range want {
		if values[key] != value {
			t.Fatalf("api socket %s = %q, want %q (all: %v)", key, values[key], value, values)
		}
	}
	// Every other daemon binds nothing through launchd.
	for _, label := range Labels() {
		if label == "com.cisco.defenseclaw.gateway" {
			continue
		}
		other, err := ReadPlist(label)
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`<key>Sockets</key>`).Match(other) {
			t.Fatalf("%s declares launchd sockets", label)
		}
	}
}
