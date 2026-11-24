// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"strings"
	"testing"
)

// GAP-0435: a kit whose relay has session keys and no verify_url is refused
// by Validate (the hook, the relay and the template build all load the kit
// through it), naming relay.verify_url; with verify_url it passes.
func TestKitConfigSessionKeysNeedVerifyURLGAP0435(t *testing.T) {
	c := DefaultConfig()
	c.Relay.SessionKeys = map[string]string{"k1": "/etc/defenseclaw/relay-keys/k1.pem"}
	c.Relay.SessionIssuer = "https://defenseclaw-admin"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "relay.verify_url") {
		t.Fatalf("session keys without verify_url: %v", err)
	}
	c.Relay.VerifyURL = RelayVerifyURL(c.GatewayURL)
	if err := c.Validate(); err != nil {
		t.Fatalf("session keys with verify_url: %v", err)
	}
	if want := strings.TrimRight(DefaultGatewayURL, "/") + "/api/v1/substrate/relay/verify"; c.Relay.VerifyURL != want {
		t.Fatalf("verify_url %q, want %q", c.Relay.VerifyURL, want)
	}
	// Keys with verify_url still need their issuer.
	c.Relay.SessionIssuer = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "session_issuer") {
		t.Fatalf("session keys without an issuer: %v", err)
	}
	// verify_url alone, and neither (a kit that starts no relay), pass.
	c.Relay.SessionKeys = nil
	if err := c.Validate(); err != nil {
		t.Fatalf("verify_url alone: %v", err)
	}
	c.Relay.VerifyURL = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("no relay session check: %v", err)
	}
}
