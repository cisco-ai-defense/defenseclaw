// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestMCPInventoryFingerprintIsKeyedOrderedAndContentFree(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	first := mcpInventoryFingerprintKey(&config.Config{Gateway: config.GatewayConfig{Token: "installation-one"}})
	second := mcpInventoryFingerprintKey(&config.Config{Gateway: config.GatewayConfig{Token: "installation-two"}})
	args := []string{"--token", "private-value"}
	got := mcpInventoryFingerprint(first, "arguments", args)
	if !strings.HasPrefix(got, "hmac-sha256:") || len(got) != 76 ||
		strings.Contains(got, "private-value") {
		t.Fatalf("unsafe fingerprint %q", got)
	}
	if got != mcpInventoryFingerprint(first, "arguments", args) {
		t.Fatal("same installation and ordered arguments changed fingerprint")
	}
	if got == mcpInventoryFingerprint(first, "arguments", []string{"private-value", "--token"}) ||
		got == mcpInventoryFingerprint(first, "arguments", []string{"--tokenprivate-value"}) ||
		got == mcpInventoryFingerprint(second, "arguments", args) ||
		got == mcpInventoryFingerprint(first, "command", args) {
		t.Fatal("argument order, boundaries, key, or domain did not change fingerprint")
	}
	if empty := mcpInventoryFingerprintKey(&config.Config{}); len(empty) != 0 ||
		mcpInventoryFingerprint(empty, "arguments", args) != "" {
		t.Fatal("missing gateway token fell back to an unkeyed fingerprint")
	}
}

func TestMCPInventoryFingerprintBoundsInput(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if got, want := mcpInventoryFingerprint(key, "arguments", []string{"--token", "private-value"}),
		"hmac-sha256:17ed19cd5e0b5a1cb9b97bf772d9a88f8535f40f7991d7a3ff50e3ef034baef4"; got != want {
		t.Fatalf("canonical ordered-argument vector = %q, want %q", got, want)
	}
	if got := mcpInventoryFingerprint(key, "arguments", make([]string, maxMCPFingerprintParts+1)); got != "" {
		t.Fatalf("too many arguments produced fingerprint %q", got)
	}
	if got := mcpInventoryFingerprint(key, "arguments", []string{strings.Repeat("x", maxMCPFingerprintBytes+1)}); got != "" {
		t.Fatalf("oversized arguments produced fingerprint %q", got)
	}
	if got := mcpInventoryFingerprint(key, "other", []string{"x"}); got != "" {
		t.Fatalf("unknown fingerprint domain produced %q", got)
	}
}
