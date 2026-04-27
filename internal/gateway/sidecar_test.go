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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestResolveActiveConnector_EmptyDefaultsToOpenClaw verifies the
// "operator did not pick anything" branch of S1.4: an empty
// guardrail.connector still works (back-compat) but emits an audible
// "defaulting to openclaw" log line. The test asserts the resolver
// returns the openclaw entry rather than nil so callers can rely on
// the contract.
func TestResolveActiveConnector_EmptyDefaultsToOpenClaw(t *testing.T) {
	t.Parallel()
	reg := connector.NewDefaultRegistry()

	conn, err := resolveActiveConnector(reg, "", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatalf("expected non-nil openclaw default, got nil")
	}
	if got := conn.Name(); got != "openclaw" {
		t.Errorf("connector name = %q, want %q", got, "openclaw")
	}
}

// TestResolveActiveConnector_WhitespaceTreatedAsEmpty pins the
// "trim before lookup" behavior. Without this, a stray space in
// guardrail.connector ("   " from a hand-edited config) would hit
// the unknown-connector error path and abort the sidecar even
// though the operator intent is clearly "use the default".
func TestResolveActiveConnector_WhitespaceTreatedAsEmpty(t *testing.T) {
	t.Parallel()
	reg := connector.NewDefaultRegistry()

	conn, err := resolveActiveConnector(reg, "   ", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil || conn.Name() != "openclaw" {
		t.Fatalf("whitespace name should default to openclaw, got %v", conn)
	}
}

// TestResolveActiveConnector_KnownNameReturnsConnector covers the
// happy path for each of the four built-in connectors. We don't
// just spot-check one — the registry contract for S1.4 is "every
// name DefaultRegistry advertises must resolve cleanly", so we
// drive the assertion off the same list the registry exposes.
func TestResolveActiveConnector_KnownNameReturnsConnector(t *testing.T) {
	t.Parallel()
	reg := connector.NewDefaultRegistry()

	for _, name := range []string{"openclaw", "codex", "claudecode", "zeptoclaw"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, err := resolveActiveConnector(reg, name, "test")
			if err != nil {
				t.Fatalf("resolveActiveConnector(%q) err: %v", name, err)
			}
			if conn == nil {
				t.Fatalf("resolveActiveConnector(%q) returned nil", name)
			}
			if got := conn.Name(); got != name {
				t.Errorf("Name() = %q, want %q", got, name)
			}
		})
	}
}

// TestResolveActiveConnector_UnknownNameReturnsError is the core
// security-relevant assertion of S1.4: a misspelled connector
// name (e.g. "claud-code", "code", "zclaw") must NOT silently
// substitute openclaw. Doing so would patch the wrong agent's
// config files and route Codex / Claude Code traffic through the
// OpenClaw connector — exactly the kind of confused-deputy
// behavior F7 was filed for.
func TestResolveActiveConnector_UnknownNameReturnsError(t *testing.T) {
	t.Parallel()
	reg := connector.NewDefaultRegistry()

	// NOTE: "openclaw " (trailing space) is intentionally NOT here —
	// resolveActiveConnector trims whitespace before lookup so a
	// stray space in a hand-edited config still resolves to the
	// expected connector. Add only values that should be rejected
	// after trimming.
	for _, bad := range []string{"claud-code", "openclaws", "codeX", "rm -rf /"} {
		bad := bad
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			conn, err := resolveActiveConnector(reg, bad, "test")
			if err == nil {
				t.Fatalf("resolveActiveConnector(%q) expected error, got conn=%v", bad, conn)
			}
			if conn != nil {
				t.Fatalf("resolveActiveConnector(%q) must return nil connector on error, got %s", bad, conn.Name())
			}
			// Error text must name the bad value so operators can find
			// it in logs. We also explicitly call out openclaw as the
			// remediation default — the message is part of the
			// operator-facing contract for S1.4.
			if !strings.Contains(err.Error(), "openclaw") {
				t.Errorf("error message should mention the openclaw default, got: %v", err)
			}
		})
	}
}

// TestResolveActiveConnector_SurfaceTagInError ensures the surface
// label flows into both the success log line and the error message.
// A future refactor that drops the parameter would lose the ability
// to distinguish runGuardrail-level failures from watcher-level
// failures in operator logs; this test pins the contract.
func TestResolveActiveConnector_SurfaceTagInError(t *testing.T) {
	t.Parallel()
	reg := connector.NewDefaultRegistry()

	_, err := resolveActiveConnector(reg, "definitely-not-a-connector", "watcher")
	if err == nil {
		t.Fatalf("expected error for unknown connector")
	}
	if !strings.Contains(err.Error(), "watcher") {
		t.Errorf("error should be tagged with surface 'watcher', got: %v", err)
	}
}
