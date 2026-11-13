// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRouteOnlyDriftClaudeCode(t *testing.T) {
	path, opts := routeSettingsFixture(t, "{\n  \"model\": \"sonnet\"\n}")
	c := NewClaudeCodeConnector()
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "tok-1"}
	if err := RouteOnlyDrift(c, opts, nil); err != nil {
		t.Fatalf("nothing rendered and nothing wanted: %v", err)
	}
	if err := RouteOnlyDrift(c, opts, route); !errors.Is(err, ErrRouteConfigDrift) {
		t.Fatalf("missing render must drift: %v", err)
	}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	if err := RouteOnlyDrift(c, opts, route); err != nil {
		t.Fatalf("fresh render drifted: %v", err)
	}
	rotated := *route
	rotated.Token = "tok-2"
	if err := RouteOnlyDrift(c, opts, &rotated); !errors.Is(err, ErrRouteConfigDrift) || !strings.HasPrefix(err.Error(), "route_config_drift") {
		t.Fatalf("a rotated credential must drift: %v", err)
	}
	raw, _ := os.ReadFile(path)
	edited := strings.Replace(string(raw), "http://127.0.0.1:18970/r/claudecode", "https://api.anthropic.com", 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RouteOnlyDrift(c, opts, route); !errors.Is(err, ErrRouteConfigDrift) {
		t.Fatalf("a user edit of the base URL must drift: %v", err)
	}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	if err := RouteOnlyDrift(c, opts, nil); !errors.Is(err, ErrRouteConfigDrift) {
		t.Fatalf("routing turned off with a render left must drift: %v", err)
	}
}

func TestRouteOnlyDriftCodex(t *testing.T) {
	_, opts := codexRouteFixture(t, "model = \"gpt-5\"\n")
	c := NewCodexConnector()
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "tok-1"}
	if err := RouteOnlyDrift(c, opts, route); !errors.Is(err, ErrRouteConfigDrift) {
		t.Fatalf("missing render must drift: %v", err)
	}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	if err := RouteOnlyDrift(c, opts, route); err != nil {
		t.Fatalf("fresh render drifted: %v", err)
	}
	rotated := *route
	rotated.Token = "tok-2"
	if err := RouteOnlyDrift(c, opts, &rotated); !errors.Is(err, ErrRouteConfigDrift) {
		t.Fatalf("a rotated credential must drift: %v", err)
	}
	if err := RouteOnlyDrift(NewCursorConnector(), opts, route); err != nil {
		t.Fatalf("a connector without route-only never drifts: %v", err)
	}
}
