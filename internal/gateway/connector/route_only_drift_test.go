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

// TestRouteOnlyDriftReadsBoundedAndQuotesNothing: an oversize agent file is
// refused without being read whole, a corrupt route record is drift whose
// text names no path and quotes no content, and the reader seam is used for
// every file (S1 REVIEW-code-winroute P3-3).
func TestRouteOnlyDriftReadsBoundedAndQuotesNothing(t *testing.T) {
	path, opts := routeSettingsFixture(t, "{}")
	c := NewClaudeCodeConnector()
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "tok-1"}
	if err := os.Truncate(path, UserNativeOTLPReadLimit+1); err != nil {
		t.Fatal(err)
	}
	err := RouteOnlyDrift(c, opts, route)
	if !errors.Is(err, ErrRouteConfigDrift) || !strings.Contains(err.Error(), "larger than") || strings.Contains(err.Error(), path) {
		t.Fatalf("oversize settings = %v; want bounded drift without the path", err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(routeBackupPath(opts.DataDir, c.Name()), []byte(`{"applied": ZZsecret`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = RouteOnlyDrift(c, opts, route)
	if !errors.Is(err, ErrRouteConfigDrift) || strings.Contains(err.Error(), "ZZ") || strings.Contains(err.Error(), opts.DataDir) {
		t.Fatalf("corrupt record = %v; want drift without content or path", err)
	}
	var read []string
	reader := func(p string) ([]byte, error) {
		read = append(read, p)
		return nil, os.ErrNotExist
	}
	if err := RouteOnlyDriftWithReader(c, opts, route, reader); !errors.Is(err, ErrRouteConfigDrift) {
		t.Fatalf("missing files through the reader = %v; want drift", err)
	}
	if len(read) != 2 || read[0] != routeBackupPath(opts.DataDir, c.Name()) || read[1] != path {
		t.Fatalf("reader got %v; want the record then the settings file", read)
	}
}
