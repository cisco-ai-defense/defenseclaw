// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1133: while the gateway does not hold its API port, the
// Claude Code render points at port 0 and carries no route credential, so an
// agent started then sends nothing to another account's process on the port.
// Owning the port renders the real route; a restore puts the user file back.
func TestClaudeCodeRouteOnlyParkedUntilThePortIsOwned(t *testing.T) {
	original := "{\n  \"env\": {\n    \"ANTHROPIC_CUSTOM_HEADERS\": \"X-Team: blue\"\n  },\n  \"model\": \"sonnet\"\n}"
	path, opts := routeSettingsFixture(t, original)
	c := NewClaudeCodeConnector()
	gate := &RouteOnlyGate{}
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "dcr1-abc", Gate: gate}

	assertParked := func(stage string) {
		t.Helper()
		env := readEnv(t, path)
		if got := env["ANTHROPIC_BASE_URL"]; got != "http://127.0.0.1:0/r/claudecode" {
			t.Fatalf("%s: base url = %v, want the parked port-0 url", stage, got)
		}
		headers, _ := env["ANTHROPIC_CUSTOM_HEADERS"].(string)
		if strings.Contains(headers, RouteOnlyHeader) || strings.Contains(headers, "dcr1-abc") {
			t.Fatalf("%s: a parked render carries the route credential: %q", stage, headers)
		}
		if !strings.Contains(headers, "X-Team: blue") {
			t.Fatalf("%s: the user header was dropped: %q", stage, headers)
		}
	}

	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	assertParked("before the port is owned")

	if !gate.SetOwned(true) {
		t.Fatal("SetOwned(true) did not report a change")
	}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	env := readEnv(t, path)
	if env["ANTHROPIC_BASE_URL"] != route.BaseURL {
		t.Fatalf("owned: base url = %v", env["ANTHROPIC_BASE_URL"])
	}
	if h, _ := env["ANTHROPIC_CUSTOM_HEADERS"].(string); !strings.Contains(h, RouteOnlyHeader+": dcr1-abc") {
		t.Fatalf("owned: headers = %q", h)
	}

	gate.SetOwned(false)
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	assertParked("after the port is released")

	if err := c.ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != original {
		t.Fatalf("restore after a park is not byte-exact:\n got %q\nwant %q", got, original)
	}
}

// The park decision is taken when the render is written, under the gate: a
// render computed before the port was owned (connector Setup running beside
// the API bind) and written after it renders the real route, and the
// reverse.
func TestRouteOnlyGateDecidesAtWriteTime(t *testing.T) {
	path, opts := routeSettingsFixture(t, "")
	c := NewClaudeCodeConnector()
	gate := &RouteOnlyGate{}
	computedWhileParked := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "dcr1-abc", Gate: gate}
	gate.SetOwned(true)
	if err := c.ApplyRouteOnly(opts, computedWhileParked); err != nil {
		t.Fatal(err)
	}
	if got := readEnv(t, path)["ANTHROPIC_BASE_URL"]; got != computedWhileParked.BaseURL {
		t.Fatalf("a render written after the port was owned = %v", got)
	}
	gate.SetOwned(false)
	if err := c.ApplyRouteOnly(opts, computedWhileParked); err != nil {
		t.Fatal(err)
	}
	if got, _ := readEnv(t, path)["ANTHROPIC_BASE_URL"].(string); !IsParkedRouteBaseURL(got) {
		t.Fatalf("a render written after the port was released = %v", got)
	}
	if computedWhileParked.BaseURL != "http://127.0.0.1:18970/r/claudecode" || computedWhileParked.Token != "dcr1-abc" {
		t.Fatal("the caller's route was changed by a parked write")
	}
}

// Codex: the parked provider table has the port-0 base_url and no route
// credential header.
func TestCodexRouteOnlyParkedCarriesNoRouteCredential(t *testing.T) {
	original := "model = \"gpt-5\"\n\n[hooks]\nenabled = true\n"
	path, opts := codexRouteFixture(t, original)
	c := NewCodexConnector()
	gate := &RouteOnlyGate{}
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-xyz", Gate: gate}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `base_url = "http://127.0.0.1:0/r/codex"`) {
		t.Fatalf("parked codex render:\n%s", text)
	}
	if strings.Contains(text, RouteOnlyHeader) || strings.Contains(text, "dcr1-xyz") {
		t.Fatalf("a parked codex render carries the route credential:\n%s", text)
	}
	gate.SetOwned(true)
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), `base_url = "http://127.0.0.1:18970/r/codex"`) || !strings.Contains(string(raw), "dcr1-xyz") {
		t.Fatalf("owned codex render:\n%s", raw)
	}
	if err := c.ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != original {
		t.Fatalf("codex restore after a park:\n got %q\nwant %q", got, original)
	}
}

func TestParkedRouteBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:18970/r/claudecode": "http://127.0.0.1:0/r/claudecode",
		"http://127.0.0.1:19020/r/codex/":     "http://127.0.0.1:0/r/codex/",
		"":                                    "http://127.0.0.1:0",
	} {
		got := ParkedRouteBaseURL(in)
		if got != want || !IsParkedRouteBaseURL(got) {
			t.Fatalf("ParkedRouteBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
	if IsParkedRouteBaseURL("http://127.0.0.1:18970/r/claudecode") {
		t.Fatal("a live route is not parked")
	}
	if !isOwnRouteValue(ParkedRouteBaseURL("http://127.0.0.1:18970/r/claudecode")) {
		t.Fatal("a lost-record restore must still recognize a parked render as ours")
	}
}

// rel-1-0-10:GAP-1133 round 2: a park is built from config alone (no route
// credential), so it must never become a real render. It parks a rendered
// Claude Code or Codex config, leaves a config with nothing rendered alone
// (that agent talks to its provider directly), and is skipped while the gate
// holds the port (the owner renders the real route itself).
func TestRouteOnlyParkOnlyNeverRendersTheRealRoute(t *testing.T) {
	t.Run("claudecode", func(t *testing.T) {
		path, opts := routeSettingsFixture(t, "{\n  \"model\": \"sonnet\"\n}")
		c := NewClaudeCodeConnector()
		gate := &RouteOnlyGate{}
		park := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Gate: gate, ParkOnly: true}

		if err := c.ApplyRouteOnly(opts, park); err != nil {
			t.Fatal(err)
		}
		if env := readEnv(t, path); env["ANTHROPIC_BASE_URL"] != nil {
			t.Fatalf("nothing rendered: a park wrote %v", env)
		}

		gate.SetOwned(true)
		live := &RouteOnlySetup{BaseURL: park.BaseURL, Token: "dcr1-abc", Gate: gate}
		if err := c.ApplyRouteOnly(opts, live); err != nil {
			t.Fatal(err)
		}
		if err := c.ApplyRouteOnly(opts, park); err != nil {
			t.Fatal(err)
		}
		if got := readEnv(t, path)["ANTHROPIC_BASE_URL"]; got != live.BaseURL {
			t.Fatalf("a park while the gate holds the port changed the render: %v", got)
		}

		gate.SetOwned(false)
		if err := c.ApplyRouteOnly(opts, park); err != nil {
			t.Fatal(err)
		}
		env := readEnv(t, path)
		headers, _ := env["ANTHROPIC_CUSTOM_HEADERS"].(string)
		if got, _ := env["ANTHROPIC_BASE_URL"].(string); !IsParkedRouteBaseURL(got) || strings.Contains(headers, RouteOnlyHeader) {
			t.Fatalf("released: base url %v headers %q, want parked without the route credential", got, headers)
		}

		// Without a gate (defenseclaw-gateway stop or start) it parks too.
		gate.SetOwned(true)
		if err := c.ApplyRouteOnly(opts, live); err != nil {
			t.Fatal(err)
		}
		ungated := *park
		ungated.Gate = nil
		if err := c.ApplyRouteOnly(opts, &ungated); err != nil {
			t.Fatal(err)
		}
		if got, _ := readEnv(t, path)["ANTHROPIC_BASE_URL"].(string); !IsParkedRouteBaseURL(got) {
			t.Fatalf("an ungated park = %v", got)
		}
	})
	t.Run("codex", func(t *testing.T) {
		original := "model = \"gpt-5\"\n"
		path, opts := codexRouteFixture(t, original)
		c := NewCodexConnector()
		park := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", ParkOnly: true}
		if err := c.ApplyRouteOnly(opts, park); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); string(got) != original {
			t.Fatalf("nothing rendered: a park changed config.toml:\n%s", got)
		}
		if err := c.ApplyRouteOnly(opts, &RouteOnlySetup{BaseURL: park.BaseURL, Token: "dcr1-xyz"}); err != nil {
			t.Fatal(err)
		}
		if err := c.ApplyRouteOnly(opts, park); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		if !strings.Contains(string(raw), `base_url = "http://127.0.0.1:0/r/codex"`) || strings.Contains(string(raw), "dcr1-xyz") {
			t.Fatalf("parked codex render:\n%s", raw)
		}
		if err := c.ApplyRouteOnly(opts, nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); string(got) != original {
			t.Fatalf("codex restore after a park-only write:\n got %q\nwant %q", got, original)
		}
	})
}
