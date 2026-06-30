// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// splitHostPort parses an httptest server URL into the (host, port) pair
// fetchConnectorModes expects.
func splitHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawURL, err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host:port %q: %v", u.Host, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port %q: %v", portStr, err)
	}
	return host, port
}

// captureStdout runs fn and returns everything it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// normalizeRosterShape collapses a rendered roster down to its
// count-agnostic skeleton so we can assert that a 1-connector and an
// N-connector roster use the SAME layout/wording. It strips ANSI styling,
// the per-connector names, and the numeric "N active" count, leaving only
// the structural labels (e.g. "Agents:", "since", "requests:"). If the two
// rosters share a layout, their skeletons are identical.
func rosterSkeleton(out string) []string {
	replacer := strings.NewReplacer(
		"antigravity", "X", "claudecode", "X", "codex", "X",
		"Antigravity", "X", "Claude Code", "X", "Codex", "X",
	)
	var lines []string
	for _, line := range strings.Split(stripANSI(out), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		t = replacer.Replace(t)
		// Drop the "N active" count and the RFC3339 "since" timestamp so
		// only the count-agnostic structure remains.
		if i := strings.Index(t, " active"); i >= 0 {
			t = "Agents: active"
		}
		if strings.HasPrefix(t, "since ") {
			t = "since"
		}
		lines = append(lines, t)
	}
	return lines
}

// stripANSI removes SGR escape sequences so structural comparisons are not
// thrown off by color codes.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// TestPrintConnectors_ListsAll pins the roster fix: the Agent view must
// list every active connector (with its own counters) under an
// "Agents: N active" header rather than rendering only the primary.
func TestPrintConnectors_ListsAll(t *testing.T) {
	now := time.Now()
	snap := &gateway.HealthSnapshot{
		Connector: &gateway.ConnectorHealth{Name: "antigravity", State: gateway.StateRunning, Since: now},
		Connectors: []gateway.ConnectorHealth{
			{Name: "antigravity", State: gateway.StateRunning, Since: now},
			{Name: "claudecode", State: gateway.StateRunning, Since: now},
			{Name: "codex", State: gateway.StateRunning, Since: now},
		},
	}

	out := captureStdout(t, func() { printConnectors(snap) })

	if !strings.Contains(out, "Agents") || !strings.Contains(out, "3 active") {
		t.Fatalf("expected roster header 'Agents: 3 active', got:\n%s", out)
	}
	for _, name := range []string{"antigravity", "claudecode", "codex"} {
		if !strings.Contains(out, "("+name+")") {
			t.Errorf("connector %q missing from Agents listing:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "Antigravity") || !strings.Contains(out, "Claude Code") || !strings.Contains(out, "Codex") {
		t.Errorf("friendly names missing from listing:\n%s", out)
	}
}

// TestPrintConnectors_SingleConnectorUsesRoster pins the uniform UX: a
// single active connector renders through the SAME "Agents: N active"
// roster as the multi-connector case — no special "Agent:" singular row,
// no "single vs multi" wording branch.
func TestPrintConnectors_SingleConnectorUsesRoster(t *testing.T) {
	now := time.Now()
	snap := &gateway.HealthSnapshot{
		Connector:  &gateway.ConnectorHealth{Name: "codex", State: gateway.StateRunning, Since: now},
		Connectors: []gateway.ConnectorHealth{{Name: "codex", State: gateway.StateRunning, Since: now}},
	}

	out := captureStdout(t, func() { printConnectors(snap) })

	if !strings.Contains(out, "Agents") || !strings.Contains(out, "1 active") {
		t.Errorf("single connector must use the uniform 'Agents: 1 active' header, got:\n%s", out)
	}
	if !strings.Contains(out, "(codex)") {
		t.Errorf("expected codex listed in roster, got:\n%s", out)
	}
}

// TestPrintConnectors_SingleAndMultiShareLayout is the core uniformity
// guarantee: the rendered layout/wording for a 1-connector roster and an
// N-connector roster must be IDENTICAL once connector names and the count
// are factored out. This is the regression guard against reintroducing a
// "single vs multi" presentation branch.
func TestPrintConnectors_SingleAndMultiShareLayout(t *testing.T) {
	now := time.Now()
	single := &gateway.HealthSnapshot{
		Connectors: []gateway.ConnectorHealth{
			{Name: "codex", State: gateway.StateRunning, Since: now},
		},
	}
	multi := &gateway.HealthSnapshot{
		Connectors: []gateway.ConnectorHealth{
			{Name: "antigravity", State: gateway.StateRunning, Since: now},
			{Name: "claudecode", State: gateway.StateRunning, Since: now},
			{Name: "codex", State: gateway.StateRunning, Since: now},
		},
	}

	singleOut := captureStdout(t, func() { printConnectors(single) })
	multiOut := captureStdout(t, func() { printConnectors(multi) })

	singleSkel := rosterSkeleton(singleOut)
	multiSkel := rosterSkeleton(multiOut)

	// The single roster is one connector entry; the multi roster repeats
	// the same entry shape N times. Compare the header + first entry block
	// (everything the single roster emits) against the multi roster prefix.
	if len(multiSkel) < len(singleSkel) {
		t.Fatalf("multi roster shorter than single roster\nsingle:\n%v\nmulti:\n%v", singleSkel, multiSkel)
	}
	for i := range singleSkel {
		if singleSkel[i] != multiSkel[i] {
			t.Errorf("layout diverges at line %d: single=%q multi=%q\nsingle:\n%v\nmulti:\n%v",
				i, singleSkel[i], multiSkel[i], singleSkel, multiSkel)
		}
	}
}

// TestPrintConnectors_NoConnector renders the empty state.
func TestPrintConnectors_NoConnector(t *testing.T) {
	out := captureStdout(t, func() { printConnectors(&gateway.HealthSnapshot{}) })
	if !strings.Contains(out, "no active connector") {
		t.Errorf("expected '(no active connector)', got:\n%s", out)
	}
}

func TestPrintHookGuardianStatusManagedMissingState(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = &config.Config{
		DataDir:        t.TempDir(),
		DeploymentMode: "managed_enterprise",
	}

	out := captureStdout(t, printHookGuardianStatus)
	if !strings.Contains(out, "Hook guardian") || !strings.Contains(out, "not reconciled") {
		t.Fatalf("managed enterprise missing-state output should show not reconciled, got:\n%s", out)
	}
}

func TestPrintHookGuardianStatusHealthy(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })
	dir := t.TempDir()
	cfg = &config.Config{
		DataDir:        dir,
		DeploymentMode: "managed_enterprise",
	}
	state := `{
  "version": 1,
  "updated_at": "2026-06-24T01:00:00Z",
  "manifest": "/etc/defenseclaw/hook-guardian/targets.yaml",
  "ok": true,
  "target_count": 1,
  "success_count": 1,
  "failure_count": 0,
  "results": [
    {"user": "alice", "connector": "codex", "ok": true}
  ]
}
`
	if err := os.WriteFile(filepath.Join(dir, "hook_guardian_state.json"), []byte(state), 0o600); err != nil {
		t.Fatalf("write hook guardian state: %v", err)
	}

	out := captureStdout(t, printHookGuardianStatus)
	for _, want := range []string{"Hook guardian", "healthy", "1/1 targets ok", "Codex (codex) for alice", "ok"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q from hook guardian output:\n%s", want, out)
		}
	}
}

func TestIsLocalStatusTarget(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "[::1]", " [::1] ", "0.0.0.0", "::"} {
		if !isLocalStatusTarget(host) {
			t.Errorf("isLocalStatusTarget(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"gateway.example.test", "192.0.2.20", "2001:db8::20"} {
		if isLocalStatusTarget(host) {
			t.Errorf("isLocalStatusTarget(%q) = true, want false", host)
		}
	}
	if hostname, err := os.Hostname(); err == nil && !isLocalStatusTarget(hostname) {
		t.Errorf("machine hostname %q was not recognized as local", hostname)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs: %v", err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch local := addr.(type) {
		case *net.IPNet:
			ip = local.IP
		case *net.IPAddr:
			ip = local.IP
		}
		if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			if !isLocalStatusTarget(ip.String()) {
				t.Fatalf("local interface IP %s was not recognized as local", ip)
			}
			return
		}
	}
}

// TestPrintConnectorModes_ListsAll pins the "Connector Mode" fan-out: every
// active connector's mode/telemetry must render under one section header,
// not just the primary connector's.
func TestPrintConnectorModes_ListsAll(t *testing.T) {
	modes := []connectorModeSummary{
		{Connector: "codex", Mode: "observability", PolicyMode: "action", EnforcementSurface: "agent_lifecycle_hooks", Telemetry: []string{"hooks", "otel", "notify"}, ProxyIntercept: false},
		{Connector: "openclaw", Mode: "guardrail", PolicyMode: "observe", EnforcementSurface: "llm_proxy", Telemetry: []string{"hooks"}, ProxyIntercept: true},
	}

	out := captureStdout(t, func() { printConnectorModes(modes) })

	if !strings.Contains(out, "Connector Mode") {
		t.Fatalf("missing 'Connector Mode' section header:\n%s", out)
	}
	for _, name := range []string{"codex", "openclaw"} {
		if !strings.Contains(out, name) {
			t.Errorf("connector %q missing from Connector Mode section:\n%s", name, out)
		}
	}
	codexStart := strings.Index(out, "Codex (codex)")
	openClawStart := strings.Index(out, "OpenClaw (openclaw)")
	if codexStart < 0 || openClawStart < 0 || codexStart >= openClawStart {
		t.Fatalf("connector blocks missing or out of order:\n%s", out)
	}
	codexBlock := out[codexStart:openClawStart]
	openClawBlock := out[openClawStart:]
	for _, want := range []string{"direct-to-upstream", "Policy mode:", "action"} {
		if !strings.Contains(codexBlock, want) {
			t.Errorf("expected %q in Codex status block, got:\n%s", want, codexBlock)
		}
	}
	for _, want := range []string{"DefenseClaw proxy", "Policy mode:", "observe"} {
		if !strings.Contains(openClawBlock, want) {
			t.Errorf("expected %q in OpenClaw status block, got:\n%s", want, openClawBlock)
		}
	}
}

// TestPrintConnectorModes_SingleEntry confirms a single connector renders
// through the same per-entry layout (header once, one entry).
func TestPrintConnectorModes_SingleEntry(t *testing.T) {
	modes := []connectorModeSummary{
		{Connector: "codex", Mode: "observability", Telemetry: []string{"hooks"}, ProxyIntercept: false},
	}
	out := captureStdout(t, func() { printConnectorModes(modes) })
	if !strings.Contains(out, "Connector Mode") || !strings.Contains(out, "codex") {
		t.Errorf("single-entry Connector Mode render missing header/connector:\n%s", out)
	}
}

func TestPrintConnectorModes_OmnigentPolicySurface(t *testing.T) {
	modes := []connectorModeSummary{{
		Connector:          "omnigent",
		Mode:               "observability",
		PolicyMode:         "action",
		EnforcementSurface: "omnigent_policy_api",
		Telemetry:          []string{"policy-api"},
	}}

	out := captureStdout(t, func() { printConnectorModes(modes) })

	for _, want := range []string{"Data path:", "direct-to-upstream", "Policy mode:", "action", "omnigent policy api", "policy-api"} {
		if !strings.Contains(out, want) {
			t.Errorf("OmniGent status missing %q:\n%s", want, out)
		}
	}
}

// TestFetchConnectorModes_PrefersPluralFallsBackToSingular verifies the
// client reads the plural roster when present and degrades to the singular
// connector_mode for older sidecars that predate connector_modes.
func TestFetchConnectorModes_PrefersPluralFallsBackToSingular(t *testing.T) {
	t.Run("plural", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"connector_mode":{"connector":"codex","mode":"observability"},`+
				`"connector_modes":[{"connector":"codex","mode":"observability"},{"connector":"openclaw","mode":"guardrail"}]}`)
		}))
		defer srv.Close()
		bind, port := splitHostPort(t, srv.URL)
		modes := fetchConnectorModes(srv.Client(), bind, port)
		if len(modes) != 2 {
			t.Fatalf("want 2 modes from plural field, got %d: %v", len(modes), modes)
		}
	})

	t.Run("singular_fallback", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"connector_mode":{"connector":"codex","mode":"observability"}}`)
		}))
		defer srv.Close()
		bind, port := splitHostPort(t, srv.URL)
		modes := fetchConnectorModes(srv.Client(), bind, port)
		if len(modes) != 1 || modes[0].Connector != "codex" {
			t.Fatalf("want 1 fallback mode for codex, got %v", modes)
		}
	})
}
