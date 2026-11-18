// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// TestHostPlaneGatesAShellThatOnlyNamesAnMCPServer is GAP-1163 through the
// whole consumer: a login shell running python3 -c with an argument that
// names an MCP server has no agent above it, so it is gated and produces no
// finding. A server an agent really starts is still reported.
func TestHostPlaneGatesAShellThatOnlyNamesAnMCPServer(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	source := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 100, PPID: 1, Name: "bash", Cmdline: "-bash", At: base},
		plane.Event{Kind: plane.KindExec, PID: 101, PPID: 100, Name: "python3",
			Cmdline: "python3 -c import time; time.sleep(45) mcp-server-dccert", At: base.Add(time.Second)},
		plane.Event{Kind: plane.KindExec, PID: 102, PPID: 100, Name: "cat",
			Cmdline: "cat /srv/dccert/mcp-server-dccert.json", At: base.Add(2 * time.Second)},
	)
	host := newHost(source)
	drainInto(t, host, source, 2)
	if classified, gated, _, _ := host.stats(); classified != 0 || gated != 2 {
		t.Fatalf("classified=%d gated=%d, want 0 classified and both gated", classified, gated)
	}
	if findings := host.harvest(base.Add(time.Minute), scoring.DefaultMinRiskToReport); len(findings) != 0 {
		t.Fatalf("a shell with no agent above it produced %d findings (first agent %q)",
			len(findings), findings[0].AgentName)
	}

	underAgent := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 200, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
		plane.Event{Kind: plane.KindExec, PID: 201, PPID: 200, Name: "npx",
			Cmdline: "npx -y @modelcontextprotocol/server-filesystem /tmp", At: base.Add(time.Second)},
	)
	agentHost := newHost(underAgent)
	drainInto(t, agentHost, underAgent, 1)
	// An MCP server is an agent process in its own right, so the server is
	// the root of its finding; what matters here is that it is reported.
	findings := agentHost.harvest(base.Add(time.Minute), 0)
	if len(findings) != 1 || findings[0].AgentName == "" {
		t.Fatalf("server started by an agent: %d findings, want one attributed finding", len(findings))
	}
}
