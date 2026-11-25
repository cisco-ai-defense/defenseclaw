// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// substrateMetricDocRows reads the Agent Substrate metrics table of the
// telemetry reference: instrument name -> its "Recorded" cell.
func substrateMetricDocRows(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "observability", "sandbox-telemetry.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 5 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if strings.HasPrefix(name, "defenseclaw.substrate.") {
			rows[name] = strings.TrimSpace(cells[3])
		}
	}
	if len(rows) != 8 {
		t.Fatalf("the docs list %d defenseclaw.substrate.* metrics, want the 8 of the registry: %v", len(rows), rows)
	}
	return rows
}

// GAP-0401, GAP-0450: every defenseclaw.substrate.* metric the docs say a
// component records is recorded, through the gateway's telemetry runtime
// (the OTLP path), when its event happens: the gateway's own four, and the
// controller's three relayed through the leader. A metric no component
// records says so in the docs. Before, none of the eight was ever recorded
// while the docs listed all eight as emitted.
func TestGAP0401DocumentedSubstrateMetricsAreRecorded(t *testing.T) {
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Limiter = ratelimit.New(ratelimit.Config{PerActorRPS: 1, PerAtespaceRPS: 1000})
		c.Chains = &chainstate.Client{}
		c.Profiles = func(_ identity.Person, _, _ string, _ bool) (string, string, error) {
			return "eng", "eng-web", nil
		}
	})
	f.api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	f.api.substrateState().cfg.Actions = &fakeActions{f: f}

	// first_hook_after_resume: the controller saw the actor suspended, so
	// its next hook call is its first after the resume (GAP-0486).
	// The leader decides it once this replica synced twice (GAP-0486).
	relayStore, relayClient := substrateRelayLeader(t)
	relayTaker := &telemetryrelay.Taker{Leader: relayClient, Record: f.api.recordSubstrateRelay}
	f.api.substrateState().cfg.Relay = relayTaker
	relayStore.Add(telemetryrelay.Record{Kind: telemetryrelay.KindLifecycle, Lifecycle: chainstate.LifecycleSuspended, At: time.Now().Add(-time.Second),
		Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Connector: "claudecode"})
	for range 2 {
		if err := relayTaker.TakeOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// A hook call, then one over the actor's budget.
	f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice",
		envelope("claudecode", map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "list the files", "session_id": "m1", "cwd": "/work/app"}))
	for i := 0; i < 4; i++ {
		f.do(t, f.actor, http.MethodGet, "/api/v1/substrate/hook/claudecode", "tok-alice", "", substrateWarmHeader, "1")
	}
	// A tool-chain step sent to the leader (none answers here).
	b, err := f.api.substrateState().cfg.Chains.Bind(chainstate.Actor{Atespace: "eng-web", UID: subUID1}, chainstate.ScopeSession, "claudecode", "m1", "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = b.Observe(context.Background(), audit.ToolChainObserveInput{})
	// The controller's counts and gauge, through the leader (GAP-0450).
	relayStore.Add(
		telemetryrelay.Record{Kind: telemetryrelay.KindCount, Metric: telemetryrelay.MetricIdleSuspends, Value: 1},
		telemetryrelay.Record{Kind: telemetryrelay.KindCount, Metric: telemetryrelay.MetricPolicyConflicts, Value: 1},
		telemetryrelay.Record{Kind: telemetryrelay.KindGauge, Metric: telemetryrelay.MetricUnattestedTemplates, Value: 0},
	)
	if err := relayTaker.TakeOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A launcher create.
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"claude-wave1","connector":"claudecode"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}

	got := map[string]int{}
	for _, m := range capture.metricSnapshot() {
		if name := m.Descriptor().Name; strings.HasPrefix(name, "defenseclaw.substrate.") {
			got[name]++
			for k := range m.Attributes() {
				t.Errorf("%s carries attribute %s; Substrate metrics have no labels", name, k)
			}
		}
	}
	for name, recorded := range substrateMetricDocRows(t) {
		switch {
		case strings.HasPrefix(recorded, "By the gateway"):
			if got[name] == 0 {
				t.Errorf("the docs say the gateway records %s, and it recorded none (recorded: %v)", name, got)
			}
		case strings.HasPrefix(recorded, "Not recorded"):
			if got[name] != 0 {
				t.Errorf("the docs say %s is not recorded, and the gateway recorded it", name)
			}
		default:
			t.Errorf("the docs row of %s neither names who records it nor says it is not recorded: %q", name, recorded)
		}
	}
	if got["defenseclaw.substrate.hook_rtt"] != 1 {
		t.Errorf("hook_rtt recorded %d times for one hook call (warm-up pings are not hook calls)", got["defenseclaw.substrate.hook_rtt"])
	}
}
