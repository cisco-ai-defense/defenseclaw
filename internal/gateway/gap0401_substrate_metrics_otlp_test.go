// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// substrateMetricsOTLPRaw is the gateway config the Substrate reference
// tells an operator to add ("Turn on OTLP export": one OTLP destination
// and nothing else), plus a 1 s export interval so the test is quick.
func substrateMetricsOTLPRaw(dataDir, endpoint string) []byte {
	return []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\nobservability:\n  defaults:\n    redaction_profile: sensitive\n  local:\n    max_store_mb: 1024\n  metric_policy:\n    export_interval_seconds: 1\n  destinations:\n    - name: my-collector\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n",
		dataDir, endpoint))
}

// GAP-0401: every defenseclaw.substrate.* metric the docs say the gateway
// records leaves the replica over a real OTLP destination (the bootstrap
// runtime, its metric reader and the OTLP exporter, no capture runtime),
// with no identity label, and the one the docs call not recorded does not.
// This is the only metrics path of a Substrate replica: its probe port
// serves /healthz and /readyz, and no /metrics page.
func TestGAP0401SubstrateMetricsLeaveThroughTheOTLPExporter(t *testing.T) {
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 9, "")
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Limiter = ratelimit.New(ratelimit.Config{PerActorRPS: 1, PerAtespaceRPS: 1000})
		c.Chains = &chainstate.Client{}
		c.Profiles = func(_ identity.Person, _, _ string, _ bool) (string, string, error) {
			return "eng", "eng-web", nil
		}
	})
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath,
		substrateMetricsOTLPRaw(fixture.dataDir, server.URL)); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)
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
	// hook_rtt: a hook call; rate_limited: warm-up pings over the budget.
	f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice",
		envelope("claudecode", map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "list the files", "session_id": "m1", "cwd": "/work/app"}))
	for i := 0; i < 4; i++ {
		f.do(t, f.actor, http.MethodGet, "/api/v1/substrate/hook/claudecode", "tok-alice", "", substrateWarmHeader, "1")
	}
	// leader_observe_latency: a tool-chain step sent to the leader.
	b, err := f.api.substrateState().cfg.Chains.Bind(chainstate.Actor{Atespace: "eng-web", UID: subUID1}, chainstate.ScopeSession, "claudecode", "m1", "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = b.Observe(context.Background(), audit.ToolChainObserveInput{})
	// idle_suspends, policy_conflicts, unattested_templates: the
	// controller's counts and gauge through the leader.
	relayStore.Add(
		telemetryrelay.Record{Kind: telemetryrelay.KindCount, Metric: telemetryrelay.MetricIdleSuspends, Value: 1},
		telemetryrelay.Record{Kind: telemetryrelay.KindCount, Metric: telemetryrelay.MetricPolicyConflicts, Value: 1},
		telemetryrelay.Record{Kind: telemetryrelay.KindGauge, Metric: telemetryrelay.MetricUnattestedTemplates, Value: 2},
	)
	if err := relayTaker.TakeOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// policy_lag: a launcher create.
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"claude-wave1","connector":"claudecode"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}

	docs := substrateMetricDocRows(t)
	want := map[string]bool{}
	for name, recorded := range docs {
		if strings.HasPrefix(recorded, "By the gateway") {
			want[name] = true
		}
	}
	got := map[string]bool{}
	labelled := map[string]bool{}
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, requests := capture.snapshot()
		for _, request := range requests {
			for _, rm := range request.GetResourceMetrics() {
				for _, sm := range rm.GetScopeMetrics() {
					for _, m := range sm.GetMetrics() {
						if !strings.HasPrefix(m.GetName(), "defenseclaw.substrate.") {
							continue
						}
						got[m.GetName()] = true
						for _, attrs := range substrateOTLPPointAttributes(m) {
							if attrs > 0 {
								labelled[m.GetName()] = true
							}
						}
					}
				}
			}
		}
		done := true
		for name := range want {
			done = done && got[name]
		}
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("the docs say the gateway records %s; no point of it reached the OTLP destination (got %v)", name, got)
		}
	}
	for name, recorded := range docs {
		if strings.HasPrefix(recorded, "Not recorded") && got[name] {
			t.Errorf("the docs say %s is not recorded, and it reached the OTLP destination", name)
		}
	}
	for name := range labelled {
		t.Errorf("%s left with point attributes; Substrate metrics carry no labels", name)
	}
}

// substrateOTLPPointAttributes returns the attribute count of every data
// point of m, whatever its type.
func substrateOTLPPointAttributes(m *metricspb.Metric) []int {
	var out []int
	for _, p := range m.GetSum().GetDataPoints() {
		out = append(out, len(p.GetAttributes()))
	}
	for _, p := range m.GetGauge().GetDataPoints() {
		out = append(out, len(p.GetAttributes()))
	}
	for _, p := range m.GetHistogram().GetDataPoints() {
		out = append(out, len(p.GetAttributes()))
	}
	for _, p := range m.GetExponentialHistogram().GetDataPoints() {
		out = append(out, len(p.GetAttributes()))
	}
	return out
}

// GAP-0401: every defenseclaw_substrate_* series the Substrate agents board
// and the chart's alert rules query is a metric the docs say the gateway
// records. Before, the board had a "First hook after resume" panel on a
// metric no component records (sandbox-telemetry.mdx: not recorded in this
// release), so it was always empty.
func TestGAP0401BoardAndAlertsQueryOnlyRecordedSubstrateMetrics(t *testing.T) {
	docs := substrateMetricDocRows(t)
	series := regexp.MustCompile(`defenseclaw_substrate_[a-z_]+`)
	for _, file := range []string{
		filepath.Join("..", "..", "bundles", "local_observability_stack", "grafana", "dashboards", "defenseclaw-substrate.json"),
		filepath.Join("..", "..", "deploy", "helm", "defenseclaw-substrate", "templates", "prometheusrule.yaml"),
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, s := range series.FindAllString(string(raw), -1) {
			name := strings.TrimPrefix(s, "defenseclaw_substrate_")
			for _, suffix := range []string{"_milliseconds_bucket", "_seconds_bucket", "_total"} {
				name = strings.TrimSuffix(name, suffix)
			}
			name = "defenseclaw.substrate." + name
			recorded, ok := docs[name]
			switch {
			case !ok:
				t.Errorf("%s queries %s, which is no documented Substrate metric", filepath.Base(file), s)
			case !strings.HasPrefix(recorded, "By the gateway"):
				t.Errorf("%s queries %s, and the docs say %s is not recorded: %q", filepath.Base(file), s, name, recorded)
			}
			seen++
		}
		if seen == 0 {
			t.Errorf("%s queries no defenseclaw_substrate_* series", filepath.Base(file))
		}
	}
}
