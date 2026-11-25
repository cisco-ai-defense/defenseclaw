// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
	_ "modernc.org/sqlite"
)

// substrateRelayLeader is a leader serving the telemetry relay, and a client.
func substrateRelayLeader(t *testing.T) (*telemetryrelay.Store, *leader.Client) {
	t.Helper()
	store := &telemetryrelay.Store{ResumeWarmup: -1} // a leader past its GAP-0486 warm-up
	srv := &leader.Server{IsLeader: func() bool { return true }}
	telemetryrelay.Serve(srv, store)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return store, &leader.Client{BaseURL: hs.URL, HTTP: hs.Client()}
}

// GAP-0450: the controller's counts and its unattested-template gauge reach
// the metrics runtime: posted to the leader, taken and recorded by a gateway
// replica. Before, the controller had no export path and none was recorded.
func TestGAP0450ControllerCountsReachTheMetricsRuntime(t *testing.T) {
	_, client := substrateRelayLeader(t)
	poster := &telemetryrelay.Poster{Leader: client, Method: telemetryrelay.MethodPostCounts}
	poster.Add(
		telemetryrelay.Record{Kind: telemetryrelay.KindCount, Metric: telemetryrelay.MetricIdleSuspends, Value: 1},
		telemetryrelay.Record{Kind: telemetryrelay.KindCount, Metric: telemetryrelay.MetricPolicyConflicts, Value: 2},
		telemetryrelay.Record{Kind: telemetryrelay.KindGauge, Metric: telemetryrelay.MetricUnattestedTemplates, Value: 5},
		telemetryrelay.Record{Kind: telemetryrelay.KindGauge, Metric: telemetryrelay.MetricUnattestedTemplates, Value: 3},
	)
	if err := poster.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	taker := &telemetryrelay.Taker{Leader: client, Record: api.recordSubstrateRelay}
	if err := taker.TakeOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A second replica takes no count again, but reports the gauge.
	other, otherCapture := newProxyGeneratedMetricRuntime(t)
	api2 := &APIServer{}
	api2.bindObservabilityV8Runtimes(other, nil, nil, other)
	if err := (&telemetryrelay.Taker{Leader: client, Record: api2.recordSubstrateRelay}).TakeOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	value := func(c *proxyCanonicalCapture, name string) string {
		ms := generatedMetricByName(c.metricSnapshot(), name)
		if len(ms) != 1 {
			return fmt.Sprintf("%d points", len(ms))
		}
		if v, ok := ms[0].Value().Int64(); ok {
			return fmt.Sprint(v)
		}
		v, _ := ms[0].Value().Double()
		return fmt.Sprint(v)
	}
	for name, want := range map[string]string{
		observability.TelemetryInstrumentDefenseClawSubstrateIdleSuspends:        "1",
		observability.TelemetryInstrumentDefenseClawSubstratePolicyConflicts:     "2",
		observability.TelemetryInstrumentDefenseClawSubstrateUnattestedTemplates: "3",
	} {
		if got := value(capture, name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	if got := value(otherCapture, observability.TelemetryInstrumentDefenseClawSubstrateIdleSuspends); got != "0 points" {
		t.Errorf("a second replica recorded the count again: %s", got)
	}
	if got := value(otherCapture, observability.TelemetryInstrumentDefenseClawSubstrateUnattestedTemplates); got != "3" {
		t.Errorf("a second replica reports the gauge as %s, want 3", got)
	}
}

// GAP-0453: a Substrate install with an OTLP destination gets the actors'
// lifecycle, the callout's egress decisions and the asks as generated log
// families (log.sandbox.lifecycle, log.egress.*, log.approval.*), with the
// Substrate attributes. Before, they were only JSON lines in pod logs.
func TestGAP0453SubstrateRecordsReachTheTelemetryRuntime(t *testing.T) {
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	store := asks.NewMemory()
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks = asksDirect{store} })
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n    agent.lifecycle:\n      collect: {logs: true, traces: true, metrics: true}\n    network.egress:\n      collect: {logs: true, traces: true, metrics: true}\n    compliance.activity:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: relay-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n      send:\n        signals: [logs]\n        buckets: ['*']\n",
		fixture.dataDir, server.URL))
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)

	// The callout's decisions and the controller's lifecycle events, through
	// the leader to this replica.
	relayStore, client := substrateRelayLeader(t)
	now := time.Now().UTC()
	relayStore.Add(
		telemetryrelay.Record{Kind: telemetryrelay.KindLifecycle, At: now, Lifecycle: chainstate.LifecycleResumed,
			Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Profile: "eng", Template: "eng-web/claude", Connector: "claudecode", RunMode: "interactive"},
		telemetryrelay.Record{Kind: telemetryrelay.KindLifecycle, At: now, Lifecycle: chainstate.LifecycleSuspended,
			Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Profile: "eng", Connector: "claudecode"},
		telemetryrelay.Record{Kind: telemetryrelay.KindEgress, At: now, Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Profile: "eng",
			Host: "pypi.org", Path: "/simple/", Decision: "allow"},
		telemetryrelay.Record{Kind: telemetryrelay.KindEgress, At: now, Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Profile: "eng",
			Host: "evil.example.com", Decision: "block", Category: "chain_egress", Reason: "a secret was read"},
	)
	if err := (&telemetryrelay.Taker{Leader: client, Record: f.api.recordSubstrateRelay}).TakeOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An ask the callout raises, and a person's answer.
	rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout,
		`{"actor":{"atespace":"eng-web","name":"alice-1"},"host":"files.example.org","rule":"ask_hosts:files.example.org"}`,
		"X-DefenseClaw-Client", "substrate-extproc")
	if rec.Code != http.StatusOK {
		t.Fatalf("ask %d %s", rec.Code, rec.Body)
	}
	list, _ := store.List(context.Background(), asks.ListRequest{All: true})
	if len(list) != 1 {
		t.Fatalf("asks %v", list)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/asks/"+list[0].ID, "p-alice", `{"decision":"approve"}`); rec.Code != http.StatusOK {
		t.Fatalf("approve %d %s", rec.Code, rec.Body)
	}

	db, err := sql.Open("sqlite", fixture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var got map[string][]string
	deadline := time.Now().Add(10 * time.Second)
	for {
		got = map[string][]string{}
		rows, err := db.Query(`SELECT event_name, projected_record_json FROM audit_events`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var name, projected string
			if err := rows.Scan(&name, &projected); err != nil {
				t.Fatal(err)
			}
			got[name] = append(got[name], projected)
		}
		rows.Close()
		if len(got["sandbox.lifecycle"]) >= 2 && len(got["approval.resolved"]) >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// And the same families leave over OTLP. The exporter sends them in
	// batches, so the wait is for every family the test asserts: it stopped
	// at three of the five, and approval.resolved, the last record written,
	// could still be in the next batch (rel-1-0-10:GAP-1325).
	families := []string{"sandbox.lifecycle", "egress.allowed", "egress.blocked", "approval.requested", "approval.resolved"}
	otlp := ""
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		otlp = fmt.Sprint(capture.logSnapshot())
		all := true
		for _, name := range families {
			all = all && strings.Contains(otlp, name)
		}
		if all {
			break
		}
	}
	for _, name := range families {
		if !strings.Contains(otlp, name) {
			t.Errorf("no %s record reached the OTLP destination", name)
		}
	}
	for family, want := range map[string][]string{
		"sandbox.lifecycle":  {`"substrate"`, "alice-1", "eng-web", `"suspended"`},
		"egress.allowed":     {"pypi.org", `"substrate"`, "alice-1"},
		"egress.blocked":     {"evil.example.com", "chain_egress", `"substrate"`},
		"approval.requested": {"files.example.org", "alice-1", `"substrate"`},
		"approval.resolved":  {list[0].ID},
	} {
		joined := strings.Join(got[family], "\n")
		if joined == "" {
			t.Errorf("no %s record (families: %v)", family, keysOf(got))
			continue
		}
		for _, w := range want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s records lack %s:\n%s", family, w, joined)
			}
		}
	}
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
