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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// substrate-1 GAP-0677: GAP-0526 gave a crash-closed ask an audit row and a
// webhook post, but the ask's lifecycle record, log.approval.resolved, was
// still missing: a consumer that follows log.approval.requested to its
// resolution saw the ask open forever. The closure writes it with the result
// cancelled, answered by the system.
func TestGAP0677CrashClosedAskWritesApprovalResolved(t *testing.T) {
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	f := newSubstrateFixture(t)
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n    compliance.activity:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: relay-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n      send:\n        signals: [logs]\n        buckets: ['*']\n",
		fixture.dataDir, server.URL))
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)

	f.api.recordSubstrateRelay(context.Background(), telemetryrelay.TakeResponse{Records: []telemetryrelay.Record{
		{Kind: telemetryrelay.KindAskClosed, At: time.Now().UTC(), Atespace: "eng-web", Actor: "bob-1", UID: subUID2,
			AskID: "ask-closed-77", Host: "files.example.org", Reason: telemetryrelay.AskClosedActorCrashed, Profile: "eng"},
	}})

	db, err := sql.Open("sqlite", fixture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows []string
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		rows = nil
		r, err := db.Query(`SELECT projected_record_json FROM audit_events WHERE event_name = 'approval.resolved'`)
		if err != nil {
			t.Fatal(err)
		}
		for r.Next() {
			var projected string
			if err := r.Scan(&projected); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, projected)
		}
		r.Close()
		if len(rows) > 0 {
			break
		}
	}
	if len(rows) != 1 {
		t.Fatalf("a crash-closed ask wrote %d log.approval.resolved records, want 1", len(rows))
	}
	for _, want := range []string{"ask-closed-77", "cancelled", "automatic", "files.example.org", "bob-1"} {
		if !strings.Contains(rows[0], want) {
			t.Errorf("the record lacks %q: %s", want, rows[0])
		}
	}
}

// substrate-1 GAP-0678: the webhook cooldown keyed a closure by target and
// action, so a second ask closed for the same host within the cooldown (two
// actors asked for it, then crashed together) was dropped as a duplicate.
// Each closed ask is its own notice; a repeat of the same record is still
// one.
func TestGAP0678TwoClosedAsksForOneHostBothReachTheWebhook(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	hook := newCollector()
	defer hook.Close()
	d := newTestDispatcher([]config.WebhookConfig{{URL: hook.URL(), Type: "generic", MinSeverity: "HIGH", Enabled: true}})
	defer d.Close()
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, &config.Config{DataDir: t.TempDir()})
	api.SetWebhookSource(func() *WebhookDispatcher { return d })

	closed := func(ask, actor string) telemetryrelay.Record {
		return telemetryrelay.Record{Kind: telemetryrelay.KindAskClosed, At: time.Now().UTC(), Atespace: "eng-web", Actor: actor,
			UID: subUID2, AskID: ask, Host: "example.com", Reason: telemetryrelay.AskClosedActorCrashed, Unattended: true, Severity: "MEDIUM"}
	}
	api.recordSubstrateRelay(context.Background(), telemetryrelay.TakeResponse{Records: []telemetryrelay.Record{
		closed("ask-1", "bob-1"), closed("ask-2", "carol-1"), closed("ask-1", "bob-1"),
	}})
	for end := time.Now().Add(5 * time.Second); hook.count() < 2 && time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
	}
	time.Sleep(300 * time.Millisecond) // a wrongly delivered repeat would land too
	if got := hook.count(); got != 2 {
		t.Fatalf("the webhook got %d closure posts, want 2: one per ask, the repeat of ask-1 suppressed", got)
	}
}
