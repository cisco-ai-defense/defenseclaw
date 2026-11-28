//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// substrate-1 GAP-0526: an ask the leader closed because its actor crashed
// left no audit row and no webhook post. The replica that takes the
// leader's ask_closed record writes an audit row with the reason code and
// tells the webhooks of an unattended run's ask (the ones that heard of it
// being queued, a HIGH endpoint included, as GAP-0557).
func TestGAP0526CrashClosedAskIsAuditedAndPosted(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	high := newCollector()
	defer high.Close()
	listed := newCollector()
	defer listed.Close()
	d := newTestDispatcher([]config.WebhookConfig{
		{URL: high.URL(), Type: "generic", MinSeverity: "HIGH", Enabled: true},
		{URL: listed.URL(), Type: "generic", MinSeverity: "CRITICAL", Events: []string{"approval-request"}, Enabled: true},
	})
	defer d.Close()
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, &config.Config{DataDir: t.TempDir()})
	api.SetWebhookSource(func() *WebhookDispatcher { return d })

	api.recordSubstrateRelay(context.Background(), telemetryrelay.TakeResponse{Records: []telemetryrelay.Record{
		{Kind: telemetryrelay.KindAskClosed, At: time.Now().UTC(), Atespace: "eng-web", Actor: "bob-1", UID: subUID2,
			AskID: "ask-7", Host: "example.com", Reason: telemetryrelay.AskClosedActorCrashed, Unattended: true, Severity: "MEDIUM"},
	}})

	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	audited := false
	for _, e := range events {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "ask-7") && strings.Contains(string(raw), "actor_crashed") {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("no audit row names the closed ask and actor_crashed: %d events", len(events))
	}
	for end := time.Now().Add(5 * time.Second); (high.count() < 1 || listed.count() < 1) && time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
	}
	for name, c := range map[string]*webhookCollector{"HIGH": high, "approval-request": listed} {
		got := c.get()
		if len(got) != 1 {
			t.Fatalf("%s endpoint got %d posts, want the closure", name, len(got))
		}
		body, _ := json.Marshal(got[0].Body)
		if !strings.Contains(string(body), "reason=actor_crashed") || !strings.Contains(string(body), `"action":"approval-closed"`) {
			t.Fatalf("%s endpoint post does not name the closure: %s", name, body)
		}
	}
}
