// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
	_ "modernc.org/sqlite"
)

// substrate-1:GAP-0581. The leader keeps an egress refusal of an actor it
// has no registration for (deleted, never registered, or a lookup outage
// at the callout) without a UID or profile, marked Unregistered.
// log.egress.blocked says so in defenseclaw.sandbox.substrate.registered,
// true for a record the leader tied to a registration.
func TestGAP0581EgressRecordsSayWhetherTheActorIsRegistered(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	f := newSubstrateFixture(t)
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n    network.egress:\n      collect: {logs: true, traces: true, metrics: true}\n",
		fixture.dataDir))
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.bindAPIServerObservabilityV8(f.api)
	now := time.Now().UTC()
	f.api.recordSubstrateRelay(context.Background(), telemetryrelay.TakeResponse{Records: []telemetryrelay.Record{
		{Kind: telemetryrelay.KindEgress, At: now, Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Profile: "eng",
			Host: "alice.example.com", Decision: "block", Category: "operator_block"},
		{Kind: telemetryrelay.KindEgress, At: now, Atespace: "eng-web", Actor: "deleted-1", Unregistered: true,
			Host: "deleted.example.com", Decision: "block", Category: "actor_not_live"},
	}})

	db, err := sql.Open("sqlite", fixture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var blocked []string
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		blocked = blocked[:0]
		rows, err := db.Query(`SELECT projected_record_json FROM audit_events WHERE event_name = 'egress.blocked'`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var projected string
			if err := rows.Scan(&projected); err != nil {
				t.Fatal(err)
			}
			blocked = append(blocked, projected)
		}
		rows.Close()
		if len(blocked) >= 2 || time.Now().After(end) {
			break
		}
	}
	if len(blocked) != 2 {
		t.Fatalf("egress.blocked records = %d, want 2: %v", len(blocked), blocked)
	}
	for host, want := range map[string]bool{"alice.example.com": true, "deleted.example.com": false} {
		found := false
		for _, rec := range blocked {
			if !strings.Contains(rec, host) {
				continue
			}
			found = true
			var doc any
			if err := json.Unmarshal([]byte(rec), &doc); err != nil {
				t.Fatal(err)
			}
			got, ok := gap0581Attr(doc, "defenseclaw.sandbox.substrate.registered")
			if !ok || got != want {
				t.Errorf("%s: defenseclaw.sandbox.substrate.registered = %v (present %t), want %t:\n%s", host, got, ok, want, rec)
			}
			if !want && (strings.Contains(rec, subUID1) || strings.Contains(rec, "ate.actor.uid")) {
				t.Errorf("%s: an unregistered record carries an actor UID:\n%s", host, rec)
			}
		}
		if !found {
			t.Errorf("no egress.blocked record for %s: %v", host, blocked)
		}
	}
}

// gap0581Attr finds key anywhere in a decoded JSON document.
func gap0581Attr(doc any, key string) (any, bool) {
	switch v := doc.(type) {
	case map[string]any:
		if got, ok := v[key]; ok {
			return got, true
		}
		for _, c := range v {
			if got, ok := gap0581Attr(c, key); ok {
				return got, true
			}
		}
	case []any:
		for _, c := range v {
			if got, ok := gap0581Attr(c, key); ok {
				return got, true
			}
		}
	}
	return nil, false
}
