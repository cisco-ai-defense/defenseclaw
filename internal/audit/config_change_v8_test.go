// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// testConfigChangePins is a record pin folder of its own.
func testConfigChangePins(t *testing.T) *ConfigChangePins {
	t.Helper()
	return NewConfigChangePins(filepath.Join(t.TempDir(), "change-record-pins"))
}

const (
	testConfigChangeID = "c-01JB8Z4X6T2Q9V3M5N7P1R0S4W"
	// testChangedAt is the time of every test change.
	testChangedAt = "2026-10-21T10:00:00Z"
)

func TestLogConfigChangeRecordsEachFamily(t *testing.T) {
	sum, previous := strings.Repeat("a", 64), strings.Repeat("b", 64)
	cases := []struct {
		name    string
		change  ConfigChange
		event   string
		outcome observability.Outcome
		want    []string
		absent  []string
	}{
		{"anchors replaced", ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
			Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SHA256: sum, PreviousSHA256: previous,
			KeyIDsAdded: []string{"fleet-2026-11"}, KeyIDsRemoved: []string{"fleet-2026-10"}},
			observability.TelemetryEventConfigTrustAnchorsChanged, observability.OutcomeApplied,
			[]string{`"defenseclaw.trust_anchors.sha256":"` + sum + `"`, `"defenseclaw.trust_anchors.previous_sha256":"` + previous + `"`,
				`"defenseclaw.trust_anchors.key_ids.added":["fleet-2026-11"]`, `"defenseclaw.trust_anchors.key_ids.removed":["fleet-2026-10"]`,
				`"defenseclaw.config.change.id":"` + testConfigChangeID + `"`, `"defenseclaw.admin.actor_ref":"os:uid:0:root"`},
			[]string{"defenseclaw.config.change.reason_code"}},
		{"anchors refused", ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
			Outcome: ConfigChangeRefused, ReasonCode: "anchor_invalid", Actor: "os:uid:0:root", SHA256: previous},
			observability.TelemetryEventConfigTrustAnchorsChanged, observability.OutcomeRejected,
			[]string{`"defenseclaw.config.change.reason_code":"anchor_invalid"`}, nil},
		{"credential set", ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
			Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"},
			observability.TelemetryEventConfigSecretChanged, observability.OutcomeApplied,
			[]string{`"defenseclaw.secret.name":"splunk-hec-token"`, `"defenseclaw.secret.action":"set"`}, nil},
		{"credential removal failed", ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "remove",
			Outcome: ConfigChangeFailed, ReasonCode: "change_failed", Actor: "os:uid:0:root", SecretName: "splunk-hec-token"},
			observability.TelemetryEventConfigSecretChangeFailed, observability.OutcomeFailed,
			[]string{`"defenseclaw.secret.action":"remove"`, `"defenseclaw.config.change.reason_code":"change_failed"`}, nil},
		{"credential name refused", ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
			Outcome: ConfigChangeRefused, ReasonCode: "invalid_arguments", Actor: "os:uid:0:root"},
			observability.TelemetryEventConfigSecretChangeFailed, observability.OutcomeRejected,
			[]string{`"defenseclaw.config.change.reason_code":"invalid_arguments"`}, []string{"defenseclaw.secret.name"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			if err := logger.LogConfigChange(tc.change, nil, testConfigChangePins(t)); err != nil {
				t.Fatalf("LogConfigChange: %v", err)
			}
			_, records := runtime.snapshot()
			if len(records) != 1 || records[0].EventName() != observability.EventName(tc.event) ||
				records[0].Outcome() != tc.outcome || !records[0].Mandatory() {
				t.Fatalf("records = %d %v", len(records), records)
			}
			assertRecordMatchesRuntimeContract(t, records[0])
			encoded, err := records[0].Bytes()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(encoded), want) {
					t.Fatalf("record lacks %s: %s", want, encoded)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(string(encoded), absent) {
					t.Fatalf("record has %s: %s", absent, encoded)
				}
			}
		})
	}
}

func TestLogConfigChangeRefusesMalformedChanges(t *testing.T) {
	logger := newTestLogger(t)
	logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
	for name, change := range map[string]ConfigChange{
		"no id":            {Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied, SecretName: "a"},
		"unknown kind":     {EventID: testConfigChangeID, Kind: "token", Action: "set", Outcome: ConfigChangeApplied},
		"failed, no code":  {EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeFailed, SecretName: "a"},
		"applied, no name": {EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied},
		"anchor set":       {EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "set", Outcome: ConfigChangeApplied},
	} {
		if err := logger.LogConfigChange(change, nil, testConfigChangePins(t)); err == nil {
			t.Fatalf("%s: LogConfigChange accepted %+v", name, change)
		}
	}
}

// The gateway marks a change event reported only once the audit store and
// every remote destination have it; until then, and after a restart, it
// offers it again. The store keeps each change event id once: a later offer
// (in the same process or after the restart) writes nothing, records no
// metric again and sends the record to the remote destinations again.
func TestLogConfigChangeRecordsEachChangeOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	change := ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"}
	pins := testConfigChangePins(t)
	for run, want := range [][]bool{{false, true}, {true, true}} {
		store, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Init(); err != nil {
			t.Fatal(err)
		}
		logger := NewLogger(store)
		runtime := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
		logger.SetRuntimeV8Emitter(runtime)
		metrics := -1
		for offer := 0; offer < 2; offer++ {
			if err := logger.LogConfigChange(change, nil, pins); err != nil {
				t.Fatalf("run %d offer %d: %v", run, offer, err)
			}
			if metrics >= 0 && len(runtime.metricSnapshot()) != metrics {
				t.Fatalf("run %d: an offer of a stored change recorded metrics again", run)
			}
			metrics = len(runtime.metricSnapshot())
		}
		if run > 0 && metrics != 0 {
			t.Fatalf("run %d: a restart recorded the metrics of a stored change again", run)
		}
		runtime.mu.Lock()
		stored := append([]bool(nil), runtime.skippedLocalWrite...)
		runtime.mu.Unlock()
		if fmt.Sprint(stored) != fmt.Sprint(want) {
			t.Fatalf("run %d offers that skipped the local write = %v, want %v", run, stored, want)
		}
		var rows int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`,
			string(ActionConfigSecretChanged)).Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("run %d: %d stored rows (%v), want 1", run, rows, err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// An audit store that cannot be read is an error, so the gateway offers the
// change again rather than marking it reported.
func TestLogConfigChangeFailsWhileTheStoreIsClosed(t *testing.T) {
	logger := newTestLogger(t)
	logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
	if err := logger.store.Close(); err != nil {
		t.Fatal(err)
	}
	change := ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
		Outcome: ConfigChangeRefused, ReasonCode: "lifecycle_busy", Actor: "os:uid:0:root"}
	if err := logger.LogConfigChange(change, nil, testConfigChangePins(t)); err == nil {
		t.Fatal("LogConfigChange succeeded with the audit store closed")
	}
}

// The activity counters of a change carry one fixed actor label for every
// kind and outcome. The OS account (a Windows administrator SID and name,
// or a uid and user name) stays in the audit record and enters no metric
// label. Before, it was the actor label of defenseclaw.activity.total and
// defenseclaw.activity.diff_entries.
func TestLogConfigChangeKeepsTheAccountOffTheCounters(t *testing.T) {
	const sid, account = "S-1-5-21-1004336348-1177238915-682003330-500", "CORP/Administrator"
	for name, change := range map[string]ConfigChange{
		"anchors installed": {Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeApplied,
			SHA256: strings.Repeat("a", 64)},
		"anchors refused": {Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeRefused,
			ReasonCode: "anchor_invalid"},
		"credential set": {Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied,
			SecretName: "splunk-hec-token"},
		"credential removal interrupted": {Kind: ConfigChangeSecret, Action: "remove", Outcome: ConfigChangeFailed,
			ReasonCode: "interrupted", SecretName: "otlp-token"},
		"credential name refused": {Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeRefused,
			ReasonCode: "invalid_arguments"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, actor := range []string{"os:sid:" + sid + ":" + account, "os:uid:0:root"} {
				change.EventID, change.Actor, change.ChangedAt = testConfigChangeID, actor, testChangedAt
				logger := newTestLogger(t)
				runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
				logger.SetRuntimeV8Emitter(runtime)
				if err := logger.LogConfigChange(change, nil, testConfigChangePins(t)); err != nil {
					t.Fatalf("LogConfigChange: %v", err)
				}
				_, records := runtime.snapshot()
				if len(records) != 1 {
					t.Fatalf("records = %d", len(records))
				}
				if encoded, err := records[0].Bytes(); err != nil ||
					!strings.Contains(string(encoded), `"defenseclaw.admin.actor_ref":"`+actor+`"`) {
					t.Fatalf("the audit record lost the actor %s: %s %v", actor, encoded, err)
				}
				activity := 0
				for _, metric := range runtime.metricSnapshot() {
					encoded, err := metric.Bytes()
					if err != nil {
						t.Fatal(err)
					}
					for _, part := range []string{sid, account, "Administrator", "root", "uid:0", actor} {
						if strings.Contains(string(encoded), part) {
							t.Fatalf("metric %s carries %q: %s", metric.EventName(), part, encoded)
						}
					}
					switch metric.EventName() {
					case observability.EventName(observability.TelemetryInstrumentDefenseClawActivityTotal),
						observability.EventName(observability.TelemetryInstrumentDefenseClawActivityDiffEntries):
						activity++
						if !strings.Contains(string(encoded), `"defenseclaw.metric.actor":"`+configChangeMetricActor+`"`) {
							t.Fatalf("metric %s actor label is not %s: %s", metric.EventName(), configChangeMetricActor, encoded)
						}
					}
				}
				if activity != 2 {
					t.Fatalf("activity counters = %d, want 2", activity)
				}
			}
		})
	}
}

// LogConfigChange returns nil only once the change's row survives a power
// loss: the pool commits with synchronous=NORMAL, so after the row is
// stored, or found stored (a stopped process may have left it in the page
// cache), it commits once on the durable connection (synchronous=FULL,
// fullfsync), which flushes the whole log. A failed flush is an error, so
// the gateway does not count the store as having the change; it offers the
// change again, and the destinations are sinks of their own that do not
// wait on the flush. Before, LogConfigChange returned after the NORMAL
// commit and the gateway wrote its durable marker for a row a power loss
// could still take back.
func TestLogConfigChangeSucceedsOnlyOnceTheRowIsPowerLossDurable(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	generation := func() int64 {
		t.Helper()
		var value int64
		if err := logger.store.db.QueryRow(`SELECT verification_generation
			FROM observability_store_readiness WHERE id = 1`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	change := ConfigChange{ChangedAt: testChangedAt, EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"}
	if _, err := logger.store.db.Exec(`CREATE TRIGGER audit_flush_fails BEFORE UPDATE ON observability_store_readiness
		BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`); err != nil {
		t.Fatal(err)
	}
	delivery, pins := observability.NewRemoteDelivery(), testConfigChangePins(t)
	for offer := 0; offer < 2; offer++ {
		if err := logger.LogConfigChange(change, delivery, pins); err == nil {
			t.Fatalf("offer %d succeeded although its row could not be flushed", offer)
		}
	}
	runtime.mu.Lock()
	stored := append([]bool(nil), runtime.skippedLocalWrite...)
	runtime.mu.Unlock()
	if fmt.Sprint(stored) != "[false true]" {
		t.Fatalf("offers that skipped the local write = %v, want the row written once and found once", stored)
	}
	if _, err := logger.store.db.Exec(`DROP TRIGGER audit_flush_fails`); err != nil {
		t.Fatal(err)
	}
	before := generation()
	for offer := 0; offer < 2; offer++ {
		if err := logger.LogConfigChange(change, delivery, pins); err != nil {
			t.Fatalf("offer %d after the flush recovered: %v", offer, err)
		}
		if got := generation(); got != before+int64(offer)+1 {
			t.Fatalf("offer %d: %d durable commits in all, want one per offer", offer, got-before)
		}
	}
}

// The durable connection runs the audit pragmas with only synchronous
// raised to FULL and fullfsync on (F_FULLFSYNC on macOS): automatic
// checkpoints stay off, as on every audit connection.
func TestAuditDurableConnectionFlushesEveryCommit(t *testing.T) {
	logger := newTestLogger(t)
	db, err := logger.store.durableConn()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"synchronous": 2, "fullfsync": 1}
	for _, pragma := range auditMandatoryIntegerPragmas {
		if _, set := want[pragma.name]; !set {
			want[pragma.name] = pragma.want
		}
	}
	for name, value := range want {
		var got int64
		if err := db.QueryRow("PRAGMA " + name).Scan(&got); err != nil || got != value {
			t.Fatalf("PRAGMA %s = %d (%v), want %d", name, got, err, value)
		}
	}
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q (%v), want wal", mode, err)
	}
	if err := logger.store.Close(); err != nil {
		t.Fatal(err)
	}
	if logger.store.durableDB != nil {
		t.Fatal("Close kept the durable connection")
	}
}
