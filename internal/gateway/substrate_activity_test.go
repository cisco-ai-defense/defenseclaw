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

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

type fakeActivityFeed struct {
	snap activity.Snapshot
	err  error
}

func (f *fakeActivityFeed) Snapshot(context.Context) (activity.Snapshot, error) { return f.snap, f.err }

func activityOf(t *testing.T, body []byte, name string) map[string]any {
	t.Helper()
	var list struct {
		Actors []map[string]any `json:"actors"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("list body: %v %s", err, body)
	}
	for _, a := range list.Actors {
		if a["name"] == name {
			act, _ := a["activity"].(map[string]any)
			return act
		}
	}
	t.Fatalf("actor %s not listed: %s", name, body)
	return nil
}

// B3.6: the list shows what each agent is doing, from the leader's activity
// snapshot and the pending asks. A person's own agents only; no feed (or a
// leader that cannot answer) means no activity object, never "idle".
func TestListActivityState(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	for _, tc := range []struct {
		name  string
		snap  activity.Snapshot
		live  string
		ask   bool
		want  string
		extra func(t *testing.T, a map[string]any)
	}{
		{"model stream just seen is thinking",
			activity.Snapshot{Last: map[string]time.Time{subUID1: ago(4 * time.Second)}, Kinds: map[string]map[string]time.Time{activity.KindModel: {subUID1: ago(4 * time.Second)}}},
			"running", false, SubstrateStateThinking, func(t *testing.T, a map[string]any) {
				if a["last_kind"] != "model" || a["last_model"] == nil {
					t.Errorf("last_kind/last_model = %v/%v", a["last_kind"], a["last_model"])
				}
			}},
		{"old activity is idle",
			activity.Snapshot{Last: map[string]time.Time{subUID1: ago(10 * time.Minute)}, Kinds: map[string]map[string]time.Time{activity.KindHook: {subUID1: ago(10 * time.Minute)}}},
			"running", false, SubstrateStateIdle, nil},
		{"never active is idle", activity.Snapshot{}, "running", false, SubstrateStateIdle, nil},
		{"a pending ask is waiting_on_ask",
			activity.Snapshot{Last: map[string]time.Time{subUID1: ago(2 * time.Second)}, Kinds: map[string]map[string]time.Time{activity.KindHook: {subUID1: ago(2 * time.Second)}}},
			"running", true, SubstrateStateWaitingOnAsk, func(t *testing.T, a map[string]any) {
				if a["pending_asks"] != float64(1) {
					t.Errorf("pending_asks = %v", a["pending_asks"])
				}
				if _, ok := a["asks"]; ok {
					t.Error("list carries asks[]; only status does")
				}
			}},
		{"a suspended agent is suspended", activity.Snapshot{Last: map[string]time.Time{subUID1: ago(time.Second)}}, "suspended", false, SubstrateStateSuspended, nil},
		{"the --task run ended",
			activity.Snapshot{Last: map[string]time.Time{subUID1: ago(30 * time.Second)}, Ended: map[string]time.Time{subUID1: ago(5 * time.Second)}, Kinds: map[string]map[string]time.Time{activity.KindModel: {subUID1: ago(time.Second)}}},
			"running", false, SubstrateStateTaskDone, func(t *testing.T, a map[string]any) {
				if a["task_ended"] == nil {
					t.Error("task_ended missing")
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := asks.NewMemory()
			feed := &fakeActivityFeed{snap: tc.snap}
			f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks = asksDirect{store}; c.ActivityFeed = feed })
			f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: identity.ActorState(strings.ToUpper(tc.live))}
			if tc.ask {
				if _, err := store.OpenAsk(context.Background(), asks.Ask{Atespace: "eng-web", Actor: "alice-1", UID: subUID1, OwnerID: alice.ID(), Kind: "egress", Host: "files.example.org", Summary: "SECRET-ARGS-token=abc", Created: now}); err != nil {
					t.Fatal(err)
				}
			}
			rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("list %d %s", rec.Code, rec.Body)
			}
			a := activityOf(t, rec.Body.Bytes(), "alice-1")
			if a == nil || a["state"] != tc.want {
				t.Fatalf("activity = %v, want state %s", a, tc.want)
			}
			if tc.extra != nil {
				tc.extra(t, a)
			}
			if _, joined := func() (any, bool) {
				var l struct {
					Actors []map[string]any `json:"actors"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &l)
				for _, x := range l.Actors {
					if x["name"] == "bob-1" {
						return x, true
					}
				}
				return nil, false
			}(); joined {
				t.Error("alice's list names bob's agent")
			}
			// status carries the pending ask, with its host, never its summary.
			rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-1", "p-alice", "")
			var one map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("get %d %s", rec.Code, rec.Body)
			}
			ga, _ := one["activity"].(map[string]any)
			if ga["state"] != tc.want {
				t.Errorf("get state = %v, want %s", ga["state"], tc.want)
			}
			if tc.ask {
				list, _ := ga["asks"].([]any)
				if len(list) != 1 {
					t.Fatalf("get asks = %v", ga["asks"])
				}
				row, _ := list[0].(map[string]any)
				if row["target"] != "files.example.org" || row["kind"] != "egress" || row["id"] == "" {
					t.Errorf("ask row = %v", row)
				}
				if raw := rec.Body.String(); strings.Contains(raw, "SECRET-ARGS") {
					t.Error("status leaks the ask summary")
				}
			}
		})
	}
}

func TestListActivityAbsentWithoutFeed(t *testing.T) {
	for _, tc := range []struct {
		name string
		feed SubstrateActivityFeed
	}{{"no feed", nil}, {"leader cannot answer", &fakeActivityFeed{err: errors.New("down")}}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.ActivityFeed = tc.feed })
			rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
			if a := activityOf(t, rec.Body.Bytes(), "alice-1"); a != nil {
				t.Fatalf("activity = %v, want none", a)
			}
		})
	}
}

// status_window 0s turns the thinking state off: a stream seconds old reads idle.
func TestActivityStatusWindowOffIsNeverThinking(t *testing.T) {
	now := time.Now()
	feed := &fakeActivityFeed{snap: activity.Snapshot{Last: map[string]time.Time{subUID1: now}, Kinds: map[string]map[string]time.Time{activity.KindModel: {subUID1: now}}}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.ActivityFeed = feed
		c.ActivityConfig = func() config.SubstrateActivityConfig { return config.SubstrateActivityConfig{StatusWindow: "0s"} }
	})
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
	if a := activityOf(t, rec.Body.Bytes(), "alice-1"); a["state"] != SubstrateStateIdle {
		t.Fatalf("state = %v, want idle with status_window 0s", a["state"])
	}
}

type countSink struct {
	mu sync.Mutex
	n  int
}

func (s *countSink) ObserveActivity(string, string, string, time.Time) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}
func (s *countSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.n }

// An open model stream is re-reported on a timer until it ends; stopping it
// ends the reports, and the timer is only made when the caller asks (status_window > 0).
func TestSubstrateReportOpenModelTicksUntilStopped(t *testing.T) {
	old := substrateModelReportEvery
	substrateModelReportEvery = 10 * time.Millisecond
	defer func() { substrateModelReportEvery = old }()
	sink := &countSink{}
	stop := substrateReportOpenModel(sink, "eng-web", subUID1)
	deadline := time.Now().Add(2 * time.Second)
	for sink.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if sink.count() < 3 {
		t.Fatalf("reports = %d, want >= 3 while open", sink.count())
	}
	stop()
	n := sink.count()
	time.Sleep(60 * time.Millisecond)
	if sink.count() != n {
		t.Fatalf("reports continued after stop: %d -> %d", n, sink.count())
	}
}
