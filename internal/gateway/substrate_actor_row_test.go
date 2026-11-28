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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// The map builders below are an independent copy of the code that list,
// status and get used before the typed rows (rel/parent 5768fe49f7:
// substrate_routes.go actorView, substratePolicyConflictView,
// substrateAttribution and substrate_activity.go substrateActivityView).
// They are the oracle of the parity tests, so they must not call the
// typed code under test (GAP-1046).

func oldAttribution(reg registry.Registration) string {
	switch {
	case reg.Attributed || reg.Person.Subject == "":
		return "atespace"
	case reg.Person.Kind == identity.PersonWorkload:
		return "workload"
	}
	return "person"
}

func oldPolicyConflictView(reg registry.Registration) map[string]any {
	if reg.PolicyConflict == nil {
		return nil
	}
	return map[string]any{
		"since": reg.PolicyConflict.Since, "reverts": reg.PolicyConflict.Reverts,
		"fix": "defenseclaw substrate policy reset " + reg.Atespace + "/" + reg.Name,
	}
}

func oldActorView(st *substrateState, reg registry.Registration) map[string]any {
	v := map[string]any{
		"atespace": reg.Atespace, "name": reg.Name, "uid": reg.UID, "registration_key": reg.Key,
		"profile": reg.Profile, "connector": reg.Connector, "template": reg.Template,
		"batch_id": reg.BatchID, "unattended": reg.Unattended, "created_at": reg.CreatedAt,
		"owner": reg.Person.Principal, "deleted": reg.Deleted,
		"attribution": oldAttribution(reg), "foreign": reg.Attributed,
	}
	if reg.Unattended {
		var rule SubstrateUnattendedAsk // no rule: deny (D12)
		if st.cfg.UnattendedAsk != nil {
			rule = st.cfg.UnattendedAsk(reg.Profile)
		}
		v["unattended_asks"] = "deny"
		if rule.Queue {
			v["unattended_asks"], v["ask_timeout_seconds"] = "queue", int64(rule.Timeout/time.Second)
		}
	}
	if pc := oldPolicyConflictView(reg); pc != nil {
		v["policy_conflict"] = pc
	}
	return v
}

type oldActivityIn struct {
	uid     string
	live    string
	snap    activity.Snapshot
	pending []asks.Ask
	now     time.Time
	window  time.Duration
	notify  bool
	detail  bool
}

func oldActivityView(in oldActivityIn) map[string]any {
	last := in.snap.Last[in.uid]
	lastKind := ""
	lastKindAt := time.Time{}
	kinds := map[string]time.Time{}
	for kind, m := range in.snap.Kinds {
		if t, ok := m[in.uid]; ok {
			kinds[kind] = t
			if t.After(lastKindAt) {
				lastKind, lastKindAt = kind, t
			}
		}
	}
	model, hook := kinds[activity.KindModel], kinds[activity.KindHook]
	ended := in.snap.Ended[in.uid]
	recent := model
	if hook.After(recent) {
		recent = hook
	}
	state := SubstrateStateIdle
	switch {
	case len(in.pending) > 0:
		state = SubstrateStateWaitingOnAsk
	case in.live == "suspended":
		state = SubstrateStateSuspended
	case !ended.IsZero() && !last.After(ended):
		state = SubstrateStateTaskDone
	case in.window > 0 && !recent.IsZero() && in.now.Sub(recent) <= in.window:
		state = SubstrateStateThinking
	}
	v := map[string]any{"state": state, "pending_asks": len(in.pending), "notify": in.notify}
	set := func(key string, t time.Time) {
		if !t.IsZero() {
			v[key] = t
		}
	}
	set("last", last)
	if lastKind != "" {
		v["last_kind"] = lastKind
	}
	set("last_model", model)
	set("last_tool", hook)
	set("attached", in.snap.Attached[in.uid])
	set("task_ended", ended)
	if in.detail && len(in.pending) > 0 {
		list := make([]map[string]any, 0, len(in.pending))
		for _, a := range in.pending {
			target := a.Host
			if a.Kind == "tool" || target == "" {
				target = a.Tool
			}
			list = append(list, map[string]any{"id": a.ID, "kind": a.Kind, "target": target, "created": a.Created})
		}
		v["asks"] = list
	}
	return v
}

// decoded is v's JSON as generic values: equal when the JSON is the same
// apart from key order.
func decoded(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func actorRegs() map[string]registry.Registration {
	created := time.Date(2026, 11, 23, 9, 12, 3, 456789000, time.UTC)
	person := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example.org", Subject: "alice", Principal: "alice@example.org"}
	workload := registry.Person{Kind: identity.PersonWorkload, Issuer: "https://ci.example.org", Subject: "repo:ci"}
	base := registry.Registration{Key: "k1", Atespace: "eng-web", Name: "a1", UID: "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", Person: person, Profile: "eng", Connector: "claudecode", Template: "t1", CreatedAt: created}
	with := func(f func(*registry.Registration)) registry.Registration { r := base; f(&r); return r }
	return map[string]registry.Registration{
		"plain":       base,
		"no template": with(func(r *registry.Registration) { r.Template, r.BatchID = "", "b-7" }),
		"unattended":  with(func(r *registry.Registration) { r.Unattended = true }),
		"queue eng":   with(func(r *registry.Registration) { r.Unattended, r.Profile = true, "queue" }),
		"queue zero":  with(func(r *registry.Registration) { r.Unattended, r.Profile = true, "queue0" }),
		"conflict": with(func(r *registry.Registration) {
			r.PolicyConflict = &registry.PolicyConflict{Since: created, Reverts: 3}
		}),
		"deleted":      with(func(r *registry.Registration) { r.Deleted = true }),
		"attributed":   with(func(r *registry.Registration) { r.Attributed, r.Person = true, registry.Person{} }),
		"workload":     with(func(r *registry.Registration) { r.Person = workload }),
		"html in name": with(func(r *registry.Registration) { r.Name, r.Template = "a<b>&c", " x\"y" }),
		"zero created": with(func(r *registry.Registration) { r.CreatedAt = time.Time{} }),
	}
}

func actorTestState() *substrateState {
	return &substrateState{cfg: SubstrateConfig{UnattendedAsk: func(profile string) SubstrateUnattendedAsk {
		switch profile {
		case "queue":
			return SubstrateUnattendedAsk{Queue: true, Timeout: 10 * time.Minute}
		case "queue0":
			return SubstrateUnattendedAsk{Queue: true}
		}
		return SubstrateUnattendedAsk{}
	}}}
}

type snapFeed struct{ snap activity.Snapshot }

func (f snapFeed) Snapshot(context.Context) (activity.Snapshot, error) { return f.snap, nil }

// activityOracle is what activityFor-and-view gives for one agent, and the
// old map builder gives for the same inputs.
func activityOracle(t *testing.T, st *substrateState, reg registry.Registration, snap activity.Snapshot, live string, pending []asks.Ask, detail bool) (*substrateActivityOut, map[string]any) {
	t.Helper()
	st.cfg.ActivityFeed = snapFeed{snap}
	r := st.activityFor(context.Background(), "", false, detail)
	if r == nil {
		t.Fatal("activityFor: nil")
	}
	pend := append([]asks.Ask(nil), pending...)
	sort.Slice(pend, func(i, j int) bool { return pend[i].Created.Before(pend[j].Created) })
	if len(pend) > 0 {
		r.pending = map[string][]asks.Ask{reg.UID: pend}
	}
	want := oldActivityView(oldActivityIn{uid: reg.UID, live: live, snap: snap, pending: pend, now: r.now, window: r.window, notify: r.notify, detail: detail})
	return r.view(reg, live), want
}

// GAP-1019, GAP-1046: list encodes typed rows; they must be the JSON the
// map of the old actorView (plus state and activity) gave, for every shape
// of actor. The oracle is a copy of the old map code, compared by decoded
// value (the key order of the typed rows differs).
func TestSubstrateActorRowMatchesView(t *testing.T) {
	created := time.Date(2026, 11, 23, 9, 12, 3, 456789000, time.UTC)
	st := actorTestState()
	act := &substrateActivityOut{State: SubstrateStateIdle, Last: created, LastKind: "hook", LastTool: created, PendingAsks: 0, Notify: true}
	oldAct := map[string]any{"state": SubstrateStateIdle, "last": created, "last_kind": "hook", "last_tool": created, "pending_asks": 0, "notify": true}
	for name, reg := range actorRegs() {
		for _, state := range []string{"", "running"} {
			for _, withAct := range []bool{false, true} {
				row := st.actorRow(reg)
				row.State = state
				want := oldActorView(st, reg)
				if state != "" {
					want["state"] = state
				}
				if withAct {
					row.Activity = act
					want["activity"] = oldAct
				}
				if got, w := decoded(t, row), decoded(t, want); !reflect.DeepEqual(got, w) {
					t.Errorf("%s (state %q, activity %v):\n row %s\n old %s", name, state, withAct, encodeJSONLine(t, row), encodeJSONLine(t, want))
				}
				// actorView (status, get) is the same object as a map.
				if got, w := decoded(t, st.actorView(reg)), decoded(t, oldActorView(st, reg)); !reflect.DeepEqual(got, w) {
					t.Errorf("%s: actorView:\n new %s\n old %s", name, encodeJSONLine(t, got), encodeJSONLine(t, w))
				}
			}
		}
	}
}

func encodeJSONLine(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// GAP-1046: the typed activity object is the JSON the old
// substrateActivityView map gave: values, omitted keys and the asks of a
// status answer, not only the key names.
func TestSubstrateActivityOutMatchesOldView(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) time.Time { return now.Add(-d).UTC().Truncate(time.Microsecond) }
	reg := actorRegs()["plain"]
	uid := reg.UID
	other := "00000000-0000-0000-0000-000000000009"
	ask := func(id, kind, host, tool string, age time.Duration) asks.Ask {
		return asks.Ask{ID: id, UID: uid, Kind: kind, Host: host, Tool: tool, Created: ago(age)}
	}
	cases := []struct {
		name    string
		snap    activity.Snapshot
		live    string
		pending []asks.Ask
		detail  bool
	}{
		{"empty snapshot", activity.Snapshot{}, "running", nil, false},
		{"model stream is thinking", activity.Snapshot{
			Last:  map[string]time.Time{uid: ago(3 * time.Second), other: ago(time.Hour)},
			Kinds: map[string]map[string]time.Time{activity.KindModel: {uid: ago(3 * time.Second)}, activity.KindHook: {uid: ago(40 * time.Second), other: ago(time.Second)}},
		}, "running", nil, false},
		{"attached and a custom kind", activity.Snapshot{
			Last:     map[string]time.Time{uid: ago(5 * time.Minute)},
			Attached: map[string]time.Time{uid: ago(time.Hour)},
			Kinds:    map[string]map[string]time.Time{activity.KindHook: {uid: ago(6 * time.Minute)}, "relay": {uid: ago(5 * time.Minute)}},
		}, "running", nil, false},
		{"task ended", activity.Snapshot{
			Last:  map[string]time.Time{uid: ago(30 * time.Second)},
			Ended: map[string]time.Time{uid: ago(5 * time.Second)},
			Kinds: map[string]map[string]time.Time{activity.KindModel: {uid: ago(time.Second)}},
		}, "running", nil, false},
		{"suspended", activity.Snapshot{Last: map[string]time.Time{uid: ago(time.Second)}}, "suspended", nil, false},
		{"pending asks, list", activity.Snapshot{Last: map[string]time.Time{uid: ago(2 * time.Second)}}, "running",
			[]asks.Ask{ask("a2", "tool", "", "Bash", time.Second), ask("a1", "egress", "api.stripe.com", "", 9*time.Second)}, false},
		{"pending asks, status", activity.Snapshot{Last: map[string]time.Time{uid: ago(2 * time.Second)}}, "running",
			[]asks.Ask{ask("a2", "tool", "h.example", "Bash", time.Second), ask("a1", "egress", "api.stripe.com", "", 9*time.Second), ask("a3", "egress", "", "Fetch", 4*time.Second)}, true},
		{"status without asks", activity.Snapshot{Last: map[string]time.Time{uid: ago(2 * time.Second)}}, "running", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := actorTestState()
			got, want := activityOracle(t, st, reg, tc.snap, tc.live, tc.pending, tc.detail)
			if g, w := decoded(t, got), decoded(t, want); !reflect.DeepEqual(g, w) {
				t.Fatalf("activity:\n new %s\n old %s", encodeJSONLine(t, got), encodeJSONLine(t, want))
			}
		})
	}
}
