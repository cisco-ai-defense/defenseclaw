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
	"context"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// What an agent is doing (B3.6), as `substrate list` and `substrate status`
// show it. The state comes from data the leader already keeps (the last hook,
// model and relay call, the --task end, the open attachment and the pending
// asks); nothing here is read from the actor and nothing is on the hook path.
const (
	SubstrateStateThinking     = "thinking"
	SubstrateStateWaitingOnAsk = "waiting_on_ask"
	SubstrateStateIdle         = "idle"
	SubstrateStateSuspended    = "suspended"
	SubstrateStateTaskDone     = "task_done"
)

// SubstrateActivityFeed is the leader's activity snapshot with per-kind times
// (activity.Reader, one leader call per DefaultSnapshotTTL).
type SubstrateActivityFeed interface {
	Snapshot(ctx context.Context) (activity.Snapshot, error)
}

// substrateModelReportEvery is how often an open model stream is re-reported
// as activity, so a long answer still shows the agent as thinking.
var substrateModelReportEvery = 10 * time.Second

// substrateReportOpenModel reports model activity of uid every
// substrateModelReportEvery until stop is called. The first report is the
// request itself, made by the caller.
func substrateReportOpenModel(sink SubstrateActivitySink, atespace, uid string) (stop func()) {
	var (
		mu      sync.Mutex
		t       *time.Timer
		stopped bool
	)
	mu.Lock()
	t = time.AfterFunc(substrateModelReportEvery, func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		sink.ObserveActivity(SubstrateActivityModel, atespace, uid, time.Now())
		t.Reset(substrateModelReportEvery)
	})
	mu.Unlock()
	return func() {
		mu.Lock()
		stopped = true
		t.Stop()
		mu.Unlock()
	}
}

func (st *substrateState) activityConfig() config.SubstrateActivityConfig {
	if st.cfg.ActivityConfig != nil {
		return st.cfg.ActivityConfig()
	}
	return config.SubstrateActivityConfig{}
}

// substrateActivityIn is what one agent's activity view is made of.
type substrateActivityIn struct {
	uid     string
	live    string // the lower-case live state, "" when unknown
	snap    activity.Snapshot
	pending []asks.Ask
	now     time.Time
	window  time.Duration
	notify  bool
	detail  bool // status: name each pending ask
}

// substrateActivityView is the "activity" object of an actor in list and
// get: state, last, last_kind, last_model, last_tool, attached, task_ended,
// pending_asks and (detail) asks. Times are the gateway's receive times
// (E15). An ask shows its kind and host or tool only, never its arguments
// (M-DEP-13).
func substrateActivityView(in substrateActivityIn) map[string]any {
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

// substrateActivityReader is the activity of the agents one list or get
// answers, read once.
type substrateActivityReader struct {
	in      substrateActivityIn
	pending map[string][]asks.Ask
}

// activityFor reads the leader's snapshot and the pending asks of the owner
// (every person's with all). nil when the cluster has no activity feed or
// the leader cannot answer: the answer then carries no activity, and the
// launcher shows "-", never "idle".
func (st *substrateState) activityFor(ctx context.Context, ownerID string, all, detail bool) *substrateActivityReader {
	if st.cfg.ActivityFeed == nil {
		return nil
	}
	snap, err := st.cfg.ActivityFeed.Snapshot(ctx)
	if err != nil {
		return nil
	}
	cfg := st.activityConfig()
	r := &substrateActivityReader{
		in:      substrateActivityIn{snap: snap, now: time.Now(), window: cfg.EffectiveStatusWindow(), notify: cfg.NotificationsOn(), detail: detail},
		pending: map[string][]asks.Ask{},
	}
	if st.cfg.Asks != nil {
		in := asks.ListRequest{OwnerID: ownerID, PendingOnly: true}
		if all {
			in.OwnerID, in.All = "", true
		}
		if list, err := st.cfg.Asks.List(ctx, in); err == nil {
			for _, a := range list {
				r.pending[a.UID] = append(r.pending[a.UID], a)
			}
			for uid := range r.pending {
				l := r.pending[uid]
				sort.Slice(l, func(i, j int) bool { return l[i].Created.Before(l[j].Created) })
			}
		}
	}
	return r
}

// view is reg's activity object; live is its lower-case live state.
func (r *substrateActivityReader) view(reg registry.Registration, live string) map[string]any {
	in := r.in
	in.uid, in.live, in.pending = reg.UID, live, r.pending[reg.UID]
	return substrateActivityView(in)
}
