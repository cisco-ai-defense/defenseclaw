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
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
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
// (activity.Reader, one leader call per DefaultSnapshotTTL). It is best
// effort and must answer at once: a leader that cannot be reached is an
// error, never a wait (GAP-1018).
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

// The pending asks of a list or status come from the leader too. Like the
// snapshot (activity.Reader) the read is best effort (GAP-1018): one attempt
// that ends within substrateActivityAsksWait, and a failure is remembered
// for substrateActivityAsksBackoff, so callers do not wait on a leader that
// cannot be reached. The answer then carries no activity ("-").
var (
	substrateActivityAsksWait    = 500 * time.Millisecond
	substrateActivityAsksBackoff = 10 * time.Second
)

// substrateActivityAsksDown is when the last pending-asks read failed (unix
// nanoseconds, 0: it did not).
type substrateActivityAsksDown struct{ at atomic.Int64 }

func (d *substrateActivityAsksDown) down(now time.Time) bool {
	at := d.at.Load()
	return at != 0 && now.Sub(time.Unix(0, at)) < substrateActivityAsksBackoff
}

// substrateActivityOut is the "activity" object of an actor in list and get
// (api.Activity on the launcher): state, last, last_kind, last_model,
// last_tool, attached, task_ended, pending_asks, notify and (status) asks.
// Times are the gateway's receive times (E15). A typed struct, not a map:
// list builds one per agent (GAP-1019).
type substrateActivityOut struct {
	State       string                    `json:"state"`
	Last        time.Time                 `json:"last,omitzero"`
	LastKind    string                    `json:"last_kind,omitempty"`
	LastModel   time.Time                 `json:"last_model,omitzero"`
	LastTool    time.Time                 `json:"last_tool,omitzero"`
	Attached    time.Time                 `json:"attached,omitzero"`
	TaskEnded   time.Time                 `json:"task_ended,omitzero"`
	PendingAsks int                       `json:"pending_asks"`
	Notify      bool                      `json:"notify"`
	Asks        []substrateActivityAskOut `json:"asks,omitempty"`
}

// substrateActivityAskOut is one pending ask of a status answer: its kind
// and host or tool only, never its arguments (M-DEP-13).
type substrateActivityAskOut struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Target  string    `json:"target"`
	Created time.Time `json:"created"`
}

// substrateActivityKind is one kind's times by UID, indexed once per answer.
type substrateActivityKind struct {
	name string
	at   map[string]time.Time
}

// substrateActivityReader is the activity of the agents one list or get
// answers, read once: the snapshot, its kinds in name order (so the newest
// kind of a tie is always the same one) and the pending asks by UID.
type substrateActivityReader struct {
	snap        activity.Snapshot
	kinds       []substrateActivityKind
	model, hook map[string]time.Time
	pending     map[string][]asks.Ask
	now         time.Time
	window      time.Duration
	notify      bool
	detail      bool // status: name each pending ask
}

// activityFor reads the leader's snapshot and the pending asks of the owner
// (every person's with all). nil when the cluster has no activity feed or
// the leader cannot answer now: the answer then carries no activity, and
// the launcher shows "-", never "idle". Neither read waits on a leader that
// cannot be reached (GAP-1018).
func (st *substrateState) activityFor(ctx context.Context, ownerID string, all, detail bool) *substrateActivityReader {
	if st.cfg.ActivityFeed == nil {
		return nil
	}
	snap, err := st.cfg.ActivityFeed.Snapshot(ctx)
	if err != nil {
		return nil
	}
	cfg := st.activityConfig()
	now := time.Now()
	r := &substrateActivityReader{
		snap: snap, now: now, window: cfg.EffectiveStatusWindow(), notify: cfg.NotificationsOn(), detail: detail,
		model: snap.Kinds[activity.KindModel], hook: snap.Kinds[activity.KindHook],
	}
	if len(snap.Kinds) > 0 {
		r.kinds = make([]substrateActivityKind, 0, len(snap.Kinds))
		for name, at := range snap.Kinds {
			r.kinds = append(r.kinds, substrateActivityKind{name: name, at: at})
		}
		sort.Slice(r.kinds, func(i, j int) bool { return r.kinds[i].name < r.kinds[j].name })
	}
	if st.cfg.Asks != nil {
		if st.activityAsks.down(now) {
			return nil
		}
		in := asks.ListRequest{OwnerID: ownerID, PendingOnly: true}
		if all {
			in.OwnerID, in.All = "", true
		}
		// The read does not follow the caller's cancellation (like the
		// shared activity.Reader refresh): the failure memory below is
		// gateway-wide, so one person's Ctrl-C must never set it (GAP-1043).
		// The 500 ms cap still bounds the read.
		actx, cancel := context.WithTimeout(leader.WithoutRetry(context.WithoutCancel(ctx)), substrateActivityAsksWait)
		list, err := st.cfg.Asks.List(actx, in)
		cancel()
		if err != nil {
			st.activityAsks.at.Store(time.Now().UnixNano())
			return nil
		}
		st.activityAsks.at.Store(0)
		if len(list) > 0 {
			r.pending = make(map[string][]asks.Ask, len(list))
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
func (r *substrateActivityReader) view(reg registry.Registration, live string) *substrateActivityOut {
	out := &substrateActivityOut{}
	r.fill(out, reg.UID, live)
	return out
}

// fill writes uid's activity into out.
func (r *substrateActivityReader) fill(out *substrateActivityOut, uid, live string) {
	pending := r.pending[uid]
	last := r.snap.Last[uid]
	var lastKindAt time.Time
	for _, k := range r.kinds {
		if t, ok := k.at[uid]; ok && t.After(lastKindAt) {
			out.LastKind, lastKindAt = k.name, t
		}
	}
	model, hook := r.model[uid], r.hook[uid]
	ended := r.snap.Ended[uid]
	recent := model
	if hook.After(recent) {
		recent = hook
	}

	state := SubstrateStateIdle
	switch {
	case len(pending) > 0:
		state = SubstrateStateWaitingOnAsk
	case live == "suspended":
		state = SubstrateStateSuspended
	case !ended.IsZero() && !last.After(ended):
		state = SubstrateStateTaskDone
	case r.window > 0 && !recent.IsZero() && r.now.Sub(recent) <= r.window:
		state = SubstrateStateThinking
	}
	out.State, out.PendingAsks, out.Notify = state, len(pending), r.notify
	out.Last, out.LastModel, out.LastTool = last, model, hook
	out.Attached, out.TaskEnded = r.snap.Attached[uid], ended
	if r.detail && len(pending) > 0 {
		out.Asks = make([]substrateActivityAskOut, 0, len(pending))
		for _, a := range pending {
			target := a.Host
			if a.Kind == "tool" || target == "" {
				target = a.Tool
			}
			out.Asks = append(out.Asks, substrateActivityAskOut{ID: a.ID, Kind: a.Kind, Target: target, Created: a.Created})
		}
	}
}
