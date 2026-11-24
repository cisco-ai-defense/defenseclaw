// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/notify"
)

type watchWorld struct {
	actors []api.Actor
	asks   map[string][]api.ActivityAsk // by atespace/name
}

func (w *watchWorld) list(context.Context) ([]api.Actor, error) { return w.actors, nil }
func (w *watchWorld) get(_ context.Context, atespace, name string) (api.Actor, error) {
	for _, a := range w.actors {
		if a.Atespace == atespace && a.Name == name {
			act := *a.Activity
			act.Asks = w.asks[atespace+"/"+name]
			a.Activity = &act
			return a, nil
		}
	}
	return api.Actor{}, context.Canceled
}

func watchActor(name string, act api.Activity) api.Actor {
	return api.Actor{Atespace: "dev", Name: name, Activity: &act}
}

func runWatchOnce(t *testing.T, wt *substrateWatcher, policy substrateNotifyPolicy, sent *[]notify.Notification) (string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := substrateWatchRun(context.Background(), &out, &errOut, wt, time.Second, true, policy, func(n notify.Notification) error {
		*sent = append(*sent, n)
		return nil
	}, func() time.Time { return time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), errOut.String()
}

// One notification per ask id, however many times the ask is seen; a new ask
// is notified; the text names the kind and the host, never the arguments.
func TestNotifyNewAskOnce(t *testing.T) {
	w := &watchWorld{
		actors: []api.Actor{watchActor("web", api.Activity{State: "waiting_on_ask", PendingAsks: 1})},
		asks:   map[string][]api.ActivityAsk{"dev/web": {{ID: "ask-1", Kind: "egress", Target: "api.stripe.com"}}},
	}
	wt := newSubstrateWatcher(w.list, w.get, "")
	pol := substrateNotifyPolicy{Asks: true, TaskEnd: true}
	var sent []notify.Notification
	out, _ := runWatchOnce(t, wt, pol, &sent)
	runWatchOnce(t, wt, pol, &sent)
	runWatchOnce(t, wt, pol, &sent)
	if len(sent) != 1 {
		t.Fatalf("notifications = %d, want 1 for one ask id", len(sent))
	}
	if !strings.Contains(sent[0].Body, "egress api.stripe.com") || !strings.Contains(sent[0].Title, "dev/web") {
		t.Errorf("notification = %+v", sent[0])
	}
	if !strings.Contains(out, "dev/web  needs an answer: egress api.stripe.com") {
		t.Errorf("printed line:\n%s", out)
	}
	w.asks["dev/web"] = append(w.asks["dev/web"], api.ActivityAsk{ID: "ask-2", Kind: "tool", Target: "Bash"})
	w.actors[0].Activity.PendingAsks = 2
	runWatchOnce(t, wt, pol, &sent)
	if len(sent) != 2 || !strings.Contains(sent[1].Body, "tool Bash") {
		t.Fatalf("a new ask id is notified once: %+v", sent)
	}
	// answered, then the same id does not come back as new while it stays answered
	w.asks["dev/web"], w.actors[0].Activity.PendingAsks = nil, 0
	runWatchOnce(t, wt, pol, &sent)
	if len(sent) != 2 {
		t.Fatalf("notifications = %d after the asks were answered", len(sent))
	}
}

func TestNotifyTaskEnd(t *testing.T) {
	end := time.Date(2026, 11, 23, 8, 59, 0, 0, time.UTC)
	w := &watchWorld{actors: []api.Actor{watchActor("job", api.Activity{State: "idle", TaskEnded: end.Add(-time.Hour)})}}
	wt := newSubstrateWatcher(w.list, w.get, "")
	pol := substrateNotifyPolicy{Asks: true, TaskEnd: true}
	var sent []notify.Notification
	runWatchOnce(t, wt, pol, &sent)
	if len(sent) != 0 {
		t.Fatalf("a task that ended before watch started notified: %+v", sent)
	}
	w.actors[0].Activity.TaskEnded = end
	out, _ := runWatchOnce(t, wt, pol, &sent)
	runWatchOnce(t, wt, pol, &sent)
	if len(sent) != 1 || !strings.Contains(sent[0].Title, "dev/job finished its task") {
		t.Fatalf("task end notifications = %+v", sent)
	}
	if !strings.Contains(out, "09:00:00Z  dev/job  the --task run ended") {
		t.Errorf("printed line:\n%s", out)
	}
}

// Always prints; sends nothing when the policy, the cluster's admin-off
// switch or a name filter says no.
func TestWatchNotificationGates(t *testing.T) {
	off := false
	mk := func(notifyFlag *bool) *watchWorld {
		return &watchWorld{
			actors: []api.Actor{watchActor("web", api.Activity{State: "waiting_on_ask", PendingAsks: 1, Notify: notifyFlag}), watchActor("other", api.Activity{State: "waiting_on_ask", PendingAsks: 1})},
			asks:   map[string][]api.ActivityAsk{"dev/web": {{ID: "a1", Kind: "egress", Target: "h.example"}}, "dev/other": {{ID: "a2", Kind: "egress", Target: "o.example"}}},
		}
	}
	for _, tc := range []struct {
		name     string
		w        *watchWorld
		filter   string
		pol      substrateNotifyPolicy
		wantSent int
		wantOut  string
		noOut    string
		wantErr  string
	}{
		{"on", mk(nil), "dev/web", substrateNotifyPolicy{Asks: true}, 1, "h.example", "o.example", ""},
		{"admin off for the cluster", mk(&off), "dev/web", substrateNotifyPolicy{Asks: true}, 0, "h.example", "", ""},
		{"asks off", mk(nil), "dev/web", substrateNotifyPolicy{TaskEnd: true}, 0, "h.example", "", ""},
		{"notifications off prints a plain note", mk(nil), "dev/web", substrateNotifyPolicy{Why: "notify-send is not installed"}, 0, "h.example", "", "Note: notify-send is not installed."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wt := newSubstrateWatcher(tc.w.list, tc.w.get, tc.filter)
			var sent []notify.Notification
			out, errOut := runWatchOnce(t, wt, tc.pol, &sent)
			if len(sent) != tc.wantSent {
				t.Errorf("sent = %d, want %d", len(sent), tc.wantSent)
			}
			if !strings.Contains(out, tc.wantOut) || (tc.noOut != "" && strings.Contains(out, tc.noOut)) {
				t.Errorf("out:\n%s", out)
			}
			if tc.wantErr != "" && !strings.Contains(errOut, tc.wantErr) {
				t.Errorf("err = %q, want %q", errOut, tc.wantErr)
			}
		})
	}
}

func TestSubstrateNotifierCheckOffByDefault(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = nil
	c := substrateNotifierCheck()
	if c.ID != "notifier" || (c.Status != doctorSkip) {
		t.Fatalf("check = %+v", c)
	}
}

// A missing notifier tool is one plain line and a doctor warning, never a
// crash. Windows delivery (Shell_NotifyIconW) needs no external tool, so
// there the same set-up with an empty PATH must stay ready and on: the
// test asserts that instead of skipping.
func TestWatchMissingNotifierTool(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = &config.Config{Notifications: config.NotificationsConfig{Enabled: true, Substrate: config.NotificationsSubstrateConfig{Asks: true, TaskEnd: true}}}
	t.Setenv("PATH", t.TempDir())
	c := substrateNotifierCheck()
	p := substrateNotifyPolicyNow()
	if runtime.GOOS == "windows" {
		if c.Status != doctorOK || c.Fix != "" {
			t.Fatalf("check = %+v, want OK: Windows needs no external tool", c)
		}
		if !p.Asks || !p.TaskEnd || p.Why != "" {
			t.Fatalf("policy = %+v, want asks and task_end on", p)
		}
		// the notifications.substrate switches still gate it
		cfg.Notifications.Substrate = config.NotificationsSubstrateConfig{}
		if p := substrateNotifyPolicyNow(); p.Asks || p.TaskEnd || p.Why == "" {
			t.Fatalf("policy with both switches off = %+v", p)
		}
		return
	}
	if c.Status != doctorWarn || c.Fix == "" {
		t.Fatalf("check = %+v, want a warning with a fix", c)
	}
	if p.Asks || p.TaskEnd || !strings.Contains(p.Why, "not installed") {
		t.Fatalf("policy = %+v", p)
	}
}

// GAP-1044: a poll that could not read an agent (a "-" row, a failed get)
// keeps that agent's seen ask ids; the next good poll does not notify an ask
// that stayed pending. Only a good read that no longer shows the ask, or an
// agent that is gone, forgets it.
func TestWatchKeepsSeenAsksAcrossUnreadablePolls(t *testing.T) {
	pending := api.Activity{State: "waiting_on_ask", PendingAsks: 1}
	cases := []struct {
		name string
		blip func(w *watchWorld, getFails *bool)
	}{
		{"list row without activity", func(w *watchWorld, _ *bool) { w.actors = []api.Actor{{Atespace: "dev", Name: "web"}} }},
		{"get fails", func(_ *watchWorld, getFails *bool) { *getFails = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &watchWorld{
				actors: []api.Actor{watchActor("web", pending)},
				asks:   map[string][]api.ActivityAsk{"dev/web": {{ID: "ask-1", Kind: "egress", Target: "api.stripe.com"}}},
			}
			getFails := false
			get := func(ctx context.Context, atespace, name string) (api.Actor, error) {
				if getFails {
					return api.Actor{}, context.DeadlineExceeded
				}
				return w.get(ctx, atespace, name)
			}
			wt := newSubstrateWatcher(w.list, get, "")
			pol := substrateNotifyPolicy{Asks: true, TaskEnd: true}
			var sent []notify.Notification
			runWatchOnce(t, wt, pol, &sent)
			if len(sent) != 1 {
				t.Fatalf("first poll: %d notifications, want 1", len(sent))
			}
			tc.blip(w, &getFails)
			runWatchOnce(t, wt, pol, &sent)
			w.actors, getFails = []api.Actor{watchActor("web", pending)}, false
			runWatchOnce(t, wt, pol, &sent)
			if len(sent) != 1 {
				t.Fatalf("an ask that stayed pending was notified again after an unreadable poll: %+v", sent)
			}
			// answered (a good read without it), then a new ask with the same id is new again
			w.actors[0].Activity = &api.Activity{State: "idle"}
			runWatchOnce(t, wt, pol, &sent)
			w.actors[0].Activity = &api.Activity{State: "waiting_on_ask", PendingAsks: 1}
			runWatchOnce(t, wt, pol, &sent)
			if len(sent) != 2 {
				t.Fatalf("an ask that was answered and came back was not notified again: %+v", sent)
			}
			// the agent is deleted: its ids go too
			w.actors = nil
			runWatchOnce(t, wt, pol, &sent)
			if len(wt.seenAsks) != 0 {
				t.Fatalf("seenAsks = %v after the agent was gone", wt.seenAsks)
			}
		})
	}
}
