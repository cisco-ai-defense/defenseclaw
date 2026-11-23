// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller/controllerfake"
)

// attachFeed is an activity feed that also reports terminal attachments
// (the gateway's attach reports through the leader).
type attachFeed struct {
	*controllerfake.Activity
	at map[string]time.Time
}

func (f *attachFeed) Attached(uid string) (time.Time, bool) { t, ok := f.at[uid]; return t, ok }

// blindFeed reports activity but cannot tell attachments (a feed older
// than GAP-0534).
type blindFeed struct{ f *controllerfake.Activity }

func (b blindFeed) LastActivity(uid string) (time.Time, bool) { return b.f.LastActivity(uid) }
func (b blindFeed) PendingAsk(uid string) bool                { return b.f.PendingAsk(uid) }

func gap0534State(r *rig, a *ateapi.Actor) ateapi.ActorState {
	got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
	return got.GetStatus().GetState()
}

// substrate-1 GAP-0534 (PLAN E4): without a CPU source (every chart
// install) 7abaca4d93 suspended an actor after idle_suspend_after with no
// hook, model or relay traffic, so a busy but quiet actor (a long build the
// person watches in an attached terminal) was suspended mid-work. Without
// a CPU source only positive evidence of idleness counts: no terminal
// attached, and the window runs from the last attachment too.
func TestGAP0534AttachedQuietActorKeptWithoutCPUSource(t *testing.T) {
	feed := &attachFeed{at: map[string]time.Time{}}
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		feed.Activity = o.Activity.(*controllerfake.Activity)
		o.Activity, o.CPU = feed, nil
	})
	attached := r.actor("eng-web", "attached-build", ateapi.ActorStateRunning, "sub-a")
	leftRecently := r.actor("eng-web", "detached-20m", ateapi.ActorStateRunning, "sub-b")
	leftLongAgo := r.actor("eng-web", "detached-40m", ateapi.ActorStateRunning, "sub-c")
	never := r.actor("eng-web", "never-attached", ateapi.ActorStateRunning, "sub-d")
	r.pass()
	start := r.clk.Now()
	for _, a := range []*ateapi.Actor{attached, leftRecently, leftLongAgo, never} {
		r.act.Touch(a.GetMetadata().GetUid(), start.Add(time.Second))
	}
	r.clk.Add(2 * time.Hour)
	now := r.clk.Now()
	feed.at[attached.GetMetadata().GetUid()] = now.Add(-time.Minute)          // open: reported a minute ago
	feed.at[leftRecently.GetMetadata().GetUid()] = now.Add(-20 * time.Minute) // closed 20 min ago
	feed.at[leftLongAgo.GetMetadata().GetUid()] = now.Add(-40 * time.Minute)  // closed 40 min ago
	r.pass()

	for name, a := range map[string]*ateapi.Actor{"attached, quiet for 2 h": attached, "detached 20 min ago": leftRecently} {
		if s := gap0534State(r, a); s != ateapi.ActorStateRunning {
			t.Errorf("%s: %s without a CPU source (a busy attached actor must not be idle-suspended)", name, s)
		}
	}
	for name, a := range map[string]*ateapi.Actor{"detached 40 min ago": leftLongAgo, "never attached": never} {
		if s := gap0534State(r, a); s != ateapi.ActorStateSuspended {
			t.Errorf("%s: %s, want suspended (no attachment, no activity for idle_suspend_after)", name, s)
		}
	}
}

// substrate-1 GAP-0534: without a CPU source, an actor is idle only on
// positive evidence. A feed that cannot tell attachments, or one that never
// heard of the actor, makes nothing idle; a wired CPU source keeps the
// last word.
func TestGAP0534UnknownAttachmentOrActivityIsNotIdleWithoutCPUSource(t *testing.T) {
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		o.Activity, o.CPU = blindFeed{o.Activity.(*controllerfake.Activity)}, nil
	})
	heard := r.actor("eng-web", "heard-quiet", ateapi.ActorStateRunning, "sub-a")
	unknown := r.actor("eng-web", "never-heard", ateapi.ActorStateRunning, "sub-b")
	r.pass()
	r.act.Touch(heard.GetMetadata().GetUid(), r.clk.Now().Add(time.Second))
	r.clk.Add(2 * time.Hour)
	r.pass()
	for name, a := range map[string]*ateapi.Actor{"attachments unknown": heard, "activity unknown": unknown} {
		if s := gap0534State(r, a); s != ateapi.ActorStateRunning {
			t.Errorf("%s: %s without a CPU source", name, s)
		}
	}

	// A CPU source decides: attached or not, a low fresh sample is idle.
	feed := &attachFeed{at: map[string]time.Time{}}
	c := newRig(t, func(_ *config.Config, o *controller.Options) {
		feed.Activity = o.Activity.(*controllerfake.Activity)
		o.Activity = feed
	})
	a := c.actor("eng-web", "attached-low-cpu", ateapi.ActorStateRunning, "sub-a")
	c.pass()
	uid := a.GetMetadata().GetUid()
	c.act.Touch(uid, c.clk.Now().Add(time.Second))
	c.clk.Add(time.Hour)
	feed.at[uid] = c.clk.Now()
	c.act.SetCPU(uid, 0.01, c.clk.Now())
	c.pass()
	if s := gap0534State(c, a); s != ateapi.ActorStateSuspended {
		t.Fatalf("with a CPU source a low sample is idle, attached or not: %s", s)
	}
}
