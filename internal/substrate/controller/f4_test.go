// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// cachedRegistry is the controller's view of the leader registry the way
// registry.Remote gives it: a miss is cached for a second (on the rig
// clock), GetFresh reads past it, and down makes every read fail.
type cachedRegistry struct {
	inner *controller.MemoryRegistry
	now   func() time.Time

	mu     sync.Mutex
	misses map[string]time.Time
	down   bool
}

func (c *cachedRegistry) Get(ctx context.Context, atespace, uid string) (controller.Registration, bool, error) {
	c.mu.Lock()
	if c.down {
		c.mu.Unlock()
		return controller.Registration{}, false, errors.New("leader: transport: connection refused")
	}
	if at, ok := c.misses[atespace+"/"+uid]; ok && c.now().Sub(at) < time.Second {
		c.mu.Unlock()
		return controller.Registration{}, false, nil
	}
	c.mu.Unlock()
	r, ok, err := c.inner.Get(ctx, atespace, uid)
	if err == nil && !ok {
		c.cacheMiss(atespace, uid)
	}
	return r, ok, err
}

func (c *cachedRegistry) GetFresh(ctx context.Context, atespace, uid string) (controller.Registration, bool, error) {
	c.mu.Lock()
	delete(c.misses, atespace+"/"+uid)
	c.mu.Unlock()
	return c.Get(ctx, atespace, uid)
}

func (c *cachedRegistry) Put(ctx context.Context, r controller.Registration) error {
	c.mu.Lock()
	down := c.down
	c.mu.Unlock()
	if down {
		return errors.New("leader: transport: connection refused")
	}
	return c.inner.Put(ctx, r)
}

func (c *cachedRegistry) cacheMiss(atespace, uid string) {
	c.mu.Lock()
	if c.misses == nil {
		c.misses = map[string]time.Time{}
	}
	c.misses[atespace+"/"+uid] = c.now()
	c.mu.Unlock()
}

func (c *cachedRegistry) setDown(d bool) { c.mu.Lock(); c.down = d; c.mu.Unlock() }

func cachedRig(t *testing.T, mutate func(*controller.Options)) (*rig, *cachedRegistry) {
	t.Helper()
	var cr *cachedRegistry
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		cr = &cachedRegistry{inner: o.Registry.(*controller.MemoryRegistry), now: o.Now}
		o.Registry = cr
		if mutate != nil {
			mutate(o)
		}
	})
	return r, cr
}

// launcherCreate is the gateway's create path (substrateCreateActor): the
// actor exists SUSPENDED before its registration is written.
func launcherCreate(r *rig, name string) *ateapi.Actor {
	r.t.Helper()
	if !r.tmpls["eng-web"] {
		r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "claude"}})
		r.tmpls["eng-web"] = true
	}
	a, err := r.api.CreateActor(context.Background(), &ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: name},
		ActorTemplate: ateapi.Ref("eng-web", "claude")})
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

func register(r *rig, a *ateapi.Actor, person string) {
	r.t.Helper()
	if err := r.reg.Put(context.Background(), controller.Registration{Atespace: a.GetMetadata().GetAtespace(), Name: a.GetMetadata().GetName(),
		UID: a.GetMetadata().GetUid(), Person: person, Profile: "eng", Source: controller.SourceLauncher}); err != nil {
		r.t.Fatal(err)
	}
}

// GAP-0145: the controller loop sees a launcher actor between CreateActor
// and the registration write. It is held, not called foreign, and the
// policy the create path then writes is kept.
func TestLauncherCreateRaceIsNotForeign(t *testing.T) {
	r, _ := cachedRig(t, nil)
	ctx := context.Background()
	a := launcherCreate(r, "alice-1")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass() // the loop wins the race: no registration yet
	if ev := r.sink.Events(controller.EventForeignActor); len(ev) != 0 {
		t.Fatalf("a just-created launcher actor was called foreign: %+v", ev)
	}
	// The gateway writes the registration, the policy, then resumes.
	register(r, a, "sub-alice")
	if err := r.ctl.EnsurePolicy(ctx, ref); err != nil {
		t.Fatalf("create path refused: %v", err)
	}
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	r.clk.Add(250 * time.Millisecond)
	r.pass()
	if p := r.api.Policy(ref); p == nil || !hasHost(p, "github.com") {
		t.Fatalf("the create path's policy was removed: %v", p)
	}
	if ev := r.sink.Events(controller.EventForeignActor); len(ev) != 0 {
		t.Fatalf("foreign events after the registration landed: %+v", ev)
	}
	if ev := r.sink.Events(controller.EventInventory); len(ev) != 1 || ev[0].Detail["person_bound"] != true {
		t.Fatalf("inventory = %+v (want one, person bound)", ev)
	}
}

// GAP-0145: a miss cached from the create gap is stale once the gateway has
// written the registration; the controller re-reads before it says foreign.
func TestStaleMissIsReadAgainBeforeForeign(t *testing.T) {
	r, cr := cachedRig(t, nil)
	a := launcherCreate(r, "alice-2")
	ref := ateapi.RefOf(a.GetMetadata())
	r.clk.Add(20 * time.Second) // a slow create: past the launcher grace
	cr.cacheMiss("eng-web", a.GetMetadata().GetUid())
	register(r, a, "sub-alice")
	r.pass()
	if ev := r.sink.Events(controller.EventForeignActor); len(ev) != 0 {
		t.Fatalf("called foreign on a stale cached miss: %+v", ev)
	}
	if r.api.Policy(ref) == nil {
		t.Fatal("no policy for a registered launcher actor")
	}
}

// The grace is bounded: an actor nobody registers is foreign once it ends.
func TestUnregisteredLauncherActorIsForeignAfterTheGrace(t *testing.T) {
	r, _ := cachedRig(t, nil)
	a := launcherCreate(r, "intruder-2")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if len(r.sink.Events(controller.EventForeignActor)) != 0 {
		t.Fatal("foreign inside the grace")
	}
	r.clk.Add(16 * time.Second)
	r.pass()
	ev := r.sink.Events(controller.EventForeignActor)
	if len(ev) != 1 || ev[0].Signal == nil || ev[0].Signal.SignalID != controller.SignalForeignActor {
		t.Fatalf("events = %+v", ev)
	}
	if r.api.Policy(ref) != nil {
		t.Fatal("a foreign actor has a policy")
	}
}

// GAP-0145: while the leader is down, a registered actor keeps DefenseClaw's
// policy and a foreign widening is reverted; past the outage grace the
// controller holds.
func TestLeaderOutageStillRevertsForeignEdits(t *testing.T) {
	r, cr := cachedRig(t, nil)
	a := r.actor("eng-web", "alice-3", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	want := r.want(ref)
	if got := r.api.Policy(ref); got == nil || !hasHost(got, "github.com") {
		t.Fatalf("first policy %v", got)
	}
	cr.setDown(true)
	if err := r.api.ForeignSetPolicy(ref, append(want.GetRules(), &ateapi.EgressRule{Https: &ateapi.HttpsRule{Hostnames: []string{"exfil.example.test"}}})); err != nil {
		t.Fatal(err)
	}
	r.clk.Add(31 * time.Second) // past the registration TTL: the leader is read
	r.pass()
	if hasHost(r.api.Policy(ref), "exfil.example.test") {
		t.Fatal("a foreign widening stayed while the leader was down")
	}
	var warned bool
	for _, e := range r.sink.Events(controller.EventWarning) {
		warned = warned || strings.Contains(e.Message, "using the actor's last registration")
	}
	if !warned {
		t.Fatal("no warning that the last registration is in use")
	}
	r.clk.Add(16 * time.Minute)
	if err := r.ctl.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "holding") {
		t.Fatalf("past the outage grace: %v, want a hold", err)
	}
}

// GAP-0141: a revert the controller saw only as RUNNING -> SUSPENDED (no new
// snapshot generation) or CRASHED -> SUSPENDED is sent as reverted; a real
// suspend stays suspended.
func TestRevertSeenOnlyAsItsOutcome(t *testing.T) {
	life := &lifeRec{}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.Lifecycle = life })
	a := r.actor("eng-web", "alice-4", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	step := func(f func() error) {
		t.Helper()
		r.clk.Add(time.Second)
		if err := f(); err != nil {
			t.Fatal(err)
		}
		r.pass()
	}
	step(func() error { return r.api.Revert(ref) })                               // reverted
	step(func() error { return r.api.SetState(ref, ateapi.ActorStateRunning) })   // resumed
	step(func() error { return r.api.SetState(ref, ateapi.ActorStateSuspended) }) // suspended (new generation)
	step(func() error { return r.api.SetState(ref, ateapi.ActorStateRunning) })   // resumed
	step(func() error { return r.api.SetState(ref, ateapi.ActorStateCrashed) })   // crashed
	step(func() error { return r.api.Revert(ref) })                               // reverted
	want := []string{"reverted", "resumed", "suspended", "resumed", "crashed", "reverted"}
	if got := life.names(); !slices.Equal(got, want) {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}
}

// GAP-0141: the fork event (the leader copies the parent's windows) is not
// lost when the leader is down on the first pass that sees the fork.
func TestForkEventSurvivesAFailedFirstPass(t *testing.T) {
	life := &lifeRec{}
	r, cr := cachedRig(t, func(o *controller.Options) { o.Lifecycle = life })
	p := r.actor("eng-web", "alice-5", ateapi.ActorStateRunning, "sub-alice")
	pref := ateapi.RefOf(p.GetMetadata())
	r.pass()
	if err := r.api.SetState(pref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	child, err := r.api.Fork(pref, "t5", "alice-5-fork")
	if err != nil {
		t.Fatal(err)
	}
	cr.setDown(true)
	_ = r.ctl.Reconcile(context.Background()) // the child's attribution fails
	cr.setDown(false)
	r.clk.Add(time.Second)
	r.pass()
	want := "forked<" + p.GetMetadata().GetUid()
	if !slices.Contains(life.names(), want) {
		t.Fatalf("lifecycle = %v, want %s", life.names(), want)
	}
	n := 0
	for _, e := range life.evs {
		if e.Event == "forked" {
			n++
			if e.Actor.UID != child.GetMetadata().GetUid() {
				t.Fatal("the fork event names the wrong actor")
			}
		}
	}
	r.pass()
	if n != 1 || strings.Count(strings.Join(life.names(), ","), "forked") != 1 {
		t.Fatalf("fork events %d, lifecycle %v", n, life.names())
	}
}

// GAP-0142: a delete marks the registration deleted before the leader is
// told, so the leader purges only a deleted registration's chain state; a
// failed tombstone write keeps the event for the next pass.
func TestDeleteTombstonesTheRegistrationFirst(t *testing.T) {
	store := &leaderStore{m: map[string]registry.Registration{}}
	life := &lifeRec{}
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		o.Registry, o.Lifecycle = &controller.LeaderRegistry{Store: store}, life
	})
	a := r.actor("eng-web", "alice-6", ateapi.ActorStateRunning, "")
	uid := a.GetMetadata().GetUid()
	if err := store.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "alice-6", UID: uid,
		Person: registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "sub-alice"}, Profile: "eng",
		Connector: "claudecode", Template: "eng-web/claude", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if _, err := r.api.DeleteActor(context.Background(), ateapi.RefOf(a.GetMetadata()), nil); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.down = true
	store.mu.Unlock()
	_ = r.ctl.Reconcile(context.Background())
	if slices.Contains(life.names(), "deleted") {
		t.Fatal("deleted sent before the registration was marked deleted")
	}
	store.mu.Lock()
	store.down = false
	store.mu.Unlock()
	r.pass()
	if !slices.Contains(life.names(), "deleted") {
		t.Fatalf("lifecycle = %v, want deleted after the leader is back", life.names())
	}
	store.mu.Lock()
	got := store.m["eng-web/"+uid]
	store.mu.Unlock()
	if !got.Deleted || got.Person.Subject != "sub-alice" {
		t.Fatalf("registration after delete = %+v (want a tombstone that keeps the person)", got)
	}
}
