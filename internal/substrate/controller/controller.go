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

// Package controller is the DefenseClaw Substrate controller (PLAN §6.2):
// it polls ate-api-server (there is no watch RPC), admits actors whose
// template DefenseClaw attested and a profile allows, writes each actor's
// EgressPolicy before its first resume (forks too) and re-checks it on
// every resume, reverts foreign policy changes until three reverts in ten
// minutes mark the actor policy_conflict (E14; it then keeps only the
// DefenseClaw rule), adopts forks with their
// parent's attribution (E17), suspends idle actors (E4), refuses old kits
// (E18) and reports inventory and shadow AI. It runs as one replica.
package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

// Defaults.
const (
	DefaultIdleInterval    = 2 * time.Second
	DefaultFastInterval    = 250 * time.Millisecond
	DefaultFastWindow      = 30 * time.Second
	DefaultWorkers         = 16
	DefaultPageSize        = 500
	DefaultConflictWindow  = 10 * time.Minute
	DefaultConflictReverts = 3
	// DefaultIdleCPU is the CPU use (cores) under which an actor counts as
	// idle; DefaultCPUSampleMaxAge how fresh the sample must be.
	DefaultIdleCPU         = 0.05
	DefaultCPUSampleMaxAge = 2 * time.Minute
	// templateCacheTTL bounds how long a template's attestation verdict is
	// reused; after it the attestor runs again (it has its own short
	// cache), so a revoked key or rotated anchors reach admitted templates.
	templateCacheTTL = 30 * time.Second
	// registrationTTL bounds how long a registration is reused before the
	// registry is read again (approvals and revocations).
	registrationTTL = 30 * time.Second
	// attestationGrace bounds how long a registry outage keeps the last good
	// attestation of an unchanged template (GAP-0127).
	attestationGrace = 15 * time.Minute
	// registrationOutageGrace bounds how long a leader outage keeps using an
	// actor's last good registration, so foreign policy edits are still
	// reverted while the leader is down (GAP-0145).
	registrationOutageGrace = 15 * time.Minute
	// launcherRegistrationGrace is how long after its create an actor in a
	// launcher atespace may be unregistered without being called foreign:
	// the gateway writes the registration one leader call after CreateActor
	// (GAP-0145). The actor is held (no alert, no policy change) meanwhile.
	launcherRegistrationGrace = 15 * time.Second
	// MigrateHint is the fix the kit refusal names.
	MigrateHint = "rebuild the template with the current kit: defenseclaw substrate migrate"
)

// Options configure a Controller.
type Options struct {
	Client   ateapi.Client
	Attestor Attestor
	Activity ActivitySource
	// CPU is the CPU source of idle suspend; without one nothing is idle.
	CPU      CPUSource
	Registry Registry
	Resolver ProfileResolver
	Sink     Sink

	// Settings are the cluster render settings; Secrets the configured
	// secrets (see SettingsFromConfig and SecretsFromConfig).
	Settings render.Settings
	Secrets  []render.Secret
	// LauncherAtespaces are the atespaces DefenseClaw owns.
	LauncherAtespaces map[string]bool
	// RequireAttestation gives no policy to an unattested template.
	RequireAttestation bool
	// Lifecycle, when set, gets every suspend, resume, fork, revert,
	// crash and delete the controller observes (A13 chain clocks).
	Lifecycle LifecycleSink
	// Resets, when set, is read every pass for admin policy_conflict
	// resets (ResetConfigMap in Namespace).
	Resets    ResetStore
	Namespace string
	// Templates holds the image allow lists (allowed_images and
	// profile_images) every admitted template's containers must match.
	Templates config.SubstrateTemplatesConfig
	// KitVersion is this release's kit version (N); N and N-1 are
	// accepted. Empty or unparseable accepts every kit.
	KitVersion string
	// IdleSuspendAfter 0 turns idle suspend off.
	IdleSuspendAfter time.Duration
	IdleCPU          float64
	CPUSampleMaxAge  time.Duration

	IdleInterval, FastInterval, FastWindow time.Duration
	Workers                                int
	PageSize                               int32
	ConflictWindow                         time.Duration
	ConflictReverts                        int

	Now func() time.Time
}

// Controller reconciles actors with their DefenseClaw policy.
type Controller struct {
	o Options

	mu        sync.Mutex
	actors    map[string]*actorState // by actor UID
	templates map[string]cachedTemplate
	fastUntil time.Time
	scoped    bool
	// unlisted are atespaces the last pass could not list: their known
	// actors are kept, not reported deleted. warnedList dedups warnings.
	unlisted   map[string]bool
	warnedList map[string]bool
	// lifeRetry are deleted actors whose delete event is not delivered.
	lifeRetry []*actorState
	// uidByKey is the last UID seen per atespace/name (GAP-0133).
	uidByKey map[string]string
}

type recreatedActor struct {
	a    *ateapi.Actor
	prev string
}

// maxNameHistory bounds uidByKey.
const maxNameHistory = 100000

type cachedTemplate struct {
	tmpl *ateapi.ActorTemplate
	att  Attestation
	at   time.Time
	// goodAt is when the template last verified; graceAlerted is set once
	// a registry outage is being ridden out on that verdict.
	goodAt       time.Time
	graceAlerted bool
}

type actorState struct {
	mu        sync.Mutex
	key, uid  string
	firstSeen time.Time
	lastState ateapi.ActorState
	runningAt time.Time
	// ourUID/ourVersion identify the policy version this controller last
	// wrote or confirmed; a different version is a foreign change.
	ourUID     string
	ourVersion int64
	reverts    []time.Time
	conflict   bool
	// lastForeign is the last foreign change seen while in conflict.
	lastForeign time.Time
	refused     string
	// refusedMsg is refused's reason in words (EnsurePolicy's answer).
	refusedMsg string
	// hold is why the last reconcile wrote no policy without refusing the
	// actor (RefusalRegistrationPending, RefusalNotManaged,
	// RefusalPolicyWriteRace), "" otherwise; EnsurePolicy names it.
	hold string
	// pendingLife are lifecycle events not yet delivered to the leader.
	pendingLife []chainstate.LifecycleEvent
	lifeWarned  bool
	// forcedDeny is why the resolver gives the actor deny-only (D8).
	forcedDeny string
	recheckGen int32
	reg        Registration
	regOK      bool
	regAt      time.Time
	regState   ateapi.ActorState
	// regStaleWarned is set while a leader outage keeps the last good
	// registration in use (one warning per outage).
	regStaleWarned bool
	// forkQueued and inventoried make the once-per-incarnation fork event
	// and inventory event survive a failed first pass.
	forkQueued, inventoried bool
	// rid is the snapshot identity seen on the last pass; a revert is told
	// from how it changed (GAP-0141).
	rid     restoreID
	written bool
	// unmanagedChecked is set once an unmanaged actor's policy was checked
	// for a DefenseClaw policy left from when it was managed.
	unmanagedChecked bool
}

// New checks the options and fills defaults.
func New(o Options) (*Controller, error) {
	if o.Client == nil || o.Attestor == nil || o.Registry == nil || o.Resolver == nil || o.Sink == nil {
		return nil, errors.New("controller: Client, Attestor, Registry, Resolver and Sink are required")
	}
	if o.Activity == nil && o.IdleSuspendAfter > 0 {
		return nil, errors.New("controller: idle suspend needs an ActivitySource")
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.IdleInterval, DefaultIdleInterval)
	def(&o.FastInterval, DefaultFastInterval)
	def(&o.FastWindow, DefaultFastWindow)
	def(&o.ConflictWindow, DefaultConflictWindow)
	def(&o.CPUSampleMaxAge, DefaultCPUSampleMaxAge)
	if o.IdleCPU <= 0 {
		o.IdleCPU = DefaultIdleCPU
	}
	if o.Workers <= 0 {
		o.Workers = DefaultWorkers
	}
	if o.PageSize <= 0 {
		o.PageSize = DefaultPageSize
	}
	if o.ConflictReverts <= 0 {
		o.ConflictReverts = DefaultConflictReverts
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Controller{o: o, actors: map[string]*actorState{}, templates: map[string]cachedTemplate{},
		unlisted: map[string]bool{}, warnedList: map[string]bool{}, uidByKey: map[string]string{}}, nil
}

// Run polls until ctx ends: every IdleInterval, or every FastInterval for
// FastWindow after new or resuming actors were seen (batch starts).
func (c *Controller) Run(ctx context.Context) error {
	for {
		if err := c.Reconcile(ctx); err != nil && ctx.Err() == nil {
			c.emit(Event{Type: EventWarning, Severity: SeverityWarn, Message: "reconcile pass failed: " + err.Error()})
		}
		wait := c.o.IdleInterval
		c.mu.Lock()
		if c.o.Now().Before(c.fastUntil) {
			wait = c.o.FastInterval
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Reconcile is one pass over every actor. New and resuming actors go first
// so their policy lands before they reach the network.
func (c *Controller) Reconcile(ctx context.Context) error {
	c.applyResets(ctx)
	c.retryLifecycle(ctx)
	actors, err := c.listActors(ctx)
	if err != nil {
		return err
	}
	now := c.o.Now()
	seen := make(map[string]bool, len(actors))
	var urgent, rest []*ateapi.Actor
	var recreated []recreatedActor
	c.mu.Lock()
	for _, a := range actors {
		uid := a.GetMetadata().GetUid()
		seen[uid] = true
		_, known := c.actors[uid]
		if !known {
			key := ateapi.Key(ateapi.RefOf(a.GetMetadata()))
			c.actors[uid] = &actorState{uid: uid, key: key, firstSeen: now}
			if prev, ok := c.uidByKey[key]; ok && prev != uid && c.o.LauncherAtespaces[a.GetMetadata().GetAtespace()] {
				recreated = append(recreated, recreatedActor{a: a, prev: prev})
			}
			if len(c.uidByKey) >= maxNameHistory {
				c.uidByKey = map[string]string{}
			}
			c.uidByKey[key] = uid
		}
		if !known || a.GetStatus().GetState() == ateapi.ActorStateResuming {
			urgent = append(urgent, a)
			c.fastUntil = now.Add(c.o.FastWindow)
		} else {
			rest = append(rest, a)
		}
	}
	var gone []*actorState
	for uid, st := range c.actors {
		ns, _, _ := strings.Cut(st.key, "/")
		if !seen[uid] && c.unlisted[ns] {
			continue // not listed this pass, not known to be deleted
		}
		if !seen[uid] {
			gone = append(gone, st)
			delete(c.actors, uid)
		}
	}
	c.mu.Unlock()
	for _, st := range gone {
		ns, name, _ := strings.Cut(st.key, "/")
		c.emit(Event{Type: EventDeleted, Severity: SeverityInfo, Atespace: ns, Actor: name, ActorUID: st.uid, Message: "actor deleted"})
		st.pendingLife = append(st.pendingLife, chainstate.LifecycleEvent{Actor: chainstate.Actor{Atespace: ns, UID: st.uid},
			Event: chainstate.LifecycleDeleted, AtUnixNano: now.UnixNano()})
		c.flushLifecycle(ctx, st, Event{Atespace: ns, Actor: name, ActorUID: st.uid})
		if len(st.pendingLife) > 0 {
			c.mu.Lock()
			c.lifeRetry = append(c.lifeRetry, st)
			c.mu.Unlock()
		}
	}
	for _, r := range recreated {
		// Egress caches the actor JWT by actor name: the new incarnation
		// presents the old UID's token until it expires (at most 300 s,
		// GAP-0133), so the gateway refuses it meanwhile.
		md := r.a.GetMetadata()
		c.emit(Event{Type: EventRecreatedSameName, Severity: SeverityWarn, Atespace: md.GetAtespace(), Actor: md.GetName(), ActorUID: md.GetUid(),
			Message: "a new actor reuses the name of a deleted one: DefenseClaw refuses its calls for up to 300 s while egress serves the old actor token; reuse names only after that, or pick a new name",
			Detail:  map[string]any{"previous_uid": r.prev}})
	}
	var errs []error
	var emu sync.Mutex
	for _, batch := range [][]*ateapi.Actor{urgent, rest} {
		c.parallel(batch, func(a *ateapi.Actor) {
			if err := c.reconcileActor(ctx, a); err != nil {
				emu.Lock()
				errs = append(errs, err)
				emu.Unlock()
			}
		})
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d actors failed, first: %w", len(errs), errs[0])
	}
	return nil
}

// listActors lists every actor, or, when the controller's principal is not a
// global viewer, the actors of the atespaces it manages by name (launcher
// atespaces and exact match.substrate names). Inventory and shadow AI then
// cover only those, which one warning says.
func (c *Controller) listActors(ctx context.Context) ([]*ateapi.Actor, error) {
	c.mu.Lock()
	scoped := c.scoped
	c.unlisted = map[string]bool{}
	c.mu.Unlock()
	if !scoped {
		actors, err := ateapi.AllActors(ctx, c.o.Client, "", c.o.PageSize)
		if err == nil || status.Code(err) != codes.PermissionDenied {
			if err != nil {
				return nil, fmt.Errorf("list actors: %w", err)
			}
			return actors, nil
		}
		c.mu.Lock()
		c.scoped = true
		c.mu.Unlock()
		c.emit(Event{Type: EventWarning, Severity: SeverityWarn,
			Message: "no global viewer role on ate-api-server: listing only the managed atespaces; inventory and shadow AI cover only those"})
	}
	set := map[string]bool{}
	for ns := range c.o.LauncherAtespaces {
		set[ns] = true
	}
	if l, ok := c.o.Resolver.(AtespaceLister); ok {
		for _, ns := range l.ManagedAtespaces() {
			set[ns] = true
		}
	}
	names := make([]string, 0, len(set))
	for ns := range set {
		names = append(names, ns)
	}
	sort.Strings(names)
	var out []*ateapi.Actor
	var failed []string
	for _, ns := range names {
		actors, err := ateapi.AllActors(ctx, c.o.Client, ns, c.o.PageSize)
		if err == nil {
			c.listOK(ns)
			out = append(out, actors...)
			continue
		}
		// One atespace that cannot be listed (no grant yet, deleted, or a
		// transient error) must not stop the others: skip it, keep its
		// known actors, and alert once until it lists again (GAP-0119).
		failed = append(failed, ns)
		if c.listFailedOnce(ns) {
			code := status.Code(err)
			msg := "cannot list actors in managed atespace " + ns + " (" + code.String() + "): it is skipped; new actors there get no policy (default deny) and drift there is not reverted until it lists again"
			if code == codes.PermissionDenied {
				msg += "; grant DefenseClaw editor on it (the chart bootstrap)"
			}
			c.emit(Event{Type: EventWarning, Severity: SeverityAlert, Atespace: ns, Message: msg,
				Detail: map[string]any{"code": code.String(), "error": err.Error()}})
		}
		if len(failed) == len(names) {
			return nil, fmt.Errorf("list actors in %s: %w", ns, err)
		}
	}
	if len(failed) > 0 {
		// Reconcile what listed; a transient error is retried next pass.
		// Actors of a failed atespace are not reported deleted.
		c.mu.Lock()
		for _, ns := range failed {
			c.unlisted[ns] = true
		}
		c.mu.Unlock()
	}
	return out, nil
}

func (c *Controller) listFailedOnce(ns string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unlisted[ns] = true
	if c.warnedList[ns] {
		return false
	}
	c.warnedList[ns] = true
	return true
}

func (c *Controller) listOK(ns string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.warnedList, ns)
}

func (c *Controller) parallel(actors []*ateapi.Actor, fn func(*ateapi.Actor)) {
	sem := make(chan struct{}, c.o.Workers)
	var wg sync.WaitGroup
	for _, a := range actors {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn(a)
		}()
	}
	wg.Wait()
}

// ErrRefused means EnsurePolicy left the actor without network.
var ErrRefused = errors.New("controller: actor refused")

// refusePending is attribution's answer for a just-created launcher actor
// whose registration is not readable yet: hold, change nothing (GAP-0145).
const refusePending = "pending_registration"

// Tombstoner is a Registry that can mark an actor's registration deleted
// (LeaderRegistry); a registry without one keeps nothing to mark.
type Tombstoner interface {
	MarkDeleted(ctx context.Context, atespace, uid string) error
}

// FreshRegistry is a Registry that can read past its own miss cache
// (LeaderRegistry over registry.Remote).
type FreshRegistry interface {
	GetFresh(ctx context.Context, atespace, uid string) (Registration, bool, error)
}

// createdAt is the actor's create time from the API server, or when this
// controller first saw it.
func createdAt(md *ateapi.ResourceMetadata, st *actorState) time.Time {
	if t := md.GetCreateTime(); t != nil && t.IsValid() {
		return t.AsTime()
	}
	return st.firstSeen
}

// EnsurePolicy reconciles one actor now, for a caller (the launcher's
// create path) that resumes the actor only after its policy is written. It
// returns a *RefusedError (it matches ErrRefused) when the actor gets no
// policy. The create path wrote the actor's registration just before, so a
// registration the leader does not show yet is waited for briefly.
func (c *Controller) EnsurePolicy(ctx context.Context, ref *ateapi.ObjectRef) error {
	for try := 1; ; try++ {
		a, err := c.o.Client.GetActor(ctx, ref)
		if err != nil {
			return err
		}
		md := a.GetMetadata()
		uid := md.GetUid()
		c.mu.Lock()
		st, ok := c.actors[uid]
		if !ok {
			st = &actorState{uid: uid, key: ateapi.Key(ref), firstSeen: c.o.Now()}
			c.actors[uid] = st
		}
		c.mu.Unlock()
		if err := c.reconcileActor(ctx, a); err != nil {
			return err
		}
		st.mu.Lock()
		written, refused, msg, hold := st.written, st.refused, st.refusedMsg, st.hold
		st.mu.Unlock()
		re := &RefusedError{Atespace: md.GetAtespace(), Name: md.GetName(), UID: uid}
		switch {
		case refused != "":
			re.Code, re.Reason = refused, msg
		case written:
			return nil
		case hold == RefusalRegistrationPending && try < ensurePendingTries:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(ensurePendingWait):
			}
			continue
		case hold == RefusalRegistrationPending:
			re.Code, re.Reason = hold, "the actor's registration is not readable from the leader yet"
		case hold == RefusalNotManaged:
			re.Code, re.Reason = hold, "no profile assignment makes DefenseClaw manage this actor"
		case hold == RefusalPolicyWriteRace:
			re.Code, re.Reason = hold, "the actor's egress policy changed under every write"
		default:
			re.Code, re.Reason = RefusalNoPolicy, "the actor has no DefenseClaw egress policy"
		}
		if re.Reason == "" {
			re.Reason = re.Code
		}
		return re
	}
}

// RefusedError is EnsurePolicy's answer for an actor left without a policy:
// a closed code, the reason in words and the actor, so the create path logs
// it and tells the person why (GAP-0182). It matches ErrRefused.
type RefusedError struct {
	Atespace, Name, UID string
	// Code is the controller event type of the refusal (for example
	// sandbox.foreign_actor) or one of the Refusal* codes.
	Code string
	// Reason is the refusal in words.
	Reason string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("%s: %s (%s), actor %s/%s uid %s", ErrRefused, e.Reason, e.Code, e.Atespace, e.Name, e.UID)
}

// Is makes errors.Is(err, ErrRefused) hold.
func (e *RefusedError) Is(target error) bool { return target == ErrRefused }

// Codes of an EnsurePolicy refusal that no controller event names.
const (
	RefusalRegistrationPending = "registration_pending"
	RefusalNotManaged          = "not_managed"
	RefusalPolicyWriteRace     = "policy_write_race"
	RefusalNoPolicy            = "no_policy"
)

// ensurePendingTries and ensurePendingWait bound how long EnsurePolicy waits
// for a registration the create path wrote but the leader does not show yet
// (the GAP-0145 hold), about 0.75 s.
var (
	ensurePendingTries = 4
	ensurePendingWait  = 250 * time.Millisecond
)

// errWriteRace is a policy write that lost to another writer (ALREADY_EXISTS
// on create, ABORTED on update): apply reads the policy again at once.
var errWriteRace = errors.New("the egress policy changed under the write")

// maxApplyTries bounds apply's read-compare-write tries in one reconcile.
const maxApplyTries = 3

// apply writes or confirms DefenseClaw's policy. A write that loses to
// another writer (the gateway's create path and the controller deployment
// both write a new actor's policy, GAP-0182) is decided again in the same
// call: EnsurePolicy has no next pass to leave it to.
func (c *Controller) apply(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, profile render.Profile, base Event) error {
	for try := 1; ; try++ {
		err := c.applyOnce(ctx, a, st, reg, profile, base)
		if !errors.Is(err, errWriteRace) {
			return err
		}
		if try == maxApplyTries {
			st.hold = RefusalPolicyWriteRace
			return nil // the next pass decides again
		}
	}
}

func (c *Controller) state(uid string) *actorState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.actors[uid]
}

func (c *Controller) reconcileActor(ctx context.Context, a *ateapi.Actor) error {
	md := a.GetMetadata()
	st := c.state(md.GetUid())
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	state := a.GetStatus().GetState()
	if state == ateapi.ActorStateDeleting {
		return nil
	}
	now := c.o.Now()
	if state == ateapi.ActorStateRunning && st.lastState != ateapi.ActorStateRunning {
		st.runningAt = now
	}
	first := st.lastState == ateapi.ActorStateUnspecified
	prev := st.lastState
	st.lastState = state
	base := Event{Atespace: md.GetAtespace(), Actor: md.GetName(), ActorUID: md.GetUid()}
	self := chainstate.Actor{Atespace: md.GetAtespace(), UID: md.GetUid()}
	rid := restoreIDOf(a.GetStatus())
	if !first {
		evs := []string{lifecycleOf(prev, state)}
		if revertSeen(prev, state, st.rid, rid) {
			// Told from the snapshot identity, so a revert whose REVERTING
			// fell between two passes, a revert of a SUSPENDED actor and a
			// suspend plus revert inside one poll still put the mutation
			// barrier in the actor's chains (GAP-0141).
			evs = append(evs, chainstate.LifecycleReverted)
		}
		for _, ev := range evs {
			if ev != "" {
				st.pendingLife = append(st.pendingLife, chainstate.LifecycleEvent{Actor: self, Event: ev, AtUnixNano: now.UnixNano()})
			}
		}
	}
	st.rid = rid
	c.flushLifecycle(ctx, st, base)

	st.hold = ""
	_, launcher := c.o.LauncherAtespaces[md.GetAtespace()]
	reg, refuse, err := c.attribution(ctx, a, st, launcher, base)
	if err != nil {
		return err
	}
	if !st.forkQueued && reg.Source == SourceFork && reg.ParentUID != "" {
		// Once per incarnation, on the first pass whose attribution
		// succeeds (a leader outage on the first pass must not lose it).
		st.forkQueued = true
		// The leader copies the parent's chain windows to the fork once
		// (never its asks), keyed on the registration's ParentUID.
		st.pendingLife = append(st.pendingLife, chainstate.LifecycleEvent{Actor: self, Event: chainstate.LifecycleForked,
			Parent: &chainstate.Actor{Atespace: md.GetAtespace(), UID: reg.ParentUID}, AtUnixNano: now.UnixNano()})
		c.flushLifecycle(ctx, st, base)
	}
	if refuse == refusePending {
		// Unregistered and just created in a launcher atespace: no
		// inventory, alert or policy change until the registration is
		// read or the grace ends (GAP-0145).
		st.hold = RefusalRegistrationPending
		return nil
	}
	if !st.inventoried {
		st.inventoried = true
		ev := base
		ev.Type, ev.Severity, ev.Message = EventInventory, SeverityInfo, "actor seen"
		ev.Detail = map[string]any{"template": ateapi.Key(a.GetActorTemplate()), "state": state.String(), "source": reg.Source,
			"launcher_atespace": launcher, "person_bound": reg.Person != "", "parent_uid": reg.ParentUID, "forked_by": reg.ForkedBy}
		c.emit(ev)
	}
	if refuse == "" {
		res, err := c.o.Resolver.Resolve(reg, launcher)
		if err != nil {
			return fmt.Errorf("%s: resolve profile: %w", st.key, err)
		}
		for _, w := range res.Warnings {
			ev := base
			ev.Type, ev.Severity, ev.Message = EventWarning, SeverityWarn, w
			c.emit(ev)
		}
		if !res.Managed {
			// Inventory only. An actor that was managed (its atespace left
			// launcher_atespaces or its profile assignment went away) must
			// not keep DefenseClaw's allow list, JWT and secret rules with
			// nothing enforcing them: remove a DefenseClaw policy once.
			st.hold = RefusalNotManaged
			return c.unmanaged(ctx, a, st, base)
		}
		st.unmanagedChecked = false
		if res.Refuse == "" && res.SandboxClass != "" {
			res.Refuse = c.classRefusal(ctx, a, res.SandboxClass)
		}
		if res.Refuse != "" {
			c.refuseOnce(st, base, EventProfileRefused, res.Refuse, "", "")
		} else if c.admit(ctx, a, st, base, res.Profile.Name) == "" {
			booted, err := c.bootedTemplate(ctx, a, st, base)
			if err != nil {
				return err
			}
			if !booted {
				return c.removePolicy(ctx, a, st, base)
			}
			if res.DenyOnly != st.forcedDeny {
				st.forcedDeny = res.DenyOnly
				if res.DenyOnly != "" {
					ev := base
					ev.Type, ev.Severity, ev.Message = EventWarning, SeverityWarn, "the actor keeps only the DefenseClaw rule: "+res.DenyOnly
					c.emit(ev)
				}
			}
			if err := c.apply(ctx, a, st, reg, res.Profile, base); err != nil {
				return err
			}
			return c.idle(ctx, a, st, reg, base, res.idleAfter(c.o.IdleSuspendAfter))
		}
	}
	// Refused: no policy, so the actor falls to default deny.
	return c.removePolicy(ctx, a, st, base)
}

// attribution finds or creates the actor's registration. A non-empty
// refuse means the actor gets no policy.
func (c *Controller) attribution(ctx context.Context, a *ateapi.Actor, st *actorState, launcher bool, base Event) (Registration, string, error) {
	now := c.o.Now()
	if st.regOK && st.regState != a.GetStatus().GetState() {
		// A lifecycle change (resume, suspend, crash, revert) re-reads the
		// registration: the launcher may have rebound or revoked it.
		st.regOK = false
	}
	if st.regOK && now.Sub(st.regAt) < registrationTTL {
		st.reg.Template = ateapi.Key(a.GetActorTemplate())
		return st.reg, "", nil
	}
	md := a.GetMetadata()
	reg, ok, err := c.o.Registry.Get(ctx, md.GetAtespace(), md.GetUid())
	if err == nil && !ok && launcher {
		// A miss is cached briefly; before an actor is called foreign, read
		// the leader again past that cache (GAP-0145).
		if fr, has := c.o.Registry.(FreshRegistry); has {
			reg, ok, err = fr.GetFresh(ctx, md.GetAtespace(), md.GetUid())
		}
	}
	if err != nil {
		// The leader is unreachable. With a recent good registration of this
		// incarnation, go on with it, so the actor keeps DefenseClaw's
		// policy and foreign edits are still reverted (GAP-0145). Without
		// one, hold: never call an unknown actor in a launcher atespace
		// foreign on a failed read, and change no policy.
		if st.reg.UID == md.GetUid() && !st.regAt.IsZero() && now.Sub(st.regAt) < registrationOutageGrace {
			if !st.regStaleWarned {
				st.regStaleWarned = true
				ev := base
				ev.Type, ev.Severity = EventWarning, SeverityWarn
				ev.Message = "registry unreachable, using the actor's last registration: " + err.Error()
				c.emit(ev)
			}
			st.reg.Template = ateapi.Key(a.GetActorTemplate())
			return st.reg, "", nil
		}
		return Registration{}, "", fmt.Errorf("%s: registry (holding, no policy change): %w", st.key, err)
	}
	st.regStaleWarned = false
	// A registration that is gone (the launcher revoked it, or an in-memory
	// registry restarted) is made again below like a new one: in a launcher
	// atespace that makes the actor foreign (no policy).
	st.regOK = false
	if !ok {
		reg = Registration{Atespace: md.GetAtespace(), Name: md.GetName(), UID: md.GetUid(), Source: SourceAtespace}
		if tag := a.GetSourceTag(); tag.GetName() != "" {
			parent, perr := c.parentRegistration(ctx, tag)
			switch {
			case perr != nil && !ateapi.IsNotFound(perr):
				return Registration{}, "", fmt.Errorf("%s: fork parent: %w", st.key, perr)
			case perr == nil:
				reg = parent
				reg.Atespace, reg.Name, reg.UID, reg.Source = md.GetAtespace(), md.GetName(), md.GetUid(), SourceFork
				reg.ParentUID = parent.UID
				// A fork inherits chain windows (keyed on the parent in the
				// leader) but never the parent's ask approvals (PLAN §5.3).
				reg.Approved = nil
				reg.ForkedBy = ForkedByUnknown
				if launcher {
					// Only DefenseClaw may fork in a launcher atespace (the
					// access policy grants it alone).
					reg.ForkedBy = ForkedByDefenseClaw
				} else {
					// Someone else forked it: it is not that person's actor,
					// so it gets no person binding (no per-person secrets).
					reg.Person, reg.Workload = "", ""
				}
				ev := base
				ev.Type, ev.Severity, ev.Message = EventFork, SeverityInfo, "fork adopted with its parent's attribution"
				ev.Detail = map[string]any{"parent_uid": parent.UID, "parent": parent.Atespace + "/" + parent.Name,
					"tag": ateapi.Key(tag), "forked_by": reg.ForkedBy, "person_bound": reg.Person != ""}
				c.emit(ev)
			default:
				// The parent is gone or never registered.
				reg.ForkedBy = ForkedByUnknown
			}
		}
		if launcher && reg.Source == SourceAtespace {
			if created := createdAt(md, st); now.Sub(created) < launcherRegistrationGrace {
				// Just created: the launcher's registration may not be
				// written yet. Hold (no alert, no policy change) and look
				// again on the next fast pass (GAP-0145).
				c.mu.Lock()
				if until := created.Add(launcherRegistrationGrace); until.After(c.fastUntil) {
					c.fastUntil = until
				}
				c.mu.Unlock()
				return reg, refusePending, nil
			}
			// Every actor in a launcher atespace is bound to a person at
			// create; one nobody registered was made outside DefenseClaw.
			c.refuseOnce(st, base, EventForeignActor, "actor in a launcher atespace that DefenseClaw did not create", SignalForeignActor, "")
			return reg, "foreign_actor", nil
		}
		if err := c.o.Registry.Put(ctx, reg); err != nil {
			return Registration{}, "", fmt.Errorf("%s: registry: %w", st.key, err)
		}
	}
	reg.Template = ateapi.Key(a.GetActorTemplate())
	st.reg, st.regOK, st.regAt, st.regState = reg, true, now, a.GetStatus().GetState()
	return reg, "", nil
}

func (c *Controller) parentRegistration(ctx context.Context, tag *ateapi.ObjectRef) (Registration, error) {
	t, err := c.o.Client.GetTag(ctx, tag)
	if err != nil {
		return Registration{}, err
	}
	src := t.GetSourceActor()
	parent, err := c.o.Client.GetActor(ctx, src)
	if err != nil {
		return Registration{}, err
	}
	reg, ok, err := c.o.Registry.Get(ctx, src.GetAtespace(), parent.GetMetadata().GetUid())
	if err != nil {
		return Registration{}, err
	}
	if !ok {
		return Registration{}, status.Error(codes.NotFound, "parent registration not found")
	}
	return reg, nil
}

// admit checks the template's attestation and kit version.
func (c *Controller) admit(ctx context.Context, a *ateapi.Actor, st *actorState, base Event, profile string) string {
	// The first admission of an actor reads its template fresh: a cached
	// verdict by name would admit an image swapped in after it (GAP-0053).
	tmpl, att, err := c.template(ctx, a.GetActorTemplate(), !st.written)
	if err != nil {
		c.refuseOnce(st, base, EventTemplateUnverified, "template could not be read: "+err.Error(), "", "")
		return "template_unreadable"
	}
	if !att.Attested && c.o.RequireAttestation {
		reason := att.Reason
		if reason == "" {
			reason = "no DefenseClaw attestation"
		}
		c.refuseOnce(st, base, EventTemplateUnverified, "template "+ateapi.Key(ateapi.RefOf(tmpl.GetMetadata()))+" is not attested: "+reason, SignalUnattestedTemplate, att.Digest)
		return "template_unverified"
	}
	{
		// PLAN §5.3 step 2: an attested digest that a profile allows. The
		// allow lists apply with attestation off too (GAP-0131).
		var repos []string
		for _, ct := range tmpl.GetContainers() {
			repos = append(repos, imageRepo(ct.GetImage()))
		}
		if repo, ok := ImagesAllowed(c.o.Templates, profile, repos); !ok {
			c.refuseOnce(st, base, EventTemplateUnverified, fmt.Sprintf("image %s is not allowed for profile %s (substrate.templates.allowed_images / profile_images)", repo, profile), SignalUnattestedTemplate, att.Digest)
			return "image_not_allowed"
		}
	}
	if att.KitVersion != "" && !KitAccepted(c.o.KitVersion, att.KitVersion) {
		c.refuseOnce(st, base, EventKitRefused, fmt.Sprintf("kit %s is older than N-1 of %s; %s", att.KitVersion, c.o.KitVersion, MigrateHint), SignalOldKit, att.KitVersion)
		return "kit_too_old"
	}
	return ""
}

// bootedTemplate reports whether the actor runs the template version that
// admission just checked (GAP-0053). An actor records only its template's
// name, not the version it booted, so a template edited after the actor was
// created (an image swapped in, an actor started, the image swapped back
// inside one poll) leaves the actor's image unknown. Such an actor keeps its
// network only if DefenseClaw already gave it its policy (a controller
// admitted it before the edit, also across a controller restart); one that
// has none is refused, and the fix is to recreate it.
func (c *Controller) bootedTemplate(ctx context.Context, a *ateapi.Actor, st *actorState, base Event) (bool, error) {
	if st.written {
		return true, nil
	}
	k := ateapi.Key(a.GetActorTemplate())
	c.mu.Lock()
	ct, ok := c.templates[k]
	c.mu.Unlock()
	if !ok {
		return true, nil
	}
	edited, created := ct.tmpl.GetMetadata().GetUpdateTime(), a.GetMetadata().GetCreateTime()
	if edited == nil || created == nil || !edited.AsTime().After(created.AsTime()) {
		return true, nil
	}
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ateapi.RefOf(a.GetMetadata()))
	switch {
	case ateapi.IsNotFound(err):
	case err != nil:
		return false, fmt.Errorf("%s: get policy (holding, no policy change): %w", st.key, err)
	case render.IsDefenseClaw(cur, c.o.Settings):
		return true, nil
	}
	c.refuseOnce(st, base, EventTemplateUnverified, "template "+k+" changed after the actor was created, so the actor's image is not known to be the attested one; delete the actor and create it again",
		SignalUnattestedTemplate, ct.att.Digest)
	return false, nil
}

// template returns the template and its attestation. A cached verdict is
// reused for templateCacheTTL by name, except when fresh: then the template
// is read again and the verdict is reused only for the same template
// version (uid and version), so an edit is never hidden by the cache.
func (c *Controller) template(ctx context.Context, ref *ateapi.ObjectRef, fresh bool) (*ateapi.ActorTemplate, Attestation, error) {
	k := ateapi.Key(ref)
	now := c.o.Now()
	c.mu.Lock()
	ct, ok := c.templates[k]
	c.mu.Unlock()
	valid := ok && now.Sub(ct.at) < templateCacheTTL && (ct.att.ValidUntil.IsZero() || now.Before(ct.att.ValidUntil))
	if valid && !fresh {
		return ct.tmpl, ct.att, nil
	}
	tmpl, err := c.o.Client.GetActorTemplate(ctx, ref)
	if err != nil {
		return nil, Attestation{}, err
	}
	if valid && sameTemplateVersion(ct.tmpl, tmpl) {
		return ct.tmpl, ct.att, nil
	}
	// Always attest again after the TTL, even for an unchanged template: a
	// revoked key, rotated anchors or a raised policy generation must reach
	// templates admitted before (GAP-0054). The attestor caches the
	// registry work itself.
	att, err := c.o.Attestor.Attest(ctx, tmpl)
	if err != nil {
		att = Attestation{Reason: "attestation check failed: " + err.Error(), Retryable: true}
	}
	// A registry outage is not a verdict about the template: keep the last
	// good verdict of the same template version for a bounded grace and
	// alert, instead of cutting every running actor's network (GAP-0127).
	// Revocation, new anchors and other refusals still cut at once.
	if !att.Attested && att.Retryable && ok && ct.att.Attested && sameTemplateVersion(ct.tmpl, tmpl) {
		since := ct.goodAt
		if since.IsZero() {
			since = ct.at
		}
		if now.Sub(since) < attestationGrace {
			if !ct.graceAlerted {
				c.emit(Event{Type: EventWarning, Severity: SeverityAlert, Atespace: ref.GetAtespace(),
					Message: "template " + k + " cannot be re-attested (" + att.Reason + "): keeping its last good attestation for at most " + attestationGrace.String(),
					Detail:  map[string]any{"template": k, "good_since": since}})
			}
			ct.at, ct.goodAt, ct.graceAlerted = now, since, true
			c.mu.Lock()
			c.templates[k] = ct
			c.mu.Unlock()
			return ct.tmpl, ct.att, nil
		}
	}
	ct = cachedTemplate{tmpl: tmpl, att: att, at: now}
	if att.Attested {
		ct.goodAt = now
	}
	c.mu.Lock()
	c.templates[k] = ct
	c.mu.Unlock()
	return ct.tmpl, ct.att, nil
}

func sameTemplateVersion(a, b *ateapi.ActorTemplate) bool {
	return a.GetMetadata().GetUid() == b.GetMetadata().GetUid() && a.GetMetadata().GetVersion() == b.GetMetadata().GetVersion()
}

// Attestor is the template admission the controller runs (wiring tests).
func (c *Controller) Attestor() Attestor { return c.o.Attestor }

// refuseOnce records why an actor gets no policy, emitting the event (and
// a shadow AI signal when signalID is set) once per reason.
func (c *Controller) refuseOnce(st *actorState, base Event, typ, msg, signalID, version string) {
	st.refusedMsg = msg
	if st.refused == typ {
		return
	}
	st.refused = typ
	ev := base
	ev.Type, ev.Severity, ev.Message = typ, SeverityWarn, msg
	if signalID != "" {
		ev.Signal = c.signal(base, signalID, version, st.firstSeen)
	}
	c.emit(ev)
}

func (c *Controller) signal(base Event, id, version string, first time.Time) *Signal {
	return &Signal{
		Fingerprint: id + ":" + base.ActorUID, SignalID: id, SignatureID: id, Name: "Agent Substrate actor " + base.Atespace + "/" + base.Actor,
		Vendor: "Agent Substrate", Product: "Substrate actor", Category: "shadow_ai", Confidence: 1, State: "new",
		Detector: "substrate_controller", Source: "substrate", Version: version, FirstSeen: first, LastSeen: c.o.Now(),
		SandboxID: base.ActorUID, SandboxName: base.Atespace + "/" + base.Actor,
	}
}

func (c *Controller) removePolicy(ctx context.Context, a *ateapi.Actor, st *actorState, base Event) error {
	ref := ateapi.RefOf(a.GetMetadata())
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ref)
	if ateapi.IsNotFound(err) {
		st.written, st.ourVersion = false, 0
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: get policy: %w", st.key, err)
	}
	if _, err := c.o.Client.DeleteActorEgressPolicy(ctx, ref, &ateapi.DeleteOptions{Uid: cur.GetMetadata().GetUid(), Version: cur.GetMetadata().GetVersion()}); err != nil && !ateapi.IsNotFound(err) {
		return fmt.Errorf("%s: remove policy: %w", st.key, err)
	}
	st.written, st.ourVersion = false, 0
	ev := base
	ev.Type, ev.Severity, ev.Message = EventPolicyRemoved, SeverityWarn, "egress policy removed: the actor is refused ("+st.refused+")"
	c.emit(ev)
	return nil
}

// applyOnce is one read-compare-write of the actor's policy (apply).
func (c *Controller) applyOnce(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, profile render.Profile, base Event) error {
	st.refused, st.refusedMsg = "", ""
	ref := ateapi.RefOf(a.GetMetadata())
	res, err := render.EgressPolicy(render.Input{Settings: c.o.Settings, Profile: profile, Person: reg.Person, Approved: reg.Approved, Secrets: c.o.Secrets})
	if err != nil {
		c.fail(base, "render: "+err.Error())
		return fmt.Errorf("%s: render: %w", st.key, err)
	}
	full := res.Policy
	deny, err := render.DenyOnly(c.o.Settings)
	if err != nil {
		c.fail(base, "render: "+err.Error())
		return fmt.Errorf("%s: render deny-only: %w", st.key, err)
	}
	// In policy_conflict the actor keeps only the DefenseClaw rule (the
	// actor JWT to the actor listener, so hooks still get verdicts): a
	// foreign policy is never left in force (GAP-0055).
	want := full
	if st.conflict || st.forcedDeny != "" {
		want = deny
	}
	state := a.GetStatus().GetState()
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ref)
	if ateapi.IsNotFound(err) {
		created, err := c.o.Client.CreateActorEgressPolicy(ctx, ref, want)
		if ateapi.IsAlreadyExists(err) {
			return errWriteRace // another writer won: read it again and compare
		}
		if err != nil {
			c.fail(base, "create policy: "+err.Error())
			return fmt.Errorf("%s: create policy: %w", st.key, err)
		}
		how := "created"
		if st.conflict {
			how = "created deny-only (policy_conflict)"
		}
		c.wrote(st, created, base, state, how, res)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: get policy: %w", st.key, err)
	}
	m := cur.GetMetadata()
	ours := m.GetUid() == st.ourUID && m.GetVersion() == st.ourVersion
	if st.conflict && !ours && render.Equal(cur, full) {
		// Another writer brought the policy back to DefenseClaw's: the
		// conflict is over.
		st.conflict, st.reverts = false, nil
		st.ourUID, st.ourVersion, st.written = m.GetUid(), m.GetVersion(), true
		ev := base
		ev.Type, ev.Severity, ev.Message = EventConflictCleared, SeverityInfo, "the actor's policy matches DefenseClaw's again"
		c.emit(ev)
		c.recheck(st, a, base, "confirmed")
		return nil
	}
	if render.Equal(cur, want) {
		st.ourUID, st.ourVersion, st.written = m.GetUid(), m.GetVersion(), true
		c.recheck(st, a, base, "confirmed")
		return nil
	}
	now := c.o.Now()
	foreign := st.ourVersion != 0 && !ours
	enter := false
	counted := foreign && !st.conflict
	if counted {
		st.reverts = append(st.reverts, now)
		cut := now.Add(-c.o.ConflictWindow)
		kept := st.reverts[:0]
		for _, t := range st.reverts {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		st.reverts = kept
		if len(st.reverts) >= c.o.ConflictReverts {
			st.conflict, enter, want = true, true, deny
		}
	}
	upd := &ateapi.EgressPolicy{Metadata: &ateapi.ResourceMetadata{Uid: m.GetUid(), Version: m.GetVersion()}, Rules: want.GetRules()}
	updated, err := c.o.Client.UpdateActorEgressPolicy(ctx, ref, upd)
	if ateapi.IsConflict(err) {
		if counted {
			// Decided again on the next try: this revert did not happen.
			st.conflict = false
			st.reverts = st.reverts[:len(st.reverts)-1]
		}
		return errWriteRace // changed under us: read again and decide again
	}
	if err != nil {
		if enter {
			st.conflict = false
			st.reverts = st.reverts[:len(st.reverts)-1]
		}
		c.fail(base, "update policy: "+err.Error())
		return fmt.Errorf("%s: update policy: %w", st.key, err)
	}
	how := "updated"
	switch {
	case enter:
		how = "replaced with deny-only (policy_conflict)"
	case foreign && st.conflict:
		how = "reverted to deny-only (policy_conflict)"
	case foreign:
		how = "reverted"
	case st.conflict:
		how = "deny-only (policy_conflict)"
	case st.forcedDeny != "":
		how = "deny-only (" + st.forcedDeny + ")"
	}
	// One foreign_rule event per revert outside a conflict; inside one, at
	// most one per conflict window (a GitOps loop would flood otherwise).
	if foreign && (!st.conflict || enter || now.Sub(st.lastForeign) >= c.o.ConflictWindow) {
		st.lastForeign = now
		ev := base
		ev.Type, ev.Severity, ev.Message = EventForeignRule, SeverityWarn, "a foreign change to the actor's egress policy was reverted"
		ev.Detail = map[string]any{"foreign_version": m.GetVersion(), "reverts_in_window": len(st.reverts), "window": c.o.ConflictWindow.String(),
			"policy_conflict": st.conflict}
		c.emit(ev)
	}
	c.wrote(st, updated, base, state, how, res)
	if enter {
		ev := base
		ev.Type, ev.Severity = EventPolicyConflict, SeverityAlert
		ev.Message = fmt.Sprintf("%d foreign changes reverted in %s: marked policy_conflict; the actor keeps only the DefenseClaw rule (no other egress) until its policy is DefenseClaw's again",
			len(st.reverts), c.o.ConflictWindow)
		ev.Signal = c.signal(base, SignalPolicyConflict, "", st.firstSeen)
		c.emit(ev)
	}
	return nil
}

func (c *Controller) wrote(st *actorState, p *ateapi.EgressPolicy, base Event, state ateapi.ActorState, how string, res render.Result) {
	st.ourUID, st.ourVersion, st.written = p.GetMetadata().GetUid(), p.GetMetadata().GetVersion(), true
	ev := base
	ev.Type, ev.Severity, ev.Message = EventPolicyWritten, SeverityInfo, "egress policy "+how
	drops := make([]string, 0, len(res.Dropped))
	for _, d := range res.Dropped {
		drops = append(drops, d.Reason)
	}
	bound := make([]string, 0, len(res.Bindings))
	for _, b := range res.Bindings {
		bound = append(bound, b.Secret+"@"+b.Host)
	}
	ev.Detail = map[string]any{"how": how, "version": p.GetMetadata().GetVersion(), "rules": len(p.GetRules()),
		"actor_state": state.String(), "policy_lag_ms": c.o.Now().Sub(st.firstSeen).Milliseconds(), "dropped": drops, "secrets_bound": bound}
	c.emit(ev)
}

func (c *Controller) recheck(st *actorState, a *ateapi.Actor, base Event, how string) {
	if a.GetStatus().GetState() != ateapi.ActorStateResuming {
		return
	}
	gen := a.GetStatus().GetLastAssignedGeneration()
	if st.recheckGen == gen && gen != 0 {
		return
	}
	st.recheckGen = gen
	ev := base
	ev.Type, ev.Severity, ev.Message = EventResumeRecheck, SeverityInfo, "policy re-checked on resume: "+how
	ev.Detail = map[string]any{"generation": gen, "policy_version": st.ourVersion}
	c.emit(ev)
}

func (c *Controller) fail(base Event, msg string) {
	ev := base
	ev.Type, ev.Severity, ev.Message = EventPolicyWriteFailed, SeverityWarn, msg
	c.emit(ev)
}

func (c *Controller) emit(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = c.o.Now()
	}
	c.o.Sink.Emit(ev)
}

// KitAccepted reports whether a kit version is N or N-1 of ours: the same
// major version and our minor or the one before it (a newer minor, from a
// template built ahead of a controller rollout, is accepted too). An
// unparseable version of ours (a dev build) accepts every kit; an
// unparseable kit is refused.
func KitAccepted(ours, kit string) bool {
	om, on, ok := majorMinor(ours)
	if !ok {
		return true
	}
	km, kn, ok := majorMinor(kit)
	if !ok {
		return false
	}
	return km == om && (kn == on || kn == on-1 || kn > on)
}

func majorMinor(v string) (int, int, bool) {
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return ma, mi, true
}

// unmanaged handles an actor DefenseClaw does not (or no longer) manage. A
// policy that carries DefenseClaw's actor rule was written by DefenseClaw
// while the actor was managed; it is removed once, so the actor falls to
// default deny instead of keeping DefenseClaw's allow list, JWT and secret
// rules with nothing enforcing them (GAP-0083). Other writers' policies on
// unmanaged actors are left alone.
func (c *Controller) unmanaged(ctx context.Context, a *ateapi.Actor, st *actorState, base Event) error {
	if st.unmanagedChecked {
		return nil
	}
	ref := ateapi.RefOf(a.GetMetadata())
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ref)
	if ateapi.IsNotFound(err) {
		st.unmanagedChecked, st.written, st.ourVersion = true, false, 0
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: get policy: %w", st.key, err)
	}
	if !st.written && !render.IsDefenseClaw(cur, c.o.Settings) {
		st.unmanagedChecked = true
		return nil
	}
	if _, err := c.o.Client.DeleteActorEgressPolicy(ctx, ref, &ateapi.DeleteOptions{Uid: cur.GetMetadata().GetUid(), Version: cur.GetMetadata().GetVersion()}); err != nil && !ateapi.IsNotFound(err) {
		return fmt.Errorf("%s: remove policy: %w", st.key, err)
	}
	st.unmanagedChecked, st.written, st.ourVersion, st.conflict, st.reverts = true, false, 0, false, nil
	ev := base
	ev.Type, ev.Severity, ev.Message = EventPolicyRemoved, SeverityWarn, "egress policy removed: DefenseClaw no longer manages the actor"
	c.emit(ev)
	return nil
}

// imageRepo is the repository name of an image reference, or the reference
// itself when it does not parse.
func imageRepo(image string) string {
	if r, err := attest.ParseRef(image); err == nil {
		return r.Name()
	}
	return image
}

// SetLifecycle sets the lifecycle sink before Run (the CLI wiring).
func (c *Controller) SetLifecycle(l LifecycleSink) { c.o.Lifecycle = l }

// maxPendingLifecycle bounds an actor's undelivered lifecycle events while
// the leader is unreachable; the oldest go first (the leader orders by the
// controller time it gets).
const maxPendingLifecycle = 64

// lifecycleOf is the lifecycle event of a state change, "" for none. Every
// way into SUSPENDED is suspended: the leader pauses the actor's running
// time only on that event (a revert or a crash ends SUSPENDED too).
func lifecycleOf(prev, cur ateapi.ActorState) string {
	if prev == cur {
		return ""
	}
	switch cur {
	case ateapi.ActorStateSuspended:
		switch prev {
		case ateapi.ActorStateRunning, ateapi.ActorStateSuspending, ateapi.ActorStateResuming, ateapi.ActorStateReverting, ateapi.ActorStateCrashed:
			return chainstate.LifecycleSuspended
		}
	case ateapi.ActorStateRunning:
		if prev == ateapi.ActorStateSuspended || prev == ateapi.ActorStateResuming || prev == ateapi.ActorStateReverting {
			return chainstate.LifecycleResumed
		}
	case ateapi.ActorStateReverting:
		return chainstate.LifecycleReverted
	case ateapi.ActorStateCrashed:
		return chainstate.LifecycleCrashed
	}
	return ""
}

// restoreID is an actor's snapshot identity in one pass: the fields a revert
// changes even when the controller never sees REVERTING. Measured on a real
// cluster (E1, substrate-1 f8): a suspend assigns last_assigned_generation
// to a new newest snapshot whose files stay on the node (locality); a resume
// keeps them; a revert assigns no generation and either drops a newest
// snapshot not yet uploaded (it goes stale) or clears the newest snapshot's
// locality; a running actor comes back on another worker process.
type restoreID struct {
	lastGen  int32 // last_assigned_generation
	headGen  int32 // newest snapshot generation, 0 for none
	headUUID string
	local    bool   // the newest snapshot's files are on a node
	worker   string // worker pod UID and epoch while placed
}

func restoreIDOf(s *ateapi.ActorStatus) restoreID {
	id := restoreID{lastGen: s.GetLastAssignedGeneration()}
	for _, sn := range s.GetSnapshots() {
		if sn.GetGeneration() > id.headGen {
			id.headGen, id.headUUID, id.local = sn.GetGeneration(), sn.GetUuid(), sn.GetLocality() != ""
		}
	}
	if w := s.GetWorkerAssignment(); w.GetWorkerEpoch() != 0 {
		id.worker = w.GetWorkerPodUid() + "/" + strconv.FormatInt(w.GetWorkerEpoch(), 10)
	}
	return id
}

// freshSuspend reports the state a suspend leaves: the newest snapshot is
// the last assigned generation and its files are still on the node.
func (id restoreID) freshSuspend() bool { return id.headGen == id.lastGen && id.local }

// revertSeen reports a revert between the last pass (prev, was) and this
// one (cur, now) that the state change alone does not show (a REVERTING
// state seen in a pass is sent by lifecycleOf). A detach (no public call;
// it also clears locality) reads as a revert: an extra mutation barrier is
// the safe side.
func revertSeen(prev, cur ateapi.ActorState, was, now restoreID) bool {
	suspendedSince := now.lastGen > was.lastGen // a suspend ran since the last pass
	switch {
	case prev == ateapi.ActorStateSuspended && cur == ateapi.ActorStateSuspended:
		if suspendedSince { // resumed and suspended again inside one poll
			return !now.freshSuspend()
		}
		// The node-local snapshot a SUSPENDED actor holds is gone.
		return was.local && (!now.local || now.headUUID != was.headUUID)
	case prev == ateapi.ActorStateRunning && cur == ateapi.ActorStateRunning:
		if suspendedSince { // suspended and resumed inside one poll
			return now.headGen < now.lastGen
		}
		// Reverted and resumed inside one poll: the files left the node or
		// the actor runs under another worker process.
		return (was.local && !now.local) || (was.worker != "" && now.worker != "" && now.worker != was.worker)
	case cur == ateapi.ActorStateSuspended:
		switch prev {
		case ateapi.ActorStateReverting:
			return false // sent when REVERTING was seen
		case ateapi.ActorStateCrashed:
			return true // only a revert brings a crashed actor back
		case ateapi.ActorStateRunning:
			if !suspendedSince {
				return true // a revert of the running actor: no new generation
			}
		}
		// A suspend ran; anything but its fresh snapshot means a revert
		// followed it inside one poll.
		return !now.freshSuspend()
	}
	return false
}

// flushLifecycle sends st's pending lifecycle events in order; the first
// failure keeps it and the rest for the next pass (one warning).
func (c *Controller) flushLifecycle(ctx context.Context, st *actorState, base Event) {
	if c.o.Lifecycle == nil {
		st.pendingLife = nil
		return
	}
	for len(st.pendingLife) > 0 {
		if err := c.sendLifecycle(ctx, st.pendingLife[0]); err != nil {
			if len(st.pendingLife) > maxPendingLifecycle {
				st.pendingLife = st.pendingLife[len(st.pendingLife)-maxPendingLifecycle:]
			}
			if !st.lifeWarned {
				st.lifeWarned = true
				ev := base
				ev.Type, ev.Severity, ev.Message = EventWarning, SeverityWarn, "lifecycle event not delivered to the leader, retrying: "+err.Error()
				c.emit(ev)
			}
			return
		}
		st.pendingLife = st.pendingLife[1:]
		st.lifeWarned = false
	}
}

// sendLifecycle delivers one event. A delete first marks the registration
// deleted: the leader purges an actor's chain state only for a deleted
// registration (substrate-1 GAP-0142), so the tombstone must land first and
// a failed write keeps the event for the next pass.
func (c *Controller) sendLifecycle(ctx context.Context, ev chainstate.LifecycleEvent) error {
	if ev.Event == chainstate.LifecycleDeleted {
		if t, ok := c.o.Registry.(Tombstoner); ok {
			if err := t.MarkDeleted(ctx, ev.Actor.Atespace, ev.Actor.UID); err != nil {
				return fmt.Errorf("mark the registration deleted: %w", err)
			}
		}
	}
	_, err := c.o.Lifecycle.Lifecycle(ctx, ev)
	return err
}

func (c *Controller) retryLifecycle(ctx context.Context) {
	c.mu.Lock()
	retry := c.lifeRetry
	c.lifeRetry = nil
	c.mu.Unlock()
	for _, st := range retry {
		ns, name, _ := strings.Cut(st.key, "/")
		c.flushLifecycle(ctx, st, Event{Atespace: ns, Actor: name, ActorUID: st.uid})
		if len(st.pendingLife) > 0 {
			c.mu.Lock()
			c.lifeRetry = append(c.lifeRetry, st)
			c.mu.Unlock()
		}
	}
}

// TemplateSkillDigests returns the admitted skill folder digests of an
// attested template (Attestation.SkillDigests), from the controller's
// template cache. ok is false when the template is not attested: then no
// folder is trusted by digest (GAP-0164).
func (c *Controller) TemplateSkillDigests(ctx context.Context, ref *ateapi.ObjectRef) (digests []string, ok bool, err error) {
	_, att, err := c.template(ctx, ref, false)
	if err != nil {
		return nil, false, err
	}
	if !att.Attested {
		return nil, false, nil
	}
	return att.SkillDigests, true, nil
}
