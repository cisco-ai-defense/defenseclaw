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
}

type cachedTemplate struct {
	tmpl *ateapi.ActorTemplate
	att  Attestation
	at   time.Time
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
	recheckGen  int32
	reg         Registration
	regOK       bool
	regAt       time.Time
	written     bool
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
		unlisted: map[string]bool{}, warnedList: map[string]bool{}}, nil
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
	actors, err := c.listActors(ctx)
	if err != nil {
		return err
	}
	now := c.o.Now()
	seen := make(map[string]bool, len(actors))
	var urgent, rest []*ateapi.Actor
	c.mu.Lock()
	for _, a := range actors {
		uid := a.GetMetadata().GetUid()
		seen[uid] = true
		_, known := c.actors[uid]
		if !known {
			c.actors[uid] = &actorState{uid: uid, key: ateapi.Key(ateapi.RefOf(a.GetMetadata())), firstSeen: now}
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
		switch code := status.Code(err); {
		case err == nil:
			c.listOK(ns)
		case code == codes.PermissionDenied || code == codes.NotFound:
			// One atespace without a grant (not bootstrapped yet) or gone
			// must not stop the others: its actors stay default deny
			// (GAP-0119). One warning until it lists again.
			if c.listFailedOnce(ns) {
				c.emit(Event{Type: EventWarning, Severity: SeverityWarn, Atespace: ns,
					Message: "cannot list actors in managed atespace " + ns + " (" + code.String() + "): its actors get no policy until DefenseClaw is granted editor there"})
			}
			continue
		default:
			failed = append(failed, ns)
			if len(failed) == len(names) {
				return nil, fmt.Errorf("list actors in %s: %w", ns, err)
			}
			continue
		}
		out = append(out, actors...)
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

// EnsurePolicy reconciles one actor now, for a caller (the launcher's
// create path) that resumes the actor only after its policy is written. It
// returns ErrRefused (wrapped with the reason) when the actor gets no
// policy.
func (c *Controller) EnsurePolicy(ctx context.Context, ref *ateapi.ObjectRef) error {
	a, err := c.o.Client.GetActor(ctx, ref)
	if err != nil {
		return err
	}
	uid := a.GetMetadata().GetUid()
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
	defer st.mu.Unlock()
	switch {
	case st.refused != "":
		return fmt.Errorf("%w: %s", ErrRefused, st.refused)
	case !st.written:
		return fmt.Errorf("%w: not managed by DefenseClaw", ErrRefused)
	}
	return nil
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
	st.lastState = state
	base := Event{Atespace: md.GetAtespace(), Actor: md.GetName(), ActorUID: md.GetUid()}

	_, launcher := c.o.LauncherAtespaces[md.GetAtespace()]
	reg, refuse, err := c.attribution(ctx, a, st, launcher, base)
	if err != nil {
		return err
	}
	if first {
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
			return c.unmanaged(ctx, a, st, base)
		}
		st.unmanagedChecked = false
		if res.Refuse != "" {
			c.refuseOnce(st, base, EventProfileRefused, res.Refuse, "", "")
		} else if c.admit(ctx, a, st, base, res.Profile.Name) == "" {
			if err := c.apply(ctx, a, st, reg, res.Profile, base); err != nil {
				return err
			}
			return c.idle(ctx, a, st, reg, base)
		}
	}
	// Refused: no policy, so the actor falls to default deny.
	return c.removePolicy(ctx, a, st, base)
}

// attribution finds or creates the actor's registration. A non-empty
// refuse means the actor gets no policy.
func (c *Controller) attribution(ctx context.Context, a *ateapi.Actor, st *actorState, launcher bool, base Event) (Registration, string, error) {
	now := c.o.Now()
	if st.regOK && now.Sub(st.regAt) < registrationTTL {
		st.reg.Template = ateapi.Key(a.GetActorTemplate())
		return st.reg, "", nil
	}
	md := a.GetMetadata()
	reg, ok, err := c.o.Registry.Get(ctx, md.GetAtespace(), md.GetUid())
	if err != nil {
		return Registration{}, "", fmt.Errorf("%s: registry: %w", st.key, err)
	}
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
	st.reg, st.regOK, st.regAt = reg, true, now
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
	tmpl, att, err := c.template(ctx, a.GetActorTemplate())
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
	if att.Attested {
		// PLAN §5.3 step 2: an attested digest that a profile allows.
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

func (c *Controller) template(ctx context.Context, ref *ateapi.ObjectRef) (*ateapi.ActorTemplate, Attestation, error) {
	k := ateapi.Key(ref)
	now := c.o.Now()
	c.mu.Lock()
	ct, ok := c.templates[k]
	c.mu.Unlock()
	if ok && now.Sub(ct.at) < templateCacheTTL && (ct.att.ValidUntil.IsZero() || now.Before(ct.att.ValidUntil)) {
		return ct.tmpl, ct.att, nil
	}
	tmpl, err := c.o.Client.GetActorTemplate(ctx, ref)
	if err != nil {
		return nil, Attestation{}, err
	}
	// Always attest again after the TTL, even for an unchanged template: a
	// revoked key, rotated anchors or a raised policy generation must reach
	// templates admitted before (GAP-0054). The attestor caches the
	// registry work itself.
	att, err := c.o.Attestor.Attest(ctx, tmpl)
	if err != nil {
		att = Attestation{Reason: "attestation check failed: " + err.Error()}
	}
	ct = cachedTemplate{tmpl: tmpl, att: att, at: now}
	c.mu.Lock()
	c.templates[k] = ct
	c.mu.Unlock()
	return ct.tmpl, ct.att, nil
}

// refuseOnce records why an actor gets no policy, emitting the event (and
// a shadow AI signal when signalID is set) once per reason.
func (c *Controller) refuseOnce(st *actorState, base Event, typ, msg, signalID, version string) {
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

func (c *Controller) apply(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, profile render.Profile, base Event) error {
	st.refused = ""
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
	if st.conflict {
		want = deny
	}
	state := a.GetStatus().GetState()
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ref)
	if ateapi.IsNotFound(err) {
		created, err := c.o.Client.CreateActorEgressPolicy(ctx, ref, want)
		if ateapi.IsAlreadyExists(err) {
			return nil // another pass or writer won; the next pass compares
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
	if foreign && !st.conflict {
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
		if enter {
			st.conflict = false // decide again on the next pass
			st.reverts = st.reverts[:len(st.reverts)-1]
		}
		return nil // changed under us; the next pass decides again
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
