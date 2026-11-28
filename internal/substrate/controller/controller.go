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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
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
	// DefaultAttachMaxAge is three of the gateway's attachment reports
	// (one a minute, gateway.substrateAttachReportEvery).
	DefaultAttachMaxAge = 3 * time.Minute
	// DefaultTaskEndGrace is how long a finished --task actor keeps its
	// worker before it is suspended (GAP-0274): time for the launcher that
	// followed it to read the end; pull, logs and connect wake it.
	DefaultTaskEndGrace = time.Minute
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
	// CPU, when set, is the CPU source of idle suspend: an idle actor also
	// needs a fresh low sample. Without one an idle actor needs no open
	// terminal attachment (AttachSource, GAP-0534), unless
	// IdleSuspendWithoutCPU makes silence alone enough (GAP-0465).
	CPU      CPUSource
	Registry Registry
	Resolver ProfileResolver
	Sink     Sink

	// Settings are the cluster render settings; Secrets the configured
	// secrets (see SettingsFromConfig and SecretsFromConfig).
	Settings render.Settings
	Secrets  []render.Secret
	// Bindings returns one person's self-service bindings (see
	// BindingsFrom); nil when self-service secrets are off. It is part of
	// the first Live, so bindings render before any config change.
	Bindings func(person string) []render.Secret
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
	// CalloutMode is what another callout in Substrate's egress callout
	// slot does to actor policies (Live.CalloutMode; GAP-0505). The slot
	// is read only with SetCallout.
	CalloutMode string
	// IdleSuspendAfter 0 turns idle suspend off.
	IdleSuspendAfter time.Duration
	// IdleSuspendWithoutCPU (substrate.idle_suspend_without_cpu): without
	// a CPU source, silence alone is idle, an attached actor's too.
	IdleSuspendWithoutCPU bool
	// AttachMaxAge is how long an attachment report means an attachment is
	// open; default DefaultAttachMaxAge.
	AttachMaxAge    time.Duration
	IdleCPU         float64
	CPUSampleMaxAge time.Duration
	// TaskEndGrace is how long a finished --task actor runs on before it
	// is suspended; default DefaultTaskEndGrace.
	TaskEndGrace time.Duration

	IdleInterval, FastInterval, FastWindow time.Duration
	Workers                                int
	PageSize                               int32
	ConflictWindow                         time.Duration
	ConflictReverts                        int

	Now func() time.Time

	// Config, when set, is config.yaml as it is now; Live builds the
	// config-decided options from it. A change applies at the start of the
	// next pass, and in EnsurePolicy (GAP-0276). Without Config the
	// options above stay as given.
	Config ConfigSource
	Live   func(*config.Config) Live
}

// Controller reconciles actors with their DefenseClaw policy.
type Controller struct {
	o Options
	// cur is the config-decided part of the options (Live), replaced
	// whole on a config change; reloadMu orders the replacements.
	cur      atomic.Pointer[Live]
	reloadMu sync.Mutex

	mu        sync.Mutex
	actors    map[string]*actorState // by actor UID
	templates map[string]cachedTemplate
	// inUse is, by template, the atespaces of the actors the last pass
	// listed that use it: only these templates' verdicts count for the
	// unattested-templates gauge, and an expired verdict of another
	// template is dropped (GAP-0583). An actor's template reference names
	// its own atespace, which can be another than the actor's, so an
	// atespace the pass could not list keeps its actors' templates by the
	// actors' atespace.
	inUse     map[string]map[string]bool
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
	// retired are atespaces a config change stopped managing, listed once
	// more by a scoped controller; listed is what the last scoped pass
	// listed (GAP-0295).
	retired, listed map[string]bool
	// startedAt is when this controller started: an actor created before
	// it may have been admitted by the controller it replaced (an upgrade).
	startedAt time.Time
	// allowlisted are the templates that fail only the 1.0.10 allowlist,
	// with the reason last alerted (GAP-0354).
	allowlisted map[string]string
	// unseparated are the templates whose relay runs as the agent's user,
	// already named in an audit warning (GAP-0372).
	unseparated map[string]bool
	// runningAt is when the running report last went to the leader;
	// runningWarned is set while it fails (GAP-0539).
	runningAt     time.Time
	runningWarned bool
	// draining is the draining workers of the pass in progress, and
	// workersWarned says the listing failed once (GAP-0449).
	draining      ateapi.Draining
	workersWarned bool
	// callout is the egress callout slot as last read (GAP-0505).
	callout calloutWatch
}

// runningReportInterval is how often the controller tells the leader which
// actors it sees running. Well under chainstate.ActiveGap, so a quiet actor
// that runs keeps its running-time clock going between two reports and a
// missed report or two costs nothing (GAP-0539).
const runningReportInterval = time.Minute

// runningReportTimeout bounds one running report, so a leader outage does
// not hold the pass.
const runningReportTimeout = 5 * time.Second

// reportRunning tells the leader which listed actors are in state RUNNING,
// at most once per runningReportInterval. Wall time while an actor runs is
// its chain window's running time, also when it makes no request: a quiet
// actor's secret read ages out after 30 minutes of running, as documented
// (how-it-works, the secret-read chain; GAP-0539). Only RUNNING is reported:
// an actor in any other or an unknown state, a pass that did not list it,
// and a failed report leave its clock paused, so a window lasts longer,
// never shorter.
func (c *Controller) reportRunning(ctx context.Context, actors []*ateapi.Actor, now time.Time) {
	rs, ok := c.o.Lifecycle.(RunningSink)
	if !ok || now.Sub(c.runningAt) < runningReportInterval {
		return
	}
	c.runningAt = now
	var running []chainstate.Actor
	for _, a := range actors {
		if a.GetStatus().GetState() == ateapi.ActorStateRunning {
			md := a.GetMetadata()
			running = append(running, chainstate.Actor{Atespace: md.GetAtespace(), UID: md.GetUid()})
		}
	}
	var err error
	for len(running) > 0 && err == nil {
		n := min(len(running), chainstate.MaxRunningActors)
		rctx, cancel := context.WithTimeout(ctx, runningReportTimeout)
		err = rs.Running(rctx, running[:n])
		cancel()
		running = running[n:]
	}
	switch {
	case err != nil && !c.runningWarned:
		c.runningWarned = true
		c.emit(Event{Type: EventWarning, Severity: SeverityWarn,
			Message: "the leader did not take the report of running actors (their chain windows' running time is paused until it does): " + err.Error()})
	case err == nil:
		c.runningWarned = false
	}
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
	// stoppedAt is the last time the actor was seen not running (as read
	// from the control API, or suspended by this controller); zero when it
	// has been running since this controller first saw it. A task end after
	// it belongs to the actor's current run (GAP-0411).
	stoppedAt time.Time
	// ourUID/ourVersion identify the policy version this controller last
	// wrote or confirmed; a different version is a foreign change.
	ourUID     string
	ourVersion int64
	reverts    []time.Time
	conflict   bool
	// conflictMarkWarned is set while the registration's policy_conflict
	// mark cannot be written (one warning per outage, GAP-0398).
	conflictMarkWarned bool
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
	// resumed is set for the pass that saw the actor come back from a
	// suspend (the resume re-check is due even when RESUMING fell between
	// two passes).
	resumed  bool
	reg      Registration
	regOK    bool
	regAt    time.Time
	regState ateapi.ActorState
	// kitFillWarned is set once a later attribution of the actor's attested
	// kit could not be written (GAP-0351), so it warns once, not every pass.
	kitFillWarned bool
	// regStaleWarned is set while a leader outage keeps the last good
	// registration in use (one warning per outage).
	regStaleWarned bool
	// forkQueued and inventoried make the once-per-incarnation fork event
	// and inventory event survive a failed first pass; forkReported is the
	// sandbox.fork event of a fork that is never registered (refused in a
	// launcher atespace), once.
	forkQueued, inventoried, forkReported bool
	// rid is the snapshot identity seen on the last pass; a revert is told
	// from how it changed (GAP-0141).
	rid     restoreID
	written bool
	// deleteDenied is set while the access policies refuse the delete of the
	// actor's policy; the alert is sent once (GAP-0481). deleteRetry is when
	// the delete is tried again, deleteWait the current backoff (GAP-0531).
	deleteDenied bool
	deleteRetry  time.Time
	deleteWait   time.Duration
	// foreignTemplateRead is set once the template of a foreign actor was
	// read and, if unattested, reported (GAP-0495).
	foreignTemplateRead bool
	// syncedAt is when the controller last wrote or confirmed the actor's
	// policy; staleSince when it saw that the policy needs a write (zero
	// while it does not). policy_lag_ms of a write is measured from
	// staleSince, not from when the actor was first seen (GAP-0392).
	syncedAt, staleSince time.Time
	// drainResume: this controller suspended the actor off a draining
	// worker and resumes it (GAP-0449); drainFrom is that worker's pod.
	drainResume, drainResumeWarned bool
	drainFrom                      string
	// unmanagedChecked is set once an unmanaged actor's policy was checked
	// for a DefenseClaw policy left from when it was managed.
	unmanagedChecked bool
	// allowlistWarned is the allowlist refusal the actor was last warned
	// about while it keeps running (GAP-0354).
	allowlistWarned string
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
	def(&o.TaskEndGrace, DefaultTaskEndGrace)
	def(&o.AttachMaxAge, DefaultAttachMaxAge)
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
	if o.Config != nil && o.Live == nil {
		return nil, errors.New("controller: Config needs Live")
	}
	c := &Controller{o: o, actors: map[string]*actorState{}, templates: map[string]cachedTemplate{},
		unlisted: map[string]bool{}, warnedList: map[string]bool{}, uidByKey: map[string]string{}, retired: map[string]bool{},
		startedAt: o.Now(), allowlisted: map[string]string{}, unseparated: map[string]bool{}}
	lv := &Live{Settings: o.Settings, Secrets: o.Secrets, Bindings: o.Bindings, LauncherAtespaces: o.LauncherAtespaces, RequireAttestation: o.RequireAttestation,
		Templates: o.Templates, Attestor: o.Attestor, Resolver: o.Resolver, IdleSuspendAfter: o.IdleSuspendAfter,
		IdleSuspendWithoutCPU: o.IdleSuspendWithoutCPU, LoadedAt: o.Now(), CalloutMode: o.CalloutMode}
	if o.Config != nil {
		_, lv.Digest = o.Config.Current()
	}
	c.cur.Store(lv)
	return c, nil
}

// Run polls until ctx ends: every IdleInterval, or every FastInterval for
// FastWindow after new or resuming actors were seen (batch starts).
func (c *Controller) Run(ctx context.Context) error {
	if c.calloutPublishes() {
		// The gateway reads the egress callout slot from these reports
		// (GAP-0505): they keep coming while a pass runs long.
		go c.watchCallout(ctx)
	}
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
	c.reloadConfig(ctx)
	c.checkCallout(ctx)
	c.applyResets(ctx)
	c.retryLifecycle(ctx)
	// The list shows each actor's state as of listedAt or later.
	listedAt := c.o.Now()
	actors, err := c.listActors(ctx)
	if err != nil {
		return err
	}
	draining := c.drainingWorkers(ctx)
	c.mu.Lock()
	c.draining = draining
	c.mu.Unlock()
	now := c.o.Now()
	seen := make(map[string]bool, len(actors))
	var urgent, rest []*ateapi.Actor
	var recreated []recreatedActor
	inUse := map[string]map[string]bool{}
	use := func(tmpl, ns string) {
		if inUse[tmpl] == nil {
			inUse[tmpl] = map[string]bool{}
		}
		inUse[tmpl][ns] = true
	}
	c.mu.Lock()
	for k, by := range c.inUse {
		for ns := range by {
			// An atespace this pass could not list keeps its actors'
			// templates.
			if c.unlisted[ns] {
				use(k, ns)
			}
		}
	}
	for _, a := range actors {
		uid := a.GetMetadata().GetUid()
		seen[uid] = true
		if t := a.GetActorTemplate(); t != nil {
			use(ateapi.Key(t), a.GetMetadata().GetAtespace())
		}
		_, known := c.actors[uid]
		if !known {
			key := ateapi.Key(ateapi.RefOf(a.GetMetadata()))
			c.actors[uid] = &actorState{uid: uid, key: key, firstSeen: now}
			if prev, ok := c.uidByKey[key]; ok && prev != uid && c.live().LauncherAtespaces[a.GetMetadata().GetAtespace()] {
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
	c.inUse = inUse
	for k, ct := range c.templates {
		if len(inUse[k]) == 0 && now.Sub(ct.at) >= templateCacheTTL {
			delete(c.templates, k)
		}
	}
	var gone []*actorState
	for uid, st := range c.actors {
		ns, _, _ := strings.Cut(st.key, "/")
		if !seen[uid] && c.unlisted[ns] {
			continue // not listed this pass, not known to be deleted
		}
		if !seen[uid] && c.scoped && !c.listed[ns] {
			// Its atespace is no longer managed and was not listed: the
			// actor is not deleted, it left DefenseClaw's view (GAP-0295).
			delete(c.actors, uid)
			continue
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
			if err := c.reconcileActor(ctx, a, listedAt); err != nil {
				emu.Lock()
				errs = append(errs, err)
				emu.Unlock()
			}
		})
	}
	c.reportRunning(ctx, actors, now)
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
	set := managedSet(c.live())
	c.mu.Lock()
	for ns := range c.retired {
		set[ns] = true
	}
	c.listed = set
	c.mu.Unlock()
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
			c.mu.Lock()
			delete(c.retired, ns)
			c.mu.Unlock()
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

// ConflictMarker is a Registry that can record an actor's policy_conflict on
// its registration (LeaderRegistry), so the gateway shows it to the person
// and to administrators (GAP-0398); c nil clears the mark.
type ConflictMarker interface {
	MarkConflict(ctx context.Context, atespace, uid string, c *registry.PolicyConflict) error
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
	c.reloadConfig(ctx)
	c.checkCallout(ctx)
	for try := 1; ; try++ {
		readAt := c.o.Now()
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
		if err := c.reconcileActor(ctx, a, readAt); err != nil {
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

// reconcileActor decides one actor. seenAt is when its state was read (no
// later than the read itself).
func (c *Controller) reconcileActor(ctx context.Context, a *ateapi.Actor, seenAt time.Time) error {
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
	if state != ateapi.ActorStateRunning && seenAt.After(st.stoppedAt) {
		st.stoppedAt = seenAt
	}
	first := st.lastState == ateapi.ActorStateUnspecified
	prev := st.lastState
	st.lastState = state
	base := Event{Atespace: md.GetAtespace(), Actor: md.GetName(), ActorUID: md.GetUid()}
	self := chainstate.Actor{Atespace: md.GetAtespace(), UID: md.GetUid()}
	rid := restoreIDOf(a.GetStatus())
	st.resumed = false
	if !first {
		evs := []string{lifecycleOf(prev, state)}
		if prev == state && rid.lastGen > st.rid.lastGen {
			// A suspend ran since the last pass (it assigned a generation)
			// and the actor is back in the state it was: a suspend and a
			// resume inside one poll (a checkpoint, kubectl ate suspend then
			// a connect) still leave their records and the resume re-check
			// (GAP-0486).
			switch state {
			case ateapi.ActorStateRunning:
				evs = []string{chainstate.LifecycleSuspended, chainstate.LifecycleResumed}
			case ateapi.ActorStateSuspended:
				evs = []string{chainstate.LifecycleResumed, chainstate.LifecycleSuspended}
			}
		}
		if revertSeen(prev, state, st.rid, rid) {
			// Told from the snapshot identity, so a revert whose REVERTING
			// fell between two passes, a revert of a SUSPENDED actor and a
			// suspend plus revert inside one poll still put the mutation
			// barrier in the actor's chains (GAP-0141).
			evs = append(evs, chainstate.LifecycleReverted)
		}
		for _, life := range evs {
			if life == "" {
				continue
			}
			st.pendingLife = append(st.pendingLife, chainstate.LifecycleEvent{Actor: self, Event: life, AtUnixNano: now.UnixNano()})
			st.resumed = st.resumed || life == chainstate.LifecycleResumed
			if life == chainstate.LifecycleCrashed {
				// The crash is a record of its own (GAP-0526): the leader
				// closes the actor's open asks with reason actor_crashed
				// when it gets the lifecycle event, and the audit trail
				// says why the actor and its asks stopped.
				ce := base
				ce.Type, ce.Severity, ce.Message = EventCrashed, SeverityWarn, "actor crashed: its open asks are closed (actor_crashed)"
				ce.Detail = map[string]any{"lifecycle": chainstate.LifecycleCrashed, "reason": "actor_crashed"}
				c.emit(ce)
			}
			if !st.inventoried {
				continue // the first record of an actor is "actor seen"
			}
			// One inventory record per transition, so discovery sees a
			// suspend, resume, revert or crash and not only the create and
			// the delete (GAP-0430).
			ev := base
			ev.Type, ev.Severity, ev.Message = EventInventory, SeverityInfo, "actor "+life
			ev.Detail = map[string]any{"lifecycle": life, "state": state.String(), "previous_state": prev.String()}
			c.emit(ev)
		}
	}
	st.rid = rid
	c.flushLifecycle(ctx, st, base)

	st.hold = ""
	// One config snapshot for the whole decision (Live).
	lv := c.live()
	_, launcher := lv.LauncherAtespaces[md.GetAtespace()]
	reg, refuse, err := c.attribution(ctx, a, st, launcher, base)
	if err != nil {
		return err
	}
	// Whatever this pass decides, the registration then carries the
	// conflict state it leaves (GAP-0398).
	defer c.markConflict(ctx, st, base)
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
		// read or the grace ends (GAP-0145). A policy that is not
		// DefenseClaw's is the exception: whoever made the actor outside
		// DefenseClaw wrote it, and it must not stay in force while the
		// controller waits.
		st.hold = RefusalRegistrationPending
		return c.dropForeignPolicy(ctx, a, st, base)
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
		res, err := lv.Resolver.Resolve(reg, launcher)
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
		} else if code, err := c.admit(ctx, a, st, base, res.Profile.Name); err != nil {
			return err
		} else if code == "" {
			booted, err := c.bootedTemplate(ctx, a, st, base)
			if err != nil {
				return err
			}
			if !booted {
				return c.removePolicy(ctx, a, st, base)
			}
			if res.DenyOnly == "" {
				// Another callout holds Substrate's egress slot: what only
				// the DefenseClaw callout enforced follows the fail mode
				// (GAP-0505).
				res.DenyOnly = c.calloutDenyOnly(lv, reg)
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
			if st.resumed && st.hold == "" {
				// The first pass after a resume: a RESUMING that fell between
				// two passes, or one whose pass wrote the policy, still gets
				// its re-check record; recheck sends one per generation
				// (GAP-0430).
				c.recheck(st, a, base, "policy in force")
			}
			// The profile opts --task runs into idle suspend (GAP-0498); the
			// registration only records that the actor is a task.
			reg.IdleSuspendTask = reg.IdleSuspendTask || res.IdleSuspendTasks
			if moved, err := c.drain(ctx, a, st, reg, base); moved || err != nil {
				return err
			}
			return c.idle(ctx, a, st, reg, base, res.idleAfter(lv.IdleSuspendAfter))
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
				// DefenseClaw makes no forks (neither the launcher nor the
				// gateway creates an actor from a tag), so a fork with no
				// registration of its own was made outside DefenseClaw, in
				// a launcher atespace too: forked_by is unknown, and it is
				// not that person's actor, so it gets no person binding (no
				// per-person secrets) (GAP-0425).
				reg.ForkedBy = ForkedByUnknown
				reg.Person, reg.Workload = "", ""
				if !st.forkReported {
					st.forkReported = true
					ev := base
					ev.Type, ev.Severity, ev.Message = EventFork, SeverityInfo, "fork adopted with its parent's attribution"
					if launcher {
						ev.Message = "fork made outside DefenseClaw in a launcher atespace"
					}
					ev.Detail = map[string]any{"parent_uid": parent.UID, "parent": parent.Atespace + "/" + parent.Name,
						"tag": ateapi.Key(tag), "forked_by": reg.ForkedBy, "person_bound": false}
					c.emit(ev)
				}
				if launcher {
					// Only DefenseClaw may fork in a launcher atespace
					// (PLAN E17): the fork is refused like any actor made
					// there outside DefenseClaw.
					c.refuseOnce(st, base, EventForeignActor, "fork in a launcher atespace that DefenseClaw did not make", SignalForeignActor, "")
					return reg, "foreign_actor", nil
				}
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
			if !st.foreignTemplateRead {
				c.foreignTemplate(ctx, a, st, base)
			}
			c.refuseOnce(st, base, EventForeignActor, "actor in a launcher atespace that DefenseClaw did not create", SignalForeignActor, "")
			return reg, "foreign_actor", nil
		}
		if reg.Source == SourceAtespace {
			c.attributeKit(ctx, a, &reg)
		}
		if err := c.o.Registry.Put(ctx, reg); err != nil {
			return Registration{}, "", fmt.Errorf("%s: registry: %w", st.key, err)
		}
	} else if reg.Source == SourceAtespace && reg.Connector == "" {
		c.fillKit(ctx, a, st, base, &reg)
	}
	reg.Template = ateapi.Key(a.GetActorTemplate())
	st.reg, st.regOK, st.regAt, st.regState = reg, true, now, a.GetStatus().GetState()
	return reg, "", nil
}

// foreignTemplate names the unattested template of an actor made outside
// DefenseClaw in a launcher atespace (GAP-0428). Admission never runs for a
// foreign actor (it gets no policy either way), so without this record
// shadow AI would list the actor but not the template behind it, as
// admission does for an actor of any other atespace (PLAN 6.2). It is sent
// once per actor, on the first pass whose template read succeeds: a read
// error is tried again on the next pass (GAP-0495).
func (c *Controller) foreignTemplate(ctx context.Context, a *ateapi.Actor, st *actorState, base Event) {
	if !c.live().RequireAttestation {
		return
	}
	ref := a.GetActorTemplate()
	_, att, err := c.template(ctx, ref, false)
	if err != nil {
		if ateapi.IsNotFound(err) {
			// The template is gone: there is nothing to name, and reading it
			// again every pass would only cost (GAP-0531).
			st.foreignTemplateRead = true
		}
		return
	}
	st.foreignTemplateRead = true
	if att.Attested {
		return
	}
	reason := att.Reason
	if reason == "" {
		reason = "no DefenseClaw attestation"
	}
	ev := base
	ev.Type, ev.Severity = EventTemplateUnverified, SeverityWarn
	ev.Message = "template " + ateapi.Key(ref) + " of an actor made outside DefenseClaw is not attested: " + reason
	ev.Detail = map[string]any{"template": ateapi.Key(ref), "template_digest": att.Digest, "foreign_actor": true}
	ev.Signal = c.signal(base, SignalUnattestedTemplate, att.Digest, st.firstSeen)
	c.emit(ev)
}

// attributeKit puts what the actor's attested template names (connector,
// agent version, hook contract, kit version, digest) in the registration of
// an actor made outside DefenseClaw (GAP-0347). Without them the gateway
// knows no connector for the actor, resolves no hook profile, and reports
// every tool step as unrecorded (GAP-0339); a launched actor gets them from
// the create route (GAP-0201). An unattested template, or one that can't be
// read now, records none: admission decides about the actor, and its steps
// are reported, never skipped. It returns the template it read (nil when it
// recorded nothing).
func (c *Controller) attributeKit(ctx context.Context, a *ateapi.Actor, reg *Registration) *ateapi.ActorTemplate {
	tmpl, att, err := c.template(ctx, a.GetActorTemplate(), false)
	if err != nil || !att.Attested {
		return nil
	}
	reg.Connector, reg.AgentVersion, reg.HookContract = att.Connector, att.AgentVersion, att.HookContract
	reg.KitVersion, reg.TemplateDigest, reg.RelayStreams = att.KitVersion, att.Digest, att.RelayStreams
	return tmpl
}

// fillKit attributes the kit again for an attributed registration that names
// no connector: a template read error or an attestation that could not be
// checked (an ATE API blip, a registry outage) at the first attribution must
// not leave the actor without a connector for its life (GAP-0351). Until it
// is recorded, the actor's tool steps are reported unrecorded (fail closed).
// The kit is recorded only from a template that attests now and was not
// edited after the actor was created, so it is the one the actor booted
// (GAP-0053); the registry takes the kit fields once, into a record that has
// none. It runs when the registration is read again (registrationTTL).
func (c *Controller) fillKit(ctx context.Context, a *ateapi.Actor, st *actorState, base Event, reg *Registration) {
	filled := *reg
	tmpl := c.attributeKit(ctx, a, &filled)
	if tmpl == nil || filled.Connector == "" {
		return
	}
	edited, created := tmpl.GetMetadata().GetUpdateTime(), a.GetMetadata().GetCreateTime()
	if edited == nil || created == nil || edited.AsTime().After(created.AsTime()) {
		return
	}
	if err := c.o.Registry.Put(ctx, filled); err != nil {
		if !st.kitFillWarned {
			st.kitFillWarned = true
			ev := base
			ev.Type, ev.Severity = EventWarning, SeverityWarn
			ev.Message = "the actor's attested connector could not be recorded (its tool steps stay reported unrecorded): " + err.Error()
			c.emit(ev)
		}
		return
	}
	*reg = filled
	ev := base
	ev.Type, ev.Severity = EventWarning, SeverityInfo
	ev.Message = "the actor's attested connector is recorded on a later pass (its template could not be attested at the first one)"
	ev.Detail = map[string]any{"connector": filled.Connector, "template_digest": filled.TemplateDigest}
	c.emit(ev)
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
func (c *Controller) admit(ctx context.Context, a *ateapi.Actor, st *actorState, base Event, profile string) (string, error) {
	// The first admission of an actor reads its template fresh: a cached
	// verdict by name would admit an image swapped in after it (GAP-0053).
	tmpl, att, err := c.template(ctx, a.GetActorTemplate(), !st.written)
	if err != nil {
		c.refuseOnce(st, base, EventTemplateUnverified, "template could not be read: "+err.Error(), "", "")
		return "template_unreadable", nil
	}
	lv := c.live()
	if !att.Attested && lv.RequireAttestation {
		reason := att.Reason
		if reason == "" {
			reason = "no DefenseClaw attestation"
		}
		key := ateapi.Key(ateapi.RefOf(tmpl.GetMetadata()))
		keep := false
		if att.Allowlist && builtBeforeAllowlist(att) {
			if keep, err = c.admittedBefore(ctx, a, st); err != nil {
				return "", err
			}
		}
		if !keep {
			c.refuseOnce(st, base, EventTemplateUnverified, "template "+key+" is not attested: "+reason, SignalUnattestedTemplate, att.Digest)
			return "template_unverified", nil
		}
		// Owner decision for 1.0.10: an actor admitted before the
		// allowlist keeps running and keeps its network; only a warning
		// row. Refusing it too comes in the next release.
		if st.allowlistWarned != reason {
			st.allowlistWarned = reason
			ev := base
			ev.Type, ev.Severity = EventWarning, SeverityWarn
			ev.Message = "the actor keeps running on template " + key + ", which fails the actor allowlist of DefenseClaw 1.0.10 (" + reason +
				"): new actors from it are refused, and DefenseClaw refuses running ones too from the next release; fix the template and recreate the actor"
			ev.Detail = map[string]any{"template": key, "allowlist": reason}
			c.emit(ev)
		}
	}
	{
		// PLAN §5.3 step 2: an attested digest that a profile allows. The
		// allow lists apply with attestation off too (GAP-0131).
		var repos []string
		for _, ct := range tmpl.GetContainers() {
			repos = append(repos, imageRepo(ct.GetImage()))
		}
		if repo, ok := ImagesAllowed(lv.Templates, profile, repos); !ok {
			c.refuseOnce(st, base, EventTemplateUnverified, fmt.Sprintf("image %s is not allowed for profile %s (substrate.templates.allowed_images / profile_images)", repo, profile), SignalUnattestedTemplate, att.Digest)
			return "image_not_allowed", nil
		}
	}
	if att.KitVersion != "" && !KitAccepted(c.o.KitVersion, att.KitVersion) {
		c.refuseOnce(st, base, EventKitRefused, fmt.Sprintf("kit %s is older than N-1 of %s; %s", att.KitVersion, c.o.KitVersion, MigrateHint), SignalOldKit, att.KitVersion)
		return "kit_too_old", nil
	}
	return "", nil
}

// admittedBefore reports whether an actor already runs with DefenseClaw's
// policy from before the allowlist refused its template: this controller
// wrote it, or the actor is older than this controller and carries
// DefenseClaw's policy (the controller it replaced at the upgrade wrote it).
// A policy read that fails is an error: no policy change on this pass.
func (c *Controller) admittedBefore(ctx context.Context, a *ateapi.Actor, st *actorState) (bool, error) {
	if st.written {
		return true, nil
	}
	created := a.GetMetadata().GetCreateTime()
	if created == nil || !created.AsTime().Before(c.startedAt) {
		return false, nil
	}
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ateapi.RefOf(a.GetMetadata()))
	switch {
	case ateapi.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("%s: get policy (holding, no policy change): %w", st.key, err)
	}
	return render.IsDefenseClaw(cur, c.live().Settings), nil
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
	case render.IsDefenseClaw(cur, c.live().Settings):
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
	att, err := c.live().Attestor.Attest(ctx, tmpl)
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
	c.alertAllowlist(k, ref.GetAtespace(), att)
	c.alertUnseparated(k, ref.GetAtespace(), att)
	c.mu.Lock()
	c.templates[k] = ct
	c.mu.Unlock()
	return ct.tmpl, ct.att, nil
}

// alertAllowlist writes one audit alert per template that the 1.0.10
// allowlist refuses (GAP-0354, GAP-0355), naming the template and why, the
// first time and when the reason changes: at the upgrade, every affected
// template is named once.
func (c *Controller) alertAllowlist(k, atespace string, att Attestation) {
	c.mu.Lock()
	prev, seen := c.allowlisted[k]
	switch {
	case att.Allowlist:
		c.allowlisted[k] = att.Reason
	case seen:
		delete(c.allowlisted, k)
	}
	c.mu.Unlock()
	if !att.Allowlist || (seen && prev == att.Reason) {
		return
	}
	c.emit(Event{Type: EventTemplateAllowlist, Severity: SeverityAlert, Atespace: atespace,
		Message: "template " + k + " fails the actor allowlist of DefenseClaw 1.0.10: " + att.Reason + ". " + AllowlistImpact,
		Detail:  map[string]any{"template": k, "allowlist": att.Reason}})
}

// alertUnseparated writes one audit warning per template whose relay runs
// as the agent's own user (GAP-0372): the image's relay prints this only on
// its own stderr, and the operator must know the template is not covered by
// the GAP-0116 fix until it is rebuilt. It is written again after the
// template was fixed and then broken again.
func (c *Controller) alertUnseparated(k, atespace string, att Attestation) {
	c.mu.Lock()
	seen := c.unseparated[k]
	if att.Unseparated != "" {
		c.unseparated[k] = true
	} else {
		delete(c.unseparated, k)
	}
	c.mu.Unlock()
	if att.Unseparated == "" || seen {
		return
	}
	c.emit(Event{Type: EventRelayUnseparated, Severity: SeverityWarn, Atespace: atespace,
		Message: "template " + k + ": " + att.Unseparated,
		Detail:  map[string]any{"template": k, "relay_separated": false}})
}

// allowlistSince is the first DefenseClaw release with the actor
// allowlist: its template build and publish refuse what admission refuses.
const allowlistSince = "1.0.10"

// builtBeforeAllowlist reports whether a template that fails the allowlist
// does so because of the upgrade (owner decision D4, GAP-0373): its
// attestation is from a kit older than the allowlist. A template built with
// the allowlist passed it at build, so it fails only through an edit made
// since (an env variable or a command added by hand): its running actors
// are refused with the new ones, as an actor booting the edit would be new.
// An unknown kit version (a dev build) is treated as built with it.
func builtBeforeAllowlist(att Attestation) bool {
	return versionBefore(att.KitVersion, allowlistSince)
}

// versionBefore reports whether release v is older than w (both
// MAJOR.MINOR.PATCH, a "v" prefix and a "-" or "+" suffix allowed); false
// when either does not parse.
func versionBefore(v, w string) bool {
	a, ok1 := releaseParts(v)
	b, ok2 := releaseParts(w)
	if !ok1 || !ok2 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func releaseParts(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// AllowlistImpact is what the 1.0.10 allowlist does to a template it refuses.
const AllowlistImpact = "New actors from it are refused; actors already running keep running and keep their network with a warning in 1.0.10, and are refused from the next release. Remove the variable, command or volume mount from the template (or the image) and publish it again"

func sameTemplateVersion(a, b *ateapi.ActorTemplate) bool {
	return a.GetMetadata().GetUid() == b.GetMetadata().GetUid() && a.GetMetadata().GetVersion() == b.GetMetadata().GetVersion()
}

// Attestor is the template admission the controller runs now (wiring
// tests); LiveAttestor follows config changes.
func (c *Controller) Attestor() Attestor { return c.live().Attestor }

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

// dropForeignPolicy removes the actor's egress policy when it is not
// DefenseClaw's. It runs while an unregistered, just created actor of a
// launcher atespace is held: DefenseClaw's own policy (written by the create
// path) stays, anything else was written by whoever made the actor and goes
// at once, so the actor keeps no creator-chosen egress during the grace
// (GAP-0145 residual).
func (c *Controller) dropForeignPolicy(ctx context.Context, a *ateapi.Actor, st *actorState, base Event) error {
	ref := ateapi.RefOf(a.GetMetadata())
	cur, err := c.o.Client.GetActorEgressPolicy(ctx, ref)
	if ateapi.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: get policy: %w", st.key, err)
	}
	if render.IsDefenseClaw(cur, c.live().Settings) {
		return nil
	}
	if _, err := c.o.Client.DeleteActorEgressPolicy(ctx, ref, &ateapi.DeleteOptions{Uid: cur.GetMetadata().GetUid(), Version: cur.GetMetadata().GetVersion()}); err != nil && !ateapi.IsNotFound(err) {
		return fmt.Errorf("%s: remove policy: %w", st.key, err)
	}
	ev := base
	// DefenseClaw's own delete: the next create is no foreign change.
	st.written, st.ourVersion = false, 0
	ev.Type, ev.Severity, ev.Message = EventPolicyRemoved, SeverityWarn, "egress policy removed: it is not DefenseClaw's and the actor is not registered yet"
	c.emit(ev)
	return nil
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
	if c.deleteBackingOff(st) {
		return nil
	}
	if _, err := c.o.Client.DeleteActorEgressPolicy(ctx, ref, &ateapi.DeleteOptions{Uid: cur.GetMetadata().GetUid(), Version: cur.GetMetadata().GetVersion()}); err != nil && !ateapi.IsNotFound(err) {
		if c.deleteRefused(st, base, err) {
			return nil
		}
		return fmt.Errorf("%s: remove policy: %w", st.key, err)
	}
	st.written, st.ourVersion, st.deleteDenied, st.deleteRetry = false, 0, false, time.Time{}
	ev := base
	ev.Type, ev.Severity, ev.Message = EventPolicyRemoved, SeverityWarn, "egress policy removed: the actor is refused ("+st.refused+")"
	c.emit(ev)
	return nil
}

// The backoff of a policy delete the access policies refuse (GAP-0531).
const (
	deleteRetryMin = time.Minute
	deleteRetryMax = 30 * time.Minute
)

// deleteBackingOff reports that a refused delete is not due again yet.
func (c *Controller) deleteBackingOff(st *actorState) bool {
	return st.deleteDenied && c.o.Now().Before(st.deleteRetry)
}

// deleteRefused handles a policy delete the access policies refuse
// (PERMISSION_DENIED: DefenseClaw lacks can_delete_egress_policy in that
// atespace, GAP-0481). The actor keeps a policy DefenseClaw wanted gone, so
// one alert names it and the missing right; later passes try again without
// failing the pass, which a reconcile loop would otherwise report about 40
// times a minute. It reports whether err was such a refusal.
func (c *Controller) deleteRefused(st *actorState, base Event, err error) bool {
	if status.Code(err) != codes.PermissionDenied {
		return false
	}
	// Try again after a backoff that doubles, 1 minute up to 30, so a
	// refused delete costs a GET and a DELETE now and then, not every pass
	// (GAP-0531).
	st.deleteWait = min(max(2*st.deleteWait, deleteRetryMin), deleteRetryMax)
	st.deleteRetry = c.o.Now().Add(st.deleteWait)
	if !st.deleteDenied {
		st.deleteDenied = true
		ev := base
		ev.Type, ev.Severity = EventPolicyWriteFailed, SeverityAlert
		ev.Message = "the actor's egress policy should be removed, but DefenseClaw may not delete egress policies in atespace " +
			base.Atespace + " (can_delete_egress_policy); the policy stays in force until an administrator removes it or grants that right"
		ev.Detail = map[string]any{"error": err.Error()}
		c.emit(ev)
	}
	return true
}

// applyOnce is one read-compare-write of the actor's policy (apply).
func (c *Controller) applyOnce(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, profile render.Profile, base Event) error {
	st.refused, st.refusedMsg = "", ""
	ref := ateapi.RefOf(a.GetMetadata())
	lv := c.live()
	secrets := lv.Secrets
	if lv.Bindings != nil && reg.Person != "" {
		secrets = append(slices.Clip(secrets), lv.Bindings(reg.Person)...)
	}
	res, err := render.EgressPolicy(render.Input{Settings: lv.Settings, Profile: profile, Person: reg.Person, Approved: reg.Approved, Secrets: secrets})
	if err != nil {
		c.fail(base, "render: "+err.Error())
		return fmt.Errorf("%s: render: %w", st.key, err)
	}
	full := res.Policy
	deny, err := render.DenyOnly(lv.Settings)
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
		// A policy this controller wrote or confirmed that is gone was
		// deleted by another writer: a foreign change like an edit, so it
		// counts toward policy_conflict (GAP-0400).
		foreign := st.ourVersion != 0
		counted, enter := c.countRevert(st, foreign)
		if enter {
			want = deny
		}
		c.markStale(st, lv)
		created, err := c.o.Client.CreateActorEgressPolicy(ctx, ref, want)
		if ateapi.IsAlreadyExists(err) {
			c.uncountRevert(st, counted)
			return errWriteRace // another writer won: read it again and compare
		}
		if err != nil {
			c.uncountRevert(st, counted)
			c.fail(base, "create policy: "+err.Error())
			return fmt.Errorf("%s: create policy: %w", st.key, err)
		}
		how := "created"
		switch {
		case foreign && st.conflict:
			how = "restored deny-only (policy_conflict)"
		case foreign:
			how = "restored"
		case st.conflict:
			how = "created deny-only (policy_conflict)"
		}
		c.landed(st, created, base, state, how, res, foreign, enter,
			"the actor's egress policy was deleted by another writer and restored", map[string]any{"deleted": true})
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
		c.synced(st)
		ev := base
		ev.Type, ev.Severity, ev.Message = EventConflictCleared, SeverityInfo, "the actor's policy matches DefenseClaw's again"
		c.emit(ev)
		c.recheck(st, a, base, "confirmed")
		return nil
	}
	if render.Equal(cur, want) {
		st.ourUID, st.ourVersion, st.written = m.GetUid(), m.GetVersion(), true
		c.synced(st)
		c.recheck(st, a, base, "confirmed")
		return nil
	}
	foreign := st.ourVersion != 0 && !ours
	counted, enter := c.countRevert(st, foreign)
	if enter {
		want = deny
	}
	c.markStale(st, lv)
	upd := &ateapi.EgressPolicy{Metadata: &ateapi.ResourceMetadata{Uid: m.GetUid(), Version: m.GetVersion()}, Rules: want.GetRules()}
	updated, err := c.o.Client.UpdateActorEgressPolicy(ctx, ref, upd)
	if ateapi.IsConflict(err) {
		c.uncountRevert(st, counted)
		return errWriteRace // changed under us: read again and decide again
	}
	if err != nil {
		c.uncountRevert(st, counted)
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
	c.landed(st, updated, base, state, how, res, foreign, enter,
		"a foreign change to the actor's egress policy was reverted", map[string]any{"foreign_version": m.GetVersion()})
	return nil
}

// countRevert counts a foreign change (an edit or a delete) toward the
// conflict rule: ConflictReverts in ConflictWindow mark policy_conflict
// (enter). Inside a conflict nothing is counted.
func (c *Controller) countRevert(st *actorState, foreign bool) (counted, enter bool) {
	if !foreign || st.conflict {
		return false, false
	}
	now := c.o.Now()
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
		st.conflict = true
		return true, true
	}
	return true, false
}

// uncountRevert takes back a counted revert whose write did not land: the
// next try decides again.
func (c *Controller) uncountRevert(st *actorState, counted bool) {
	if counted {
		st.conflict = false
		st.reverts = st.reverts[:len(st.reverts)-1]
	}
}

// landed reports a policy write: the foreign_rule event of a revert (one
// per revert outside a conflict; inside one, at most one per conflict
// window, or a GitOps loop would flood), the write, and the conflict
// alert when this revert marked one.
func (c *Controller) landed(st *actorState, p *ateapi.EgressPolicy, base Event, state ateapi.ActorState, how string, res render.Result,
	foreign, enter bool, foreignMsg string, foreignDetail map[string]any) {
	now := c.o.Now()
	if foreign && (!st.conflict || enter || now.Sub(st.lastForeign) >= c.o.ConflictWindow) {
		st.lastForeign = now
		ev := base
		ev.Type, ev.Severity, ev.Message = EventForeignRule, SeverityWarn, foreignMsg
		ev.Detail = map[string]any{"reverts_in_window": len(st.reverts), "window": c.o.ConflictWindow.String(), "policy_conflict": st.conflict}
		for k, v := range foreignDetail {
			ev.Detail[k] = v
		}
		c.emit(ev)
	}
	c.wrote(st, p, base, state, how, res)
	if enter {
		ev := base
		ev.Type, ev.Severity = EventPolicyConflict, SeverityAlert
		ev.Message = fmt.Sprintf("%d foreign changes reverted in %s: marked policy_conflict; the actor keeps only the DefenseClaw rule (no other egress) until its policy is DefenseClaw's again",
			len(st.reverts), c.o.ConflictWindow)
		ev.Signal = c.signal(base, SignalPolicyConflict, "", st.firstSeen)
		c.emit(ev)
	}
}

// markStale records when the controller saw that the actor's policy needs
// the write it is about to make, unless an earlier failed try did: the
// actor's first policy from when the controller first saw the actor, a
// config change from when it was applied, anything else (a foreign change,
// a new approval or registration) from now, the pass that found it.
func (c *Controller) markStale(st *actorState, lv *Live) {
	switch {
	case !st.staleSince.IsZero():
	case st.syncedAt.IsZero():
		st.staleSince = st.firstSeen
	case lv.LoadedAt.After(st.syncedAt):
		st.staleSince = lv.LoadedAt
	default:
		st.staleSince = c.o.Now()
	}
}

// synced marks the actor's policy as right now (written or confirmed).
func (c *Controller) synced(st *actorState) {
	st.syncedAt, st.staleSince = c.o.Now(), time.Time{}
}

func (c *Controller) wrote(st *actorState, p *ateapi.EgressPolicy, base Event, state ateapi.ActorState, how string, res render.Result) {
	st.ourUID, st.ourVersion, st.written = p.GetMetadata().GetUid(), p.GetMetadata().GetVersion(), true
	now := c.o.Now()
	lag := time.Duration(0)
	if !st.staleSince.IsZero() && now.After(st.staleSince) {
		lag = now.Sub(st.staleSince)
	}
	c.synced(st)
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
		"actor_state": state.String(), "policy_lag_ms": lag.Milliseconds(), "dropped": drops, "secrets_bound": bound,
		"config_digest": c.live().Digest}
	c.emit(ev)
}

// recheck records the policy check of a resume: in a pass that sees
// RESUMING, or the first pass after a resume the controller did not see.
func (c *Controller) recheck(st *actorState, a *ateapi.Actor, base Event, how string) {
	if a.GetStatus().GetState() != ateapi.ActorStateResuming && !st.resumed {
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
	if !st.written && !render.IsDefenseClaw(cur, c.live().Settings) {
		st.unmanagedChecked = true
		return nil
	}
	if c.deleteBackingOff(st) {
		return nil
	}
	if _, err := c.o.Client.DeleteActorEgressPolicy(ctx, ref, &ateapi.DeleteOptions{Uid: cur.GetMetadata().GetUid(), Version: cur.GetMetadata().GetVersion()}); err != nil && !ateapi.IsNotFound(err) {
		if c.deleteRefused(st, base, err) {
			return nil
		}
		return fmt.Errorf("%s: remove policy: %w", st.key, err)
	}
	st.unmanagedChecked, st.written, st.ourVersion, st.conflict, st.reverts, st.deleteDenied = true, false, 0, false, nil, false
	st.deleteRetry = time.Time{}
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
// way into SUSPENDED is suspended (a revert or a crash ends SUSPENDED too):
// the leader's retention of suspended actors. The leader's running-time
// clock needs no event (GAP-0292): it runs from the actor's requests and
// the running report (reportRunning, GAP-0539).
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
	durable  bool   // the newest snapshot is uploaded
	worker   string // worker pod UID and epoch while placed
}

func restoreIDOf(s *ateapi.ActorStatus) restoreID {
	id := restoreID{lastGen: s.GetLastAssignedGeneration()}
	for _, sn := range s.GetSnapshots() {
		if sn.GetGeneration() > id.headGen {
			id.headGen, id.headUUID, id.local = sn.GetGeneration(), sn.GetUuid(), sn.GetLocality() != ""
			id.durable = sn.GetDurableSnapshot().GetState() == ateapi.SnapshotStorageCompleted
		}
	}
	if w := s.GetWorkerAssignment(); w.GetWorkerEpoch() != 0 {
		id.worker = w.GetWorkerPodUid() + "/" + strconv.FormatInt(w.GetWorkerEpoch(), 10)
	}
	return id
}

// freshSuspend reports the state a suspend leaves: the newest snapshot is
// the last assigned generation, its files still on the node or uploaded.
// atelet drops the node copy of an uploaded snapshot after
// --snapshot-detach-delay (30 minutes by default): the actor resumes from
// the same snapshot, so a detach is no revert (GAP-0292).
func (id restoreID) freshSuspend() bool { return id.headGen == id.lastGen && (id.local || id.durable) }

// revertSeen reports a revert between the last pass (prev, was) and this
// one (cur, now) that the state change alone does not show (a REVERTING
// state seen in a pass is sent by lifecycleOf). A detach is not one: the
// restore point is the same snapshot, and a barrier would end the actor's
// egress chains (GAP-0292).
func revertSeen(prev, cur ateapi.ActorState, was, now restoreID) bool {
	suspendedSince := now.lastGen > was.lastGen // a suspend ran since the last pass
	switch {
	case prev == ateapi.ActorStateCrashed && cur != ateapi.ActorStateCrashed:
		// Only a revert brings a crashed actor back, whatever state the
		// next pass sees: SUSPENDED, or RUNNING after a revert and a resume
		// inside one poll (GAP-0141). A REVERTING seen in a pass is sent by
		// lifecycleOf; DELETING never gets here.
		return cur != ateapi.ActorStateReverting
	case prev == ateapi.ActorStateSuspended && cur == ateapi.ActorStateSuspended:
		if suspendedSince { // resumed and suspended again inside one poll
			return !now.freshSuspend()
		}
		// A revert of a SUSPENDED actor needs its node-local snapshot. It
		// drops a newest snapshot not uploaded (the newest changes); of an
		// uploaded one it drops only the node copy, as a detach does, and
		// the actor resumes from that same snapshot: no revert of what the
		// windows saw (GAP-0292).
		return was.local && (now.headUUID != was.headUUID || !now.local && !now.durable)
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
