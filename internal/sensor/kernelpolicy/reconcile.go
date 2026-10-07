// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Intervals are the reconciler's clocks. The zero value of a field means its
// default.
type Intervals struct {
	// Reconcile is the full pass cadence (60 s).
	Reconcile time.Duration
	// Scan is how often live processes are read for new or exited agent
	// roots (5 s). A changed root set triggers a pass after Debounce.
	Scan time.Duration
	// Accrue is the burn-in accrual tick: covered time counts in units of it (60 s).
	Accrue time.Duration
	// Flush writes burnin.json (30 s).
	Flush time.Duration
	// PauseCheck is how often the pause files are read (2 s), so a pause
	// takes effect well inside 5 s.
	PauseCheck time.Duration
	// Debounce batches re-renders (1 s).
	Debounce time.Duration
	// Call bounds all Tetragon calls of one pass (30 s).
	Call time.Duration
	// RetryBackoff spaces repeated attempts to repair one broken policy (5 min).
	RetryBackoff time.Duration
	// Lock is how often a helper that starts during a --tetragon-cleanup
	// tries the reconciler lock again (1 s).
	Lock time.Duration
}

func (i Intervals) withDefaults() Intervals {
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&i.Reconcile, 60*time.Second)
	def(&i.Scan, 5*time.Second)
	def(&i.Accrue, 60*time.Second)
	def(&i.Flush, 30*time.Second)
	def(&i.PauseCheck, 2*time.Second)
	def(&i.Debounce, time.Second)
	def(&i.Call, 30*time.Second)
	def(&i.RetryBackoff, 5*time.Minute)
	def(&i.Lock, time.Second)
	return i
}

// DialFunc opens a connection to Tetragon that already passed the endpoint
// trust checks, and returns its closer. It is called once per pass and once
// per cleanup.
type DialFunc func(ctx context.Context) (Client, func(), error)

// Config wires a Controller to its environment.
type Config struct {
	Intent Intent
	Dirs   Dirs
	Logger *slog.Logger
	Dial   DialFunc
	// Enrollment returns the guardian manifest's enabled rows.
	Enrollment func() (Enrollment, error)
	// FS defaults to the operating system's.
	FS FS
	// Procs lists live processes; the argument says which uids are enrolled.
	// It defaults to a /proc scan.
	Procs         func(enrolled func(uid int) bool) ([]Proc, error)
	ExtraPrefixes []string
	// Customer reports the host's own Tetragon policies and the counts of
	// their events, for the published state (nil: none).
	Customer  CustomerSource
	Now       func() time.Time
	Intervals Intervals
}

// Hit is a kernel event from a DefenseClaw controls policy: an open that the
// control denied (enforce) or would have denied (monitor).
type Hit struct {
	// Policy is the event's policy name, matched exactly against the names
	// this helper loaded.
	Policy string
	UID    int
	Path   string
	Binary string
	At     time.Time
}

type known struct {
	family Family
	index  PathIndex
	mode   LoadedMode
	// modeAt is when mode last changed: the event mapper prefers it over a
	// Tetragon listing that is older.
	modeAt time.Time
	// live is true while the helper's record holds the name; a retired name
	// stays a few seconds so its last events are still attributed.
	live    bool
	expires time.Time
}

// Controller is the reconciler. One goroutine (Run) owns all state; the
// event source reaches it through RecordHit, RecordLoss and SetStream, and
// readers through Status.
type Controller struct {
	cfg Config

	// Loop-owned.
	st         FileState
	tracker    *Tracker
	enrollment Enrollment
	installs   []Install
	roots      RootSet
	rootSig    string
	recorded   map[string]bool
	retryAt    map[string]time.Time
	lastPaused bool
	lastStale  bool
	pauseKey   string
	lastPIDs   map[int]bool
	enabled    map[int]bool
	alive      map[int]int
	// progressAt is when each user's last uid_progress change was emitted.
	progressAt map[int]time.Time

	snapshot atomic.Pointer[State]
	nudge    chan struct{}
	// owned is a copy of recorded for Owns, which the event mapper calls
	// from the stream's goroutine.
	owned atomic.Pointer[map[string]bool]

	// tallyMu guards what RecordHit and friends touch.
	tallyMu sync.Mutex
	burn    *Burnin
	stream  bool
	loss    bool
	names   map[string]known
	// totals count the controls events since start (would_block_total,
	// blocked_total), every user's.
	totals map[string]int64
	// streamNote is the event stream's last word about Tetragon, waiting
	// for the off/consume loop to publish it.
	streamNote *StreamStatus
}

// StreamStatus is what the helper's event stream knows about Tetragon.
type StreamStatus struct {
	Connected bool
	Version   string
	PID       int
	// Reason says why the stream is down ("tetragon_unavailable: ...",
	// "tetragon_untrusted_endpoint: ..."); empty when the stream closed
	// because nobody subscribes to it.
	Reason string
}

// New creates a Controller and restores what a previous helper published
// (applied records, operator overrides, burn-in evidence).
func New(cfg Config) *Controller {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.FS == nil {
		cfg.FS = OSFS()
	}
	if cfg.Procs == nil {
		cfg.Procs = func(enrolled func(int) bool) ([]Proc, error) { return ScanProcs("/proc", enrolled) }
	}
	cfg.Intervals = cfg.Intervals.withDefaults()
	c := &Controller{
		cfg:        cfg,
		tracker:    NewTracker(),
		recorded:   map[string]bool{},
		retryAt:    map[string]time.Time{},
		lastPIDs:   map[int]bool{},
		enabled:    map[int]bool{},
		alive:      map[int]int{},
		progressAt: map[int]time.Time{},
		nudge:      make(chan struct{}, 1),
		burn:       LoadBurnin(cfg.Dirs),
		names:      map[string]known{},
		totals:     map[string]int64{},
	}
	if err := readJSON(cfg.Dirs.StateFile(), &c.st); err != nil && !errors.Is(err, os.ErrNotExist) {
		cfg.Logger.Warn("kernel policy state unreadable; starting from the live state", "error", err)
		c.st = FileState{}
	}
	c.reloadRecord()
	c.st.Version = stateVersion
	c.st.HelperPID = os.Getpid()
	c.st.KernelPolicy = Digest()
	c.st.Intent = IntentStatus{
		Mode: cfg.Intent.Mode, BurnIn: burnInText(cfg.Intent.BurnIn), EnforceAck: strings.Join(cfg.Intent.EnforceAcks, ","),
		EnforceConnectors: cfg.Intent.EnforceConnectors, CustomerEvents: cfg.Intent.CustomerEventsSetting(),
		Problems: cfg.Intent.Problems,
	}
	if c.st.Applied == nil {
		c.st.Applied = map[string]Applied{}
	}
	// Overrides last until the intent changes.
	if key := cfg.Intent.Key(); c.st.IntentKey != key {
		if len(c.st.Overrides) > 0 {
			c.change(Change{Event: EventResumed, Reason: "intent changed; operator overrides cleared"})
		}
		c.st.Overrides = nil
		c.st.IntentKey = key
	}
	c.syncTally()
	c.publish()
	return c
}

func burnInText(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	return strconv.Itoa(int(d/time.Hour)) + "h"
}

// Nudge asks for a pass soon (a root started or exited, Tetragon reconnected).
func (c *Controller) Nudge() {
	select {
	case c.nudge <- struct{}{}:
	default:
	}
}

// NoteStream records what the event stream knows about Tetragon. Covered
// time accrues only while it is connected. In observe and enforce every pass
// asks Tetragon itself, and a new session triggers one (Tetragon may have
// restarted and dropped the policies added over gRPC). In off and consume
// the stream is the helper's only session with Tetragon, so it is what the
// published state says about it: reachable with its version and pid, or the
// reason it is not.
func (c *Controller) NoteStream(s StreamStatus) {
	c.SetStream(s.Connected)
	if !c.cfg.Intent.Mode.LoadsPolicies() {
		c.tallyMu.Lock()
		c.streamNote = &s
		c.tallyMu.Unlock()
	} else if !s.Connected {
		return
	}
	c.Nudge()
}

// SetStream tells the controller whether the Tetragon event stream is
// connected. Covered time accrues only while it is.
func (c *Controller) SetStream(connected bool) {
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	if c.stream != connected {
		c.loss = true // the minute it changed is not a covered minute
	}
	c.stream = connected
}

// RecordLoss tells the controller the stream dropped events: a process
// throttle or a rate-limit notice. The current minute does not count as
// covered.
func (c *Controller) RecordLoss() {
	c.tallyMu.Lock()
	c.loss = true
	c.tallyMu.Unlock()
}

// RecordHit counts an event from a controls policy. It only counts events
// whose policy name is exactly one this helper loaded.
func (c *Controller) RecordHit(h Hit) {
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	entry, ok := c.names[h.Policy]
	if !ok || (entry.family != FamilyControls && entry.family != FamilyBurnin) {
		return
	}
	control := entry.index.ControlOf(h.Path)
	if control == "" {
		control = "unknown"
	}
	at := h.At
	if at.IsZero() {
		at = c.cfg.Now()
	}
	// An enforcing controls policy denied this open; anything else would have.
	blocked := entry.family == FamilyControls && entry.mode.Enforcing()
	if blocked {
		c.totals["blocked_total"]++
	} else {
		c.totals["would_block_total"]++
	}
	c.burn.Hit(h.UID, control, blocked, h.Path, h.Binary, at)
}

// Owns reports whether this helper recorded loading name (tetragon-loaded,
// the record mayTouch reads), or retired it moments ago. It is the only
// test of ownership: a policy named in DefenseClaw's pattern that this
// helper did not load is the customer's. Safe from any goroutine.
func (c *Controller) Owns(name string) bool {
	if owned := c.owned.Load(); owned != nil && (*owned)[name] {
		return true
	}
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	// An entry with a family came from an applied record; one without is
	// only the path index of a policy compiled and not loaded yet.
	entry, recent := c.names[name]
	return recent && entry.family != ""
}

// noteRecorded publishes the record for Owns after it changed.
func (c *Controller) noteRecorded() {
	owned := make(map[string]bool, len(c.recorded))
	for name := range c.recorded {
		owned[name] = true
	}
	c.owned.Store(&owned)
}

// OwnsPolicy reports whether name is a policy of family that this helper
// recorded as loaded. The event source uses it to decide that DefenseClaw's own
// observe policy is in place before it stops the fanotify watch.
func (c *Controller) OwnsPolicy(name string, family Family) bool {
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	entry, ok := c.names[name]
	return ok && entry.live && entry.family == family
}

// Status is the published state. It never blocks on a pass.
func (c *Controller) Status() State {
	var out State
	if snap := c.snapshot.Load(); snap != nil {
		out = *snap
	}
	c.tallyMu.Lock()
	out.BurnIn = c.burn.Snapshot()
	out.HitTotals = make(map[string]int64, len(c.totals))
	for key, value := range c.totals {
		out.HitTotals[key] = value
	}
	c.tallyMu.Unlock()
	if pause := ReadPause(c.cfg.Dirs, c.cfg.Now()); pause.Active() {
		out.Pause = &pause
	} else {
		out.Pause = nil
	}
	return out
}

// publish stores an immutable copy of the loop's state for Status.
func (c *Controller) publish() {
	snap := State{FileState: c.st}
	snap.Policies = append([]PolicyStatus(nil), c.st.Policies...)
	snap.UIDs = append([]UIDStatus(nil), c.st.UIDs...)
	snap.Warnings = append([]string(nil), c.st.Warnings...)
	snap.Changes = append([]Change(nil), c.st.Changes...)
	snap.CustomerPolicies = append([]CustomerPolicy(nil), c.st.CustomerPolicies...)
	snap.Applied = map[string]Applied{}
	for name, a := range c.st.Applied {
		snap.Applied[name] = a
	}
	snap.Overrides = map[Family]Override{}
	for family, o := range c.st.Overrides {
		snap.Overrides[family] = o
	}
	snap.Loaded = sortedKeys(c.recorded)
	c.snapshot.Store(&snap)
}

func (c *Controller) persist() {
	c.st.UpdatedAt = c.cfg.Now().UTC()
	c.applyCustomer()
	if err := writeJSON(c.cfg.Dirs.StateFile(), c.st); err != nil {
		c.cfg.Logger.Warn("kernel policy state not written", "error", err)
	}
	c.publish()
}

// applyCustomer refreshes the customer policies from the event stream's
// ledger and the warnings they raise: a capped warning per policy over its
// volume budget in the last hour and, in off and consume (no pass lists
// Tetragon then), a foreign-name warning per customer policy named in
// DefenseClaw's pattern.
func (c *Controller) applyCustomer() {
	if c.cfg.Customer == nil {
		return
	}
	policies, events := c.cfg.Customer(c.cfg.Now())
	c.st.CustomerPolicies = policies
	c.st.CustomerEvents = nil
	if events != (CustomerEvents{}) || len(policies) > 0 {
		c.st.CustomerEvents = &events
	}
	listing := !c.cfg.Intent.Mode.LoadsPolicies()
	kept := c.st.Warnings[:0:0]
	for _, warning := range c.st.Warnings {
		if strings.HasPrefix(warning, WarnCustomerEventsCapped+":") ||
			(listing && strings.HasPrefix(warning, WarnForeignName+":")) {
			continue
		}
		kept = append(kept, warning)
	}
	for _, policy := range policies {
		if len(kept) >= 64 {
			break
		}
		if policy.CappedLastHour > 0 {
			kept = addUnique(kept, WarnCustomerEventsCapped+":"+policy.Name)
		}
		if listing && policy.Listed && IsDefenseClawName(policy.Name) {
			kept = addUnique(kept, WarnForeignName+":"+policy.Name)
		}
	}
	c.st.Warnings = kept
}

// change appends to the change ring.
func (c *Controller) change(ch Change) {
	c.st.Seq++
	ch.Seq = c.st.Seq
	ch.At = c.cfg.Now().UTC()
	c.st.Changes = append(c.st.Changes, ch)
	if len(c.st.Changes) > maxChanges {
		c.st.Changes = c.st.Changes[len(c.st.Changes)-maxChanges:]
	}
}

// syncTally refreshes the lookup RecordHit uses.
func (c *Controller) syncTally() {
	now := c.cfg.Now()
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	for name, entry := range c.names {
		if _, live := c.st.Applied[name]; !live {
			entry.live = false
			c.names[name] = entry
			if now.After(entry.expires) {
				delete(c.names, name)
			}
		}
	}
	for name, applied := range c.st.Applied {
		entry, had := c.names[name]
		entry.family = applied.Family
		entry.live = true
		entry.expires = now.Add(30 * time.Second)
		mode := LoadedMonitor
		if applied.Mode == PolicyEnforce {
			mode = LoadedEnforce
		}
		if !had || entry.mode != mode {
			entry.mode, entry.modeAt = mode, now
		}
		c.names[name] = entry
	}
}

// setIndex records the path index of a loaded controls policy.
func (c *Controller) setIndex(name string, index PathIndex) {
	c.tallyMu.Lock()
	entry := c.names[name]
	entry.index = index
	c.names[name] = entry
	c.tallyMu.Unlock()
}

// observeMode records the mode Tetragon reports for a name, so a hit is
// counted as blocked or would-block by what is actually loaded.
func (c *Controller) observeMode(name string, mode LoadedMode) {
	now := c.cfg.Now()
	c.tallyMu.Lock()
	if entry, ok := c.names[name]; ok && entry.mode != mode {
		entry.mode, entry.modeAt = mode, now
		c.names[name] = entry
	}
	c.tallyMu.Unlock()
}

// PolicyMode is the mode of a policy this helper loaded, as of its own last
// call or listing ("enforce" or "monitor"), and when that changed. The event
// mapper uses it to tell a denial from a would-block: the helper knows the
// moment it adds, promotes or demotes a policy, and a controls policy gets a
// new name whenever its anchors change. ok is false for any other name.
func (c *Controller) PolicyMode(name string) (mode string, changed time.Time, ok bool) {
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	entry, known := c.names[name]
	if !known || !entry.live {
		return "", time.Time{}, false
	}
	if entry.mode.Enforcing() {
		return "enforce", entry.modeAt, true
	}
	return "monitor", entry.modeAt, true
}

// mayTouch is the only authority to delete or configure a name: the helper's
// own record.
func (c *Controller) mayTouch(name string) bool { return c.recorded[name] }

// reloadRecord reads the record of loaded names again and drops what Applied
// says about names it no longer holds. Applied is written after the record and
// cleared before it, so such a name was retired by DefenseClaw's own cleanup:
// its absence from Tetragon is never an operator's deletion. An unreadable
// record changes nothing.
func (c *Controller) reloadRecord() {
	names, err := readLoaded(c.cfg.Dirs)
	if err != nil {
		return
	}
	c.recorded = map[string]bool{}
	for _, name := range names {
		c.recorded[name] = true
	}
	for name := range c.st.Applied {
		if !c.recorded[name] {
			delete(c.st.Applied, name)
		}
	}
	c.noteRecorded()
}

// lockReconciler holds the reconciler lock for as long as Run reconciles, so
// a one-shot --tetragon-cleanup never removes policies under a helper that
// manages them. It waits out a cleanup in progress and then reads the record
// again; a lock that cannot be taken for another reason is logged, and the
// reconciler runs without it.
func (c *Controller) lockReconciler(ctx context.Context) func() {
	waiting := false
	for {
		unlock, err := tryLock(c.cfg.Dirs)
		switch {
		case err == nil:
			if waiting {
				c.reloadRecord()
				c.syncTally()
			}
			return unlock
		case !errors.Is(err, ErrReconcilerRunning):
			c.cfg.Logger.Warn("kernel policy lock unavailable; reconciling without it", "error", err)
			return func() {}
		case !waiting:
			waiting = true
			c.cfg.Logger.Info("waiting for a tetragon cleanup to finish")
		}
		select {
		case <-ctx.Done():
			return func() {}
		case <-time.After(c.cfg.Intervals.Lock):
		}
	}
}

func (c *Controller) recordLoaded(name string) error {
	if c.recorded[name] {
		return nil
	}
	c.recorded[name] = true
	c.noteRecorded()
	return writeLoaded(c.cfg.Dirs, sortedKeys(c.recorded))
}

func (c *Controller) forgetLoaded(name string) {
	if !c.recorded[name] {
		return
	}
	delete(c.recorded, name)
	c.noteRecorded()
	if err := writeLoaded(c.cfg.Dirs, sortedKeys(c.recorded)); err != nil {
		c.cfg.Logger.Warn("tetragon-loaded not written", "error", err)
	}
	removePolicyCopy(c.cfg.Dirs, name)
}

// Run drives the controller until ctx ends. In off and consume it only
// retires names its record holds (and, in consume, publishes what the event
// stream says about Tetragon). The policies it loaded keep running when it
// stops, with frozen anchors, until it returns; status says so.
func (c *Controller) Run(ctx context.Context) error {
	if !c.cfg.Intent.Mode.LoadsPolicies() {
		return c.runRetire(ctx)
	}
	unlock := c.lockReconciler(ctx)
	defer unlock()
	if ctx.Err() != nil {
		return nil
	}
	iv := c.cfg.Intervals
	c.pass(ctx, "start")
	reconcile := time.NewTicker(iv.Reconcile)
	scan := time.NewTicker(iv.Scan)
	accrue := time.NewTicker(iv.Accrue)
	flush := time.NewTicker(iv.Flush)
	pauseCheck := time.NewTicker(iv.PauseCheck)
	defer func() {
		for _, t := range []*time.Ticker{reconcile, scan, accrue, flush, pauseCheck} {
			t.Stop()
		}
	}()
	var debounce <-chan time.Time
	arm := func() {
		if debounce == nil {
			debounce = time.After(iv.Debounce)
		}
	}
	for {
		select {
		case <-ctx.Done():
			c.flush()
			c.persist()
			return nil
		case <-reconcile.C:
			c.pass(ctx, "interval")
		case <-scan.C:
			if c.rescan() {
				arm()
			}
		case <-c.nudge:
			arm()
		case <-debounce:
			debounce = nil
			c.pass(ctx, "nudge")
		case <-pauseCheck.C:
			if c.pauseChanged() {
				c.pass(ctx, "pause")
			}
		case <-accrue.C:
			c.accrue()
		case <-flush.C:
			c.flush()
			// The customer policies' counts, between passes.
			c.persist()
		}
	}
}

func (c *Controller) flush() {
	c.tallyMu.Lock()
	err := c.burn.Save(c.cfg.Dirs)
	c.tallyMu.Unlock()
	if err != nil {
		c.cfg.Logger.Warn("burn-in not written", "error", err)
	}
}

// pauseChanged reports whether the pause files changed since the last look.
func (c *Controller) pauseChanged() bool {
	state := ReadPause(c.cfg.Dirs, c.cfg.Now())
	key := "none"
	switch {
	case state.Invalid != "":
		key = "invalid:" + state.Invalid
	case state.Pause != nil:
		key = fmt.Sprintf("%d:%v:%d", state.Pause.Until.Unix(), state.Pause.UntilReboot, state.Pause.SetAt.Unix())
	}
	if key == c.pauseKey {
		return false
	}
	c.pauseKey = key
	return true
}

// runRetire is the whole of off and consume: retire the names this helper
// recorded, if any, and never load anything. Tetragon may be down at start,
// so it retries until the record is empty, at once when the event stream
// connects again. Off then returns; consume keeps publishing what the event
// stream says about Tetragon until ctx ends.
func (c *Controller) runRetire(ctx context.Context) error {
	c.st.Effective = string(c.cfg.Intent.Mode)
	// What a previous mode published (its policies, users, warnings and the
	// Tetragon its passes saw) is not this mode's.
	c.st.Warnings = append([]string(nil), c.cfg.Intent.Problems...)
	c.st.Policies, c.st.UIDs, c.st.Roots, c.st.InSync = nil, nil, RootsStatus{}, false
	c.st.Tetragon = TetragonStatus{}
	c.persist()
	orphaned := false
	var retry <-chan time.Time
	// The customer policies' counts are written on this cadence (in consume
	// the event stream runs and nothing else writes the state).
	flush := time.NewTicker(c.cfg.Intervals.Flush)
	defer flush.Stop()
	for {
		if len(c.recorded) > 0 && retry == nil {
			err := c.retireOnce(ctx)
			switch {
			case err != nil && !orphaned:
				// Policies this helper loaded are still in Tetragon while the
				// mode says none should be.
				orphaned = true
				c.change(Change{Event: EventOrphaned, Reason: fmt.Sprintf("%d recorded policies not retired: %v", len(c.recorded), err)})
				c.warn(WarnTetragonUnavailable)
				c.persist()
			case err == nil && orphaned:
				orphaned = false
				c.st.Warnings = withoutValue(c.st.Warnings, WarnTetragonUnavailable)
				c.persist()
			}
			if err != nil {
				c.cfg.Logger.Warn("retiring recorded tetragon policies failed; will retry", "error", err)
			}
			if len(c.recorded) > 0 {
				retry = time.After(c.cfg.Intervals.Reconcile)
			}
		}
		if len(c.recorded) == 0 && c.cfg.Intent.Mode != ModeConsume {
			return nil
		}
		select {
		case <-ctx.Done():
			c.persist()
			return nil
		case <-retry:
			retry = nil
		case <-flush.C:
			c.persist()
		case <-c.nudge:
			if c.noteStream() {
				retry = nil // Tetragon answers again: retire now
			}
		}
	}
}

// noteStream publishes the event stream's last word about Tetragon (off and
// consume) and reports whether the stream is connected.
func (c *Controller) noteStream() bool {
	c.tallyMu.Lock()
	note := c.streamNote
	c.streamNote = nil
	c.tallyMu.Unlock()
	if note == nil {
		return false
	}
	switch {
	case note.Connected:
		c.st.Tetragon = TetragonStatus{Reachable: true, Version: note.Version, PID: note.PID, SeenAt: c.cfg.Now().UTC()}
		c.st.Warnings = withoutValue(c.st.Warnings, WarnTetragonUnavailable)
	case note.Reason != "":
		c.st.Tetragon.Reachable, c.st.Tetragon.Reason = false, note.Reason
		c.warn(WarnTetragonUnavailable)
	default:
		// Nobody subscribes to the stream any more: nothing is known.
		c.st.Tetragon.Reachable, c.st.Tetragon.Reason = false, ""
	}
	c.persist()
	return note.Connected
}

func (c *Controller) retireOnce(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.Intervals.Call)
	defer cancel()
	client, closeFn, err := c.cfg.Dial(callCtx)
	if err != nil {
		return err
	}
	if closeFn != nil {
		defer closeFn()
	}
	result, err := Cleanup(callCtx, client, c.cfg.Dirs)
	for _, name := range append(append([]string(nil), result.Removed...), result.Missing...) {
		delete(c.recorded, name)
		c.noteRecorded()
		delete(c.st.Applied, name)
		c.change(Change{Event: EventRemoved, Policy: name, Reason: "mode " + string(c.cfg.Intent.Mode)})
	}
	// The record on disk is the truth: a --tetragon-cleanup run while this
	// helper waited to retry may have retired the rest.
	c.reloadRecord()
	for _, name := range result.Foreign {
		c.st.Warnings = addUnique(c.st.Warnings, WarnForeignName+":"+name)
	}
	c.st.Policies = nil
	c.persist()
	return err
}

func withoutValue(list []string, value string) []string {
	out := list[:0:0]
	for _, item := range list {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}

func addUnique(list []string, value string) []string {
	for _, item := range list {
		if item == value {
			return list
		}
	}
	return append(list, value)
}

// rescan reads live processes and reports whether the set of agent roots
// changed, which warrants a re-render.
func (c *Controller) rescan() bool {
	c.installs = ResolveInstalls(c.cfg.FS, c.enrollment, ResolveOptions{ExtraPrefixes: c.cfg.ExtraPrefixes})
	procs, err := c.cfg.Procs(c.enrollment.Has)
	if err != nil {
		return false
	}
	c.roots = c.tracker.Update(c.cfg.FS, procs, c.installs, c.enrollment)
	keys := make([]string, 0, len(c.roots.Roots))
	alive := map[int]int{}
	for _, root := range c.roots.Roots {
		keys = append(keys, fmt.Sprintf("%d:%d", root.PID, root.StartTicks))
		if c.lastPIDs[root.PID] {
			alive[root.UID]++
		}
	}
	sort.Strings(keys)
	sig := strings.Join(keys, ",")
	changed := sig != c.rootSig
	c.rootSig = sig
	c.alive = alive
	return changed
}

// accrue adds one tick of covered time to every user whose controls are
// enabled with an anchored root alive, if the stream was connected and
// lossless and nothing is paused.
func (c *Controller) accrue() {
	paused := ReadPause(c.cfg.Dirs, c.cfg.Now()).Active()
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	lossy := c.loss || !c.stream
	c.loss = false
	if lossy || paused || !c.cfg.Intent.Mode.LoadsPolicies() {
		return
	}
	for uid, on := range c.enabled {
		if on && c.alive[uid] > 0 {
			c.burn.Accrue(uid, c.cfg.Intervals.Accrue)
		}
	}
}
