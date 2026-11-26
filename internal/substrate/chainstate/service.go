// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/copilotjoin"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/historystore"
	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
)

// Egress actions for a detected secret-read-then-egress chain.
const (
	EgressBlock = "block"
	EgressAlert = "alert"
)

const (
	// Intent bounds per actor: the tool judge's own (llm_judge.go). Each
	// actor has its own store, so one actor rotating session keys evicts
	// only its own sessions (GAP-0093).
	intentMaxSessions = 64
	intentMaxPrior    = 7
	intentTTL         = 30 * time.Minute
	taskMaxBytes      = 4096
	// DefaultRetention is how long a suspended actor's windows stay ahead of
	// finished actors' when the atespace cap evicts.
	DefaultRetention = 24 * time.Hour
	// DefaultPurgeAfter is how long the state of an actor suspended (or
	// silent) is kept before it is purged, unless its window still holds a
	// secret read (GAP-0292).
	DefaultPurgeAfter = 7 * 24 * time.Hour
	// DefaultMaxActors bounds the actors with chain state per atespace
	// (the 4,096-partition cap of a host store, per atespace).
	DefaultMaxActors = guardrail.ToolChainMaxPartitions
	// DefaultMaxOpenStores bounds the open SQLite handles; idle ones close.
	DefaultMaxOpenStores = 128
	// DefaultWALGuardEvery is how often Run checkpoints the open stores.
	DefaultWALGuardEvery = 2 * time.Second
)

// egressChains are the chains whose terminal step is external egress, and
// the subset the callout refuses.
var (
	egressChains = []string{
		guardrail.ToolChainSecretReadThenEgress,
		guardrail.ToolChainSecretManagerReadThenEgress,
		guardrail.ToolChainGuardrailsOffThenEgress,
	}
	egressDenyChains = map[string]bool{
		guardrail.ToolChainSecretReadThenEgress:        true,
		guardrail.ToolChainSecretManagerReadThenEgress: true,
	}
)

// RefusesEgress reports a chain the callout refuses when its egress
// action is block: a secret read, or a secret-manager read, followed by
// external egress. The gateway's hook answers the same set for a verified
// actor (gateway.SetSubstrateChainEgressAction).
func RefusesEgress(chainID string) bool {
	return egressDenyChains[chainID]
}

// Options configure a Service.
type Options struct {
	// Dir is the leader's store volume directory.
	Dir string
	// EgressAction is what a detected secret-read-then-egress chain does at
	// the callout: block (default, PLAN §5.3) or alert.
	EgressAction string
	// Retention is how long a suspended actor counts as live for the
	// atespace cap (default 24 h).
	Retention time.Duration
	// PurgeAfter purges the state of an actor suspended, or silent, that
	// long (default 7 days), unless its window still holds a secret read
	// (GAP-0292) and Deleted does not confirm it gone (GAP-0311). A deleted
	// actor is purged at once.
	PurgeAfter time.Duration
	// MaxActors bounds the actors with state per atespace (default 4,096):
	// a new actor past it evicts a retired actor first, else the one used
	// least recently.
	MaxActors int
	// MaxOpenStores bounds the open per-actor stores (default 128).
	MaxOpenStores int
	// WALGuardEvery is how often Run copies the open per-actor stores'
	// write-ahead logs into their databases (default 2 s, as the gateway's
	// WAL guard does for audit.db; GAP-0404).
	WALGuardEvery time.Duration
	// ParentOf returns the parent UID of a forked actor from its verified
	// registration ("" for none). The leader copies the parent's windows the
	// first time it sees the child, whatever comes first (GAP-0091).
	ParentOf func(ctx context.Context, atespace, uid string) (string, error)
	// Deleted reports whether the actor's registration is marked deleted
	// (true also when it has none). A deleted event purges only then: the
	// controller marks the registration first, and a peer that cannot write
	// registrations cannot wipe a live actor's chains (GAP-0142). Sweep asks
	// it too, for an actor past PurgeAfter whose window holds a secret read:
	// a delete the controller never sent (GAP-0311). Nil, or an error,
	// keeps the actor.
	Deleted func(ctx context.Context, atespace, uid string) (bool, error)
	// Current reports whether uid is the live incarnation of the actor
	// atespace/name: its name's newest registration, not deleted. An egress
	// check under any other UID is answered stale, never from that UID's
	// windows (GAP-0234). Nil answers every UID (tests without a store).
	Current func(ctx context.Context, atespace, name, uid string) (bool, error)
	// OnCrashed closes the actor's open asks when it crashes (the ask store).
	OnCrashed func(ctx context.Context, actor Actor)
	// Now replaces the clock (tests).
	Now func() time.Time
	// Warn receives operational warnings (default stderr).
	Warn io.Writer
	// StartGrace is how long after its first clear egress check the leader
	// answers a clear one unavailable (0: never). A gateway that could not
	// record a tool step while no leader answered (a secret read during an
	// outage) tells the leader when it is back, retrying every 5 s; until
	// that note can have arrived, a clear answer may miss the read. The
	// callout takes unavailable as unchecked: a send is refused in every
	// mode, GET and HEAD follow chain.failure_mode (GAP-0601). A hit, or a
	// detection under the alert action, is answered at once. Known limit: a
	// gateway with a long note backlog, or a leader too busy to take a note,
	// can deliver one after the grace.
	//
	// The grace never lasts past startGraceCap(StartGrace) after the leader
	// term began (Leading; New when Leading is never called): a new leader
	// is reachable within its readiness period, and a gateway's waiting
	// note arrives within one retry and its timeout after that. Without the
	// cap the first clear check after any restart was refused, however long
	// after the restart it came (GAP-0601, IB5 TST-2593).
	StartGrace time.Duration
	// Born returns when the actor's registration was made and its parent
	// UID ("" for none). An actor registered in this leader term with no
	// parent skips the start grace (bornInTerm, GAP-0642). Nil, an error
	// or no registration keeps the grace.
	Born func(ctx context.Context, atespace, uid string) (created time.Time, parentUID string, err error)
}

// Service is the leader's chain and intent state. Every actor has its own
// store file, state file and intent map: an actor's expiries, prunes and
// LRU run on its own running-time clock and never touch another actor's
// rows (GAP-0089), and everything an actor holds is removed with it.
type Service struct {
	opts Options
	// action is the chain egress action in force: opts.EgressAction at
	// start, then SetEgressAction (a config.yaml change, GAP-0276).
	action atomic.Pointer[string]
	// servingAt is when the term's first clear egress check came (served
	// says it did), and termAt is when the term began, for
	// opts.StartGrace and its cap; graceMu guards them (monotonic with the
	// default clock). Before GAP-0601 (IB5) a sync.Once kept servingAt for
	// the process and nothing capped the grace.
	graceMu   sync.Mutex
	served    bool
	servingAt time.Time
	termAt    time.Time

	mu      sync.Mutex
	actors  map[string]*actorEntry // atespace/uid
	open    int
	closed  bool
	stripes [256]sync.Mutex
	// egress records the callout's egress steps off the RPC (GAP-0179).
	egress *egressWorker
	// purging holds the actors whose files are being removed, after their
	// entry left the index: purges close stores and remove files outside
	// mu, which the egress check takes (GAP-0179), and no call reaches the
	// actor until the files are gone.
	purging map[string]bool
	// purges are the purges whose files wait for runPurges.
	purges []purgeJob
	// gone are the actors a delete purged (their registration was marked
	// deleted first). No call makes an entry for one again: a check that
	// read the registration just before the delete must not get a fresh,
	// empty entry that answers allow (GAP-0234). Oldest first, at most
	// maxGone; past it, Egress still asks Current while it holds the entry.
	gone     map[string]bool
	goneList []string
	// calls are the tool calls this leader prepared or resolved, for a
	// further result of a call (GAP-0348, GAP-0345, GAP-0350; calls.go).
	calls *callTable
	// seed is the migrated store a new actor's store is copied from
	// (seed.go, GAP-0564).
	seed storeSeed
	// shares are the gateway replicas' request counts for the fair-share
	// limits (GAP-0566).
	shares ratelimit.Shares
	// diskHook, set by tests only, runs before every disk operation on an
	// actor's files: a store open or access (storeOf), a state file write
	// and a purge's removals. A test blocks it to stand for a disk that does
	// not answer, so any call that touches the disk hangs (GAP-0179,
	// GAP-0247). Nil in production.
	diskHook atomic.Pointer[func(op string)]
}

// disk runs the test disk hook before a disk operation.
func (s *Service) disk(op string) {
	if f := s.diskHook.Load(); f != nil {
		(*f)(op)
	}
}

// maxGone bounds Service.gone.
const maxGone = 1 << 16

// purgeJob is a purged actor's store and files, removed after mu.
type purgeJob struct {
	actor Actor
	store *audit.Store
}

// actorEntry is one actor's state. Fields are guarded by Service.mu except
// openMu, which orders opening the store.
type actorEntry struct {
	actor    Actor
	state    actorState
	store    *audit.Store
	refs     int
	lastUsed time.Time
	intents  *intentstore.Process
	// history is the proxy's inspect-once record of the actor (GAP-0266).
	history *historystore.Process
	// copilot is the actor's Copilot permission join (GAP-0269).
	copilot *copilotjoin.Process
	openMu  sync.Mutex
	purged  bool
	// purgeIdle is a delete that waits for the calls holding the entry.
	purgeIdle bool
	// memo is what the callout's chain check answers from (GAP-0179).
	memo egressMemo
	// stateMu orders the state file writes, so the newest memo is the one
	// on the volume.
	stateMu sync.Mutex
	// linkMu orders the fork parent's lookup (parent, parentKnown) and the
	// memo link (memoLinked), which the egress check makes without the
	// store (GAP-0091 with GAP-0179).
	linkMu      sync.Mutex
	parent      string
	parentKnown bool
	memoLinked  bool
}

// ActiveGap is the most a gap between two of an actor's own requests counts
// toward its running time (GAP-0292).
const ActiveGap = 5 * time.Minute

// actorState is what the leader keeps of an actor on the volume: its
// running-time clock, the order of its lifecycle events, and its task.
//
// The clock is wall time while the actor runs (the chain horizon: 30
// minutes of running time, a suspend does not count). The leader sees it
// running from the actor's own requests through DefenseClaw (hook chain
// calls, intent calls and egress checks) and from the controller's report
// of the actors it saw in state RUNNING (ChainRunning, about once a minute,
// GAP-0539), each at the leader's receive time (never a guest or controller
// timestamp, E15, GAP-0319). A gap between two of them counts at most
// ActiveGap. An actor that is not running makes no requests and is not
// reported running, so whatever stopped it (a suspend of any kind, a
// detach, a drain, an eviction, an outage of the controller or of the
// leader) stops its clock, and nothing has to report the stop (GAP-0292).
// What the leader does not see counts as not running: a chain window lasts
// longer, never shorter.
type actorState struct {
	// UncountedNanos is the wall time that is not running time: the part of
	// each gap between two requests past ActiveGap.
	UncountedNanos int64 `json:"uncounted_nanos,omitempty"`
	// ActiveUnixNano is the receive time of the actor's last request (0
	// before the first).
	ActiveUnixNano int64 `json:"active_unix_nano,omitempty"`
	// RunningHighUnixNano is the high-water mark of the running time: the
	// latest the leader gave one of the actor's events. The running time
	// never goes below it, so a backward step of the leader's wall clock (an
	// NTP step, a failover onto a node whose clock lags) never puts a check
	// before an event it follows (GAP-0310).
	RunningHighUnixNano int64 `json:"running_high_unix_nano,omitempty"`
	// SinceUnixNano is the start of the suspension the controller reported
	// last (0 while running); it only decides retention (Sweep).
	SinceUnixNano int64 `json:"since_unix_nano,omitempty"`
	// LastEventUnixNano is the time of the last suspend or resume applied;
	// an older one arriving late is ignored (GAP-0092).
	LastEventUnixNano int64 `json:"last_event_unix_nano,omitempty"`
	Retired           bool  `json:"retired,omitempty"`
	// Forked is set once the child's clock started from its parent's; a
	// later or repeated fork event copies missing windows only (GAP-0142).
	Forked bool `json:"forked,omitempty"`
	// Task is the launcher-registered --task text.
	Task string `json:"task,omitempty"`
	// UnrecordedUnixNano is the actor's running time of its last tool step
	// a gateway could not record (0 for none), UnrecordedWhy the reason
	// (GAP-0339).
	UnrecordedUnixNano int64  `json:"unrecorded_unix_nano,omitempty"`
	UnrecordedWhy      string `json:"unrecorded_why,omitempty"`
	// UnclearedUnixNano and UnclearedWhy are the same for the last
	// credentials read that started the chain uncleared (GAP-0338).
	UnclearedUnixNano int64  `json:"uncleared_unix_nano,omitempty"`
	UnclearedWhy      string `json:"uncleared_why,omitempty"`
	// Egress is the egress memo (GAP-0179), filled when the file is
	// written. A state file without it is from an older leader.
	Egress *egressSnapshot `json:"egress,omitempty"`
}

// running is wall in the actor's running time. It never goes back: a wall
// time before the last request counts as that request's, and the result is
// never below the high-water mark (GAP-0310).
func (c actorState) running(wall time.Time) time.Time {
	w := max(wall.UnixNano(), c.ActiveUnixNano)
	off := c.UncountedNanos
	if c.ActiveUnixNano != 0 {
		if idle := w - c.ActiveUnixNano - int64(ActiveGap); idle > 0 {
			off += idle
		}
	}
	r := max(w-off, c.RunningHighUnixNano)
	return wall.Add(time.Duration(r - wall.UnixNano()))
}

// active is c after a request of the actor at wall. The running time at
// wall does not change; from wall on it runs again. A wall time before the
// last request is a backward step of the leader's clock: the running time
// goes on from the last request's, never back (GAP-0310).
func (c actorState) active(wall time.Time) actorState {
	w := wall.UnixNano()
	switch {
	case w == c.ActiveUnixNano:
		return c
	case w < c.ActiveUnixNano:
		c.UncountedNanos -= c.ActiveUnixNano - w
	case c.ActiveUnixNano != 0:
		if idle := w - c.ActiveUnixNano - int64(ActiveGap); idle > 0 {
			c.UncountedNanos += idle
		}
	}
	c.ActiveUnixNano = w
	return c
}

// New opens a Service on opts.Dir and loads the actors it knows.
func New(opts Options) (*Service, error) {
	if opts.Dir == "" {
		return nil, errors.New("chainstate: a store directory is required")
	}
	switch opts.EgressAction {
	case "":
		opts.EgressAction = EgressBlock
	case EgressBlock, EgressAlert:
	default:
		return nil, fmt.Errorf("chainstate: egress action %q is not block or alert", opts.EgressAction)
	}
	if opts.Retention <= 0 {
		opts.Retention = DefaultRetention
	}
	if opts.PurgeAfter <= 0 {
		opts.PurgeAfter = DefaultPurgeAfter
	}
	if opts.MaxActors <= 0 {
		opts.MaxActors = DefaultMaxActors
	}
	if opts.MaxOpenStores <= 0 {
		opts.MaxOpenStores = DefaultMaxOpenStores
	}
	if opts.WALGuardEvery <= 0 {
		opts.WALGuardEvery = DefaultWALGuardEvery
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Warn == nil {
		opts.Warn = os.Stderr
	}
	for _, d := range []string{"chains", "actors"} {
		if err := os.MkdirAll(filepath.Join(opts.Dir, d), 0o700); err != nil {
			return nil, err
		}
		// A pod fsGroup makes the store volume 2770/0660 on every mount
		// (EKS with EBS); the leader takes its own entries back to
		// owner-only, or the audit store refuses every chain (GAP-0394).
		if err := audit.ReclaimOwnTree(filepath.Join(opts.Dir, d)); err != nil {
			return nil, err
		}
	}
	s := &Service{opts: opts, actors: map[string]*actorEntry{}, purging: map[string]bool{}, gone: map[string]bool{},
		calls: newCallTable()}
	s.termAt = opts.Now()
	s.action.Store(&opts.EgressAction)
	if err := s.load(); err != nil {
		return nil, err
	}
	var cold []Actor
	for _, e := range s.actors {
		// A known actor is past its first call: a fork was linked then.
		e.memoLinked = true
		switch _, err := os.Stat(s.dbPath(e.actor)); {
		case e.memo.restore(e.state.Egress):
			// The memo this leader's predecessor saved is the store's state.
		case errors.Is(err, os.ErrNotExist):
			// No store: nothing the memo would miss.
			e.memo.warm = true
		default:
			// A store from a leader that saved no memo (or another format):
			// the worker reads it back; until then the egress check answers
			// errWarming.
			cold = append(cold, e.actor)
		}
		e.state.Egress = nil
	}
	s.startEgressWorker()
	for _, a := range cold {
		s.egress.push(egressRecord{actor: a, sync: true})
	}
	return s, nil
}

// Register serves the chain, intent, lifecycle and egress methods on srv.
func (s *Service) Register(srv *leader.Server) {
	srv.Handle(leader.MethodChainObserve, s.logged(leader.MethodChainObserve, leader.Typed(s.Observe)))
	srv.Handle(leader.MethodIntentGet, s.logged(leader.MethodIntentGet, leader.Typed(s.IntentGet)))
	srv.Handle(leader.MethodIntentPut, s.logged(leader.MethodIntentPut, leader.Typed(s.IntentPut)))
	srv.Handle(MethodChainLifecycle, s.logged(MethodChainLifecycle, leader.Typed(s.Lifecycle)))
	srv.Handle(MethodChainEgress, s.logged(MethodChainEgress, leader.Typed(s.Egress)))
	srv.Handle(MethodChainUnrecorded, s.logged(MethodChainUnrecorded, leader.Typed(s.Unrecorded)))
	srv.Handle(MethodChainRunning, s.logged(MethodChainRunning, leader.Typed(s.Running)))
	srv.Handle(MethodHistorySeen, s.logged(MethodHistorySeen, leader.Typed(s.HistorySeen)))
	srv.Handle(MethodHistoryRecord, s.logged(MethodHistoryRecord, leader.Typed(s.HistoryRecord)))
	srv.Handle(MethodCopilotJoinRecord, s.logged(MethodCopilotJoinRecord, leader.Typed(s.CopilotJoinRecord)))
	srv.Handle(MethodCopilotJoinTake, s.logged(MethodCopilotJoinTake, leader.Typed(s.CopilotJoinTake)))
	// A read: the newest report of each replica replaces its last one, so
	// a retry is harmless and its answer is not kept for replay.
	srv.HandleRead(ratelimit.MethodShare, leader.Typed(s.rateShare))
}

// rateShare is the fair-share limits' exchange of the gateway replicas
// (ratelimit.Shares, GAP-0566).
func (s *Service) rateShare(ctx context.Context, in ratelimit.ShareReport) (ratelimit.ShareAnswer, error) {
	out, err := s.shares.Share(ctx, in)
	switch {
	case errors.Is(err, ratelimit.ErrBadShare):
		return out, bad(err)
	case err != nil:
		return out, &leader.WireError{Code: leader.CodeUnavailable, Message: err.Error()}
	}
	return out, nil
}

// logged logs the errors a handler returns that the transport reports only
// as "internal" (no request content is logged).
func (s *Service) logged(method string, h leader.Handler) leader.Handler {
	return func(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
		out, err := h(ctx, body)
		return out, s.internal(method, err)
	}
}

// internal logs an error the transport hands back only as "internal".
func (s *Service) internal(what string, err error) error {
	var we *leader.WireError
	if err != nil && !errors.As(err, &we) {
		fmt.Fprintf(s.opts.Warn, "[chainstate] warning: %s: %v\n", what, err)
	}
	return err
}

func (s *Service) warnf(format string, args ...any) {
	fmt.Fprintf(s.opts.Warn, "[chainstate] warning: "+format+"\n", args...)
}

// Close stops the egress worker (after it has written what it holds) and
// closes every store.
func (s *Service) Close() error {
	s.egress.stop()
	s.runPurges()
	s.removeSeed()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	var errs []error
	for _, e := range s.actors {
		if e.store != nil {
			errs = append(errs, e.store.Close())
			e.store = nil
		}
	}
	s.open = 0
	return errors.Join(errs...)
}

func bad(err error) error {
	return &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
}

// lock orders the calls of one actor.
func (s *Service) lock(a Actor) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(a.key()))
	m := &s.stripes[h.Sum32()%uint32(len(s.stripes))]
	m.Lock()
	return m.Unlock
}

func (s *Service) dbPath(a Actor) string {
	return filepath.Join(s.opts.Dir, "chains", a.Atespace, a.UID+".db")
}

func (s *Service) statePath(a Actor) string {
	return filepath.Join(s.opts.Dir, "actors", a.Atespace, a.UID+".json")
}

// load builds the actor index from the volume (a new leader after a
// failover): state files and store files.
func (s *Service) load() error {
	now := s.opts.Now()
	for _, sub := range []struct{ dir, ext string }{{"actors", ".json"}, {"chains", ".db"}} {
		root := filepath.Join(s.opts.Dir, sub.dir)
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != sub.ext {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			a, ok := actorFromKey(filepath.ToSlash(strings.TrimSuffix(rel, sub.ext)))
			if !ok {
				return nil
			}
			e := s.actors[a.key()]
			if e == nil {
				e = &actorEntry{actor: a, lastUsed: now}
				if info, err := d.Info(); err == nil {
					e.lastUsed = info.ModTime()
				}
				s.actors[a.key()] = e
			}
			if sub.ext == ".json" {
				raw, err := os.ReadFile(path)
				if err == nil {
					_ = json.Unmarshal(raw, &e.state)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// errEvicted is returned for an actor whose state was purged while a call
// waited for it.
var errEvicted = &leader.WireError{Code: leader.CodeUnavailable, Message: "the actor's chain state was purged"}

// errGone is returned for an actor a delete purged.
var errGone = &leader.WireError{Code: leader.CodeUnavailable, Message: "the actor was deleted"}

// acquire returns the actor's entry with a reference; release returns it.
// An actor seen for the first time gets an entry (evicting another when the
// atespace is full).
func (s *Service) acquire(a Actor) (*actorEntry, func(), error) {
	return s.acquireWith(a, false)
}

// acquireWith is acquire; quick (the egress check) leaves the store
// closes and file removals its release makes to a goroutine, so the check
// never waits on the volume (GAP-0179).
func (s *Service) acquireWith(a Actor, quick bool) (*actorEntry, func(), error) {
	e, release, _, err := s.acquireEntry(a, quick)
	return e, release, err
}

// acquireEntry is acquireWith; created reports an entry this call made.
// An actor a delete purged gets none (errGone).
func (s *Service) acquireEntry(a Actor, quick bool) (_ *actorEntry, _ func(), created bool, _ error) {
	if err := a.Validate(); err != nil {
		return nil, nil, false, bad(err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, false, &leader.WireError{Code: leader.CodeUnavailable, Message: "chain store closed"}
	}
	e := s.actors[a.key()]
	if (e != nil && e.purgeIdle) || s.purging[a.key()] {
		s.mu.Unlock()
		return nil, nil, false, errEvicted
	}
	if e == nil && s.gone[a.key()] {
		s.mu.Unlock()
		return nil, nil, false, errGone
	}
	if e == nil {
		created = true
		s.makeRoomLocked(a.Atespace)
		// A new actor has no store this leader has not seen: the memo
		// covers it from the start.
		e = &actorEntry{actor: a, lastUsed: s.opts.Now()}
		e.memo.warm = true
		s.actors[a.key()] = e
	}
	e.refs++
	evicted := len(s.purges) > 0
	s.mu.Unlock()
	if evicted {
		s.after(quick, s.runPurges)
	}
	return e, func() {
		s.mu.Lock()
		e.refs--
		e.lastUsed = s.opts.Now()
		if e.refs == 0 && e.purgeIdle && !e.purged {
			s.purgeLocked(e)
		}
		toClose := s.closeIdleLocked()
		s.mu.Unlock()
		// Closing a store checkpoints its WAL: never under the service
		// mutex, which every call of every actor takes (GAP-0142).
		s.after(quick, func() {
			for _, st := range toClose {
				_ = st.Close()
			}
			s.runPurges()
		})
	}, created, nil
}

// after runs f now, or in a goroutine for a quick call.
func (s *Service) after(quick bool, f func()) {
	if quick {
		go f()
		return
	}
	f()
}

// makeRoomLocked evicts one actor of atespace when it is full: one whose
// window holds no secret read first (GAP-0292), then a retired actor, else
// the least recently used; never one in use.
func (s *Service) makeRoomLocked(atespace string) {
	var in []*actorEntry
	for _, e := range s.actors {
		if e.actor.Atespace == atespace {
			in = append(in, e)
		}
	}
	if len(in) < s.opts.MaxActors {
		return
	}
	holds := make(map[*actorEntry]bool, len(in))
	for _, e := range in {
		holds[e] = s.holdsEgressLocked(e)
	}
	sort.Slice(in, func(i, j int) bool {
		if holds[in[i]] != holds[in[j]] {
			return holds[in[j]]
		}
		if in[i].state.Retired != in[j].state.Retired {
			return in[i].state.Retired
		}
		return in[i].lastUsed.Before(in[j].lastUsed)
	})
	for _, e := range in {
		if e.refs == 0 {
			s.purgeLocked(e)
			return
		}
	}
}

// closeIdleLocked takes the least recently used idle stores out of use
// past the cap, down to 7/8 of it, so a busy leader past the cap does not
// close and reopen a store on every call (GAP-0142). The caller closes the
// returned stores after it unlocks.
func (s *Service) closeIdleLocked() []*audit.Store {
	if s.open <= s.opts.MaxOpenStores {
		return nil
	}
	low := s.opts.MaxOpenStores - s.opts.MaxOpenStores/8
	var idle []*actorEntry
	for _, e := range s.actors {
		if e.store != nil && e.refs == 0 {
			idle = append(idle, e)
		}
	}
	sort.Slice(idle, func(i, j int) bool { return idle[i].lastUsed.Before(idle[j].lastUsed) })
	var out []*audit.Store
	for _, e := range idle {
		if s.open <= low {
			break
		}
		out = append(out, e.store)
		e.store = nil
		s.open--
	}
	return out
}

// purgeLocked takes an actor out of the index; runPurges, after mu, closes
// its store and removes its files. Until then the actor answers
// errEvicted.
func (s *Service) purgeLocked(e *actorEntry) {
	job := purgeJob{actor: e.actor, store: e.store}
	if e.store != nil {
		e.store = nil
		s.open--
	}
	e.purged = true
	delete(s.actors, e.actor.key())
	s.calls.dropActor(e.actor.key())
	s.purging[e.actor.key()] = true
	s.purges = append(s.purges, job)
}

// goneLocked records a deleted actor (Service.gone).
func (s *Service) goneLocked(key string) {
	if s.gone[key] {
		return
	}
	if len(s.goneList) >= maxGone {
		delete(s.gone, s.goneList[0])
		s.goneList = s.goneList[1:]
	}
	s.gone[key] = true
	s.goneList = append(s.goneList, key)
}

// runPurges closes the stores and removes the files of the purged actors
// (never under mu).
func (s *Service) runPurges() {
	s.mu.Lock()
	jobs := s.purges
	s.purges = nil
	s.mu.Unlock()
	for _, j := range jobs {
		s.disk("purge")
		if j.store != nil {
			_ = j.store.Close()
		}
		db := s.dbPath(j.actor)
		for _, p := range []string{db, db + "-wal", db + "-shm", s.statePath(j.actor)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.warnf("purge %s/%s: %v", j.actor.Atespace, j.actor.UID, err)
			}
		}
		s.mu.Lock()
		delete(s.purging, j.actor.key())
		s.mu.Unlock()
	}
}

// storeOf opens the actor's store (a held entry). A store opened for the
// first time for an actor with a parent starts from the parent's windows:
// the copy runs before the store is published, so a concurrent call of the
// child waits for it (on openMu) and its first hooks and egress checks see
// the parent's windows (GAP-0091). If the parent can't be named or copied,
// the store is not kept and the call answers unavailable, so the caller's
// fail mode applies and the next call tries the link again.
func (s *Service) storeOf(ctx context.Context, e *actorEntry) (*audit.Store, audit.ConnectorInstanceID, error) {
	s.disk("store")
	instance, err := audit.ToolChainSubstrateInstanceID(e.actor.Atespace, e.actor.UID)
	if err != nil {
		return nil, "", bad(err)
	}
	s.mu.Lock()
	st, purged := e.store, e.purged
	s.mu.Unlock()
	if purged {
		return nil, "", errEvicted
	}
	if st != nil {
		return st, instance, nil
	}
	e.openMu.Lock()
	defer e.openMu.Unlock()
	s.mu.Lock()
	st = e.store
	s.mu.Unlock()
	if st != nil {
		return st, instance, nil
	}
	path := s.dbPath(e.actor)
	_, statErr := os.Stat(path)
	fresh := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	if fresh {
		// A copy of the migrated seed, not every migration again (GAP-0564).
		s.seedStore(path)
	}
	// A per-actor store is one of up to MaxOpenStores: a small page cache
	// and no read pool, or each holds up to 100 MB outside the Go heap as it
	// grows (GAP-0404).
	st, err = audit.NewStore(path, audit.WithSmallFootprint())
	if err != nil {
		return nil, "", err
	}
	if err := st.Init(); err != nil {
		_ = st.Close()
		return nil, "", err
	}
	if err := st.EnsureToolChainSubstrateInstance(ctx, instance); err != nil {
		_ = st.Close()
		return nil, "", err
	}
	if fresh && s.opts.ParentOf != nil {
		if err := s.linkFork(ctx, e, st, instance); err != nil {
			_ = st.Close()
			for _, p := range []string{path, path + "-wal", path + "-shm"} {
				if rerr := os.Remove(p); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
					s.warnf("fork link for %s/%s: remove %s: %v", e.actor.Atespace, e.actor.UID, filepath.Base(p), rerr)
				}
			}
			s.warnf("fork link for %s/%s failed, its chain calls answer unavailable until it succeeds: %v", e.actor.Atespace, e.actor.UID, err)
			return nil, "", errForkUnlinked
		}
	}
	if fresh {
		// The state file says a memo-keeping leader made this store, so
		// the next leader answers from the saved memo (GAP-0179).
		if err := s.writeState(e); err != nil {
			s.warnf("state of %s/%s: %v", e.actor.Atespace, e.actor.UID, err)
		}
	}
	s.mu.Lock()
	if e.purged {
		s.mu.Unlock()
		_ = st.Close()
		return nil, "", errEvicted
	}
	e.store = st
	s.open++
	s.mu.Unlock()
	return st, instance, nil
}

// errForkUnlinked answers a forked actor's call while its parent's windows
// could not be linked (GAP-0091).
var errForkUnlinked = &leader.WireError{Code: leader.CodeUnavailable, Message: "the forked actor's chain windows are not linked to its parent yet"}

// linkFork copies the parent's windows into a new child store (not yet
// published) when the verified registration names a parent.
func (s *Service) linkFork(ctx context.Context, e *actorEntry, st *audit.Store, instance audit.ConnectorInstanceID) error {
	e.linkMu.Lock()
	parent, err := s.parentOfLocked(ctx, e)
	e.linkMu.Unlock()
	if err != nil {
		return fmt.Errorf("parent: %w", err)
	}
	if parent == "" || parent == e.actor.UID {
		return nil
	}
	if _, err := s.copyFork(ctx, e, st, instance, Actor{Atespace: e.actor.Atespace, UID: parent}, s.opts.Now()); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// copyFork copies the parent's windows, clock and task into the child (a
// held, open entry). Asks and approvals are never copied; nor are windows
// across atespaces (one directory each).
func (s *Service) copyFork(ctx context.Context, child *actorEntry, st *audit.Store, childInstance audit.ConnectorInstanceID,
	parent Actor, at time.Time) (LifecycleResult, error) {
	if err := parent.Validate(); err != nil {
		return LifecycleResult{}, bad(err)
	}
	if parent.Atespace != child.actor.Atespace {
		return LifecycleResult{}, bad(errors.New("chainstate: a fork into another atespace inherits no windows"))
	}
	parentInstance, _ := audit.ToolChainSubstrateInstanceID(parent.Atespace, parent.UID)
	parentDigest, _ := audit.ToolChainActorScopeDigest(parent.Atespace, parent.UID)
	childDigest, _ := audit.ToolChainActorScopeDigest(child.actor.Atespace, child.actor.UID)
	s.mu.Lock()
	var pst actorState
	pe := s.actors[parent.key()]
	if pe != nil {
		pst = pe.state
	}
	cst := child.state
	s.mu.Unlock()
	cst = forkClock(cst, pst)
	copyAt := cst.running(at)
	// The child's high-water mark is the parent's saved one (forkClock), not
	// the copy time: at is the controller's clock, and a controller clock
	// ahead of the leader's would otherwise move the child's running time
	// forward and age the secret read it inherits (GAP-0319).
	result := LifecycleResult{}
	if _, err := os.Stat(s.dbPath(parent)); err == nil {
		r, err := st.CopyToolChainFork(ctx, s.dbPath(parent), audit.ToolChainForkCopy{
			ParentInstance: parentInstance, ChildInstance: childInstance,
			ParentActorDigest: parentDigest, ChildActorDigest: childDigest, At: copyAt,
		})
		if errors.Is(err, audit.ErrToolChainForkAlreadyStarted) {
			return LifecycleResult{}, nil
		}
		if err != nil {
			return LifecycleResult{}, err
		}
		result.CopiedEvents, result.Skipped = r.Copied, r.Skipped
		if r.Skipped != 0 {
			s.warnf("fork %s/%s: %d parent windows not copied, the child already had them", child.actor.Atespace, child.actor.UID, r.Skipped)
		}
	}
	if err := s.setState(child, cst); err != nil {
		return result, err
	}
	// The child's egress memo is its store's window, the copied parent
	// windows included (GAP-0179 with GAP-0091).
	s.syncMemo(ctx, st, child)
	return result, nil
}

// forkClock starts a child's clock from its parent's, once: a late or
// repeated fork event never resets the child's own time. The child takes
// the parent's task if it has none, and the parent's later unrecorded and
// uncleared marks: the child goes on from the parent's work, as it inherits
// its windows (GAP-0339 review F1).
func forkClock(cst, pst actorState) actorState {
	if !cst.Forked {
		cst.UncountedNanos, cst.ActiveUnixNano = pst.UncountedNanos, pst.ActiveUnixNano
		cst.RunningHighUnixNano = max(cst.RunningHighUnixNano, pst.RunningHighUnixNano)
		cst.SinceUnixNano, cst.Forked = 0, true
	}
	if cst.Task == "" {
		cst.Task = pst.Task
	}
	if pst.UnrecordedUnixNano > cst.UnrecordedUnixNano {
		cst.UnrecordedUnixNano, cst.UnrecordedWhy = pst.UnrecordedUnixNano, pst.UnrecordedWhy
	}
	if pst.UnclearedUnixNano > cst.UnclearedUnixNano {
		cst.UnclearedUnixNano, cst.UnclearedWhy = pst.UnclearedUnixNano, pst.UnclearedWhy
	}
	return cst
}

// parentOfLocked is the actor's fork parent from its registration, looked
// up once (e.linkMu held).
func (s *Service) parentOfLocked(ctx context.Context, e *actorEntry) (string, error) {
	if e.parentKnown || s.opts.ParentOf == nil {
		return e.parent, nil
	}
	parent, err := s.opts.ParentOf(ctx, e.actor.Atespace, e.actor.UID)
	if err != nil {
		return "", err
	}
	e.parent, e.parentKnown = parent, true
	return parent, nil
}

// linkMemo gives a new forked actor's egress memo its parent's windows
// and clock at its first egress check, without the store (GAP-0091 with
// GAP-0179): a clone before any hook is checked against what the parent
// did. A concurrent check of the child waits for it. A failed lookup
// answers errForkUnlinked (the callout's chain failure mode applies), and
// the next check tries again. The worker's store open copies the stored
// windows and saves the clock.
func (s *Service) linkMemo(ctx context.Context, e *actorEntry) error {
	if s.opts.ParentOf == nil {
		return nil
	}
	e.linkMu.Lock()
	defer e.linkMu.Unlock()
	if e.memoLinked {
		return nil
	}
	s.mu.Lock()
	opened := e.store != nil
	s.mu.Unlock()
	if opened {
		// storeOf linked the store, and copyFork the memo.
		e.memoLinked = true
		return nil
	}
	parent, err := s.parentOfLocked(ctx, e)
	if err != nil {
		s.warnf("fork link for %s/%s failed, its chain calls answer unavailable until it succeeds: %v", e.actor.Atespace, e.actor.UID, err)
		return errForkUnlinked
	}
	if parent != "" && parent != e.actor.UID {
		s.mu.Lock()
		pe := s.actors[Actor{Atespace: e.actor.Atespace, UID: parent}.key()]
		var pst actorState
		if pe != nil {
			pst = pe.state
		}
		// In memory only: copyFork saves it with the store.
		e.state = forkClock(e.state, pst)
		s.mu.Unlock()
		if pe != nil {
			e.memo.linkFrom(&pe.memo)
		}
	}
	e.memoLinked = true
	return nil
}

func (s *Service) stateOf(e *actorEntry) actorState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return e.state
}

// setState replaces the actor's state; the high-water mark a concurrent
// call raised meanwhile is kept (GAP-0310).
func (s *Service) setState(e *actorEntry, st actorState) error {
	s.mu.Lock()
	st.RunningHighUnixNano = max(st.RunningHighUnixNano, e.state.RunningHighUnixNano)
	e.state = st
	s.mu.Unlock()
	return s.writeState(e)
}

// writeState saves the actor's state with its egress memo.
func (s *Service) writeState(e *actorEntry) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	s.mu.Lock()
	st, purged := e.state, e.purged
	s.mu.Unlock()
	if purged {
		return nil
	}
	st.Egress = e.memo.snapshot()
	s.disk("state")
	return writeFileAtomic(s.statePath(e.actor), mustJSON(st))
}

func (s *Service) repo(ctx context.Context, st *audit.Store, e *actorEntry, scope Scope) (*audit.ToolChainRepository, error) {
	opts := []audit.ToolChainOption{audit.WithToolChainClock(func() time.Time {
		return s.stamp(e, s.opts.Now())
	})}
	switch scope {
	case ScopeSession:
	case ScopeActor:
		opts = append(opts, audit.WithToolChainActorScope(e.actor.Atespace, e.actor.UID))
	default:
		return nil, bad(errors.New("chainstate: scope is session or actor"))
	}
	return st.ToolChainRepositoryWith(ctx, opts...)
}

// stamp is wall in the actor's running time for a time the leader gives
// one of its events or checks: it raises the high-water mark, so nothing
// later is ever before it, whatever the wall clock does (GAP-0310).
func (s *Service) stamp(e *actorEntry, wall time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.raiseLocked(e, e.state.running(wall))
}

// raiseLocked raises the actor's high-water mark to t (s.mu held).
func (s *Service) raiseLocked(e *actorEntry, t time.Time) time.Time {
	e.state.RunningHighUnixNano = max(e.state.RunningHighUnixNano, t.UnixNano())
	return t
}

// touch records a request of the actor itself: a hook chain call, an
// intent call or an egress check (actorState.active, GAP-0292). It is
// saved with the next state write; a leader that stops before loses only
// running time, so the windows last longer, never shorter.
func (s *Service) touch(e *actorEntry) {
	s.mu.Lock()
	e.state = e.state.active(s.opts.Now())
	s.mu.Unlock()
}

// holdsEgressLocked reports whether the actor window still holds the first
// step of an egress chain at the actor's running time now, or may (a cold
// memo). Such a window is never purged for a long suspend or silence, and
// a revert does not end it (GAP-0292). s.mu is held.
func (s *Service) holdsEgressLocked(e *actorEntry) bool {
	v, ok := e.memo.verdict(e.state.running(s.opts.Now()), EgressAlert)
	return !ok || len(v.Detected) > 0
}

func (s *Service) holdsEgress(e *actorEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holdsEgressLocked(e)
}

// Observe serves ChainObserve: one hook chain operation. The leader stamps
// the event with its own receive time in the actor's running time.
func (s *Service) Observe(ctx context.Context, in ObserveRequest) (ObserveResponse, error) {
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return ObserveResponse{}, err
	}
	defer release()
	st, instance, err := s.storeOf(ctx, e)
	if err != nil {
		return ObserveResponse{}, err
	}
	defer s.lock(in.Actor)()
	s.touch(e)
	repo, err := s.repo(ctx, st, e, in.Scope)
	if err != nil {
		return ObserveResponse{}, err
	}
	if in.Op != OpAttach {
		if in.Join == nil {
			return ObserveResponse{}, bad(errors.New("chainstate: the operation needs its join"))
		}
		if err := st.RecordToolChainJoin(ctx, audit.ToolChainJoin{
			ConnectorInstanceID: instance, SemanticEventID: audit.SemanticEventID(in.Join.SemanticEventID),
			EventName: in.Join.EventName, InputFingerprint: in.Join.InputFingerprint,
			ReceivedAt: s.stamp(e, s.opts.Now()), SessionDigest: in.Join.SessionDigest,
		}); err != nil {
			return ObserveResponse{}, bad(err)
		}
	}
	var result any
	switch in.Op {
	case OpObserve:
		var x audit.ToolChainObserveInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		x.ConnectorInstanceID = instance
		if err := s.notePending(e, in.Scope, x.Projection); err != nil {
			return ObserveResponse{}, err
		}
		result, err = repo.Observe(ctx, x)
	case OpResolve:
		var x audit.ToolChainResolvePendingInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		x.ConnectorInstanceID = instance
		var r audit.ToolChainResolvePendingResult
		r, err = repo.ResolvePending(ctx, x)
		if err == nil {
			r, err = s.furtherResult(ctx, repo, e, in, x, r)
		}
		result = r
	case OpPrepare:
		var x audit.ToolChainPreparePendingInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		// The replicas mint their own semantic event IDs: a PreToolUse
		// delivered again to another replica is the same call, not a reused
		// invocation ID that voids the proposal (GAP-0562). Set here, so no
		// caller sets it.
		x.PreEventFromAnyReplica = true
		x.ConnectorInstanceID = instance
		if err := s.notePending(e, in.Scope, x.Projection); err != nil {
			return ObserveResponse{}, err
		}
		var r audit.ToolChainPreparePendingResult
		r, err = repo.PreparePending(ctx, x)
		s.noteCall(e, in, x, r.Status, err)
		result = r
	case OpDiscard:
		var x audit.ToolChainDiscardPendingForEventSessionInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		x.ConnectorInstanceID = instance
		result, err = repo.DiscardPendingForEventSession(ctx, x)
	case OpReset:
		var x audit.ToolChainResetForTerminalEventSessionInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		x.ConnectorInstanceID = instance
		result, err = repo.ResetForTerminalEventSession(ctx, x)
	case OpAttach:
		var x AttachInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		err = repo.AttachFinalization(ctx, x.ReceiptIDs, x.EvaluationID, x.AuditEventID)
		result = AttachResult{Attached: err == nil}
	default:
		return ObserveResponse{}, bad(fmt.Errorf("chainstate: unknown operation %q", in.Op))
	}
	if in.Scope == ScopeActor && in.Op != OpAttach {
		// Whatever the operation did to the actor window (a failed one may
		// have written part of it), the memo is the store's again.
		s.syncMemo(ctx, st, e)
	}
	if err != nil {
		if errors.Is(err, audit.ErrToolChainIntegrity) || errors.Is(err, audit.ErrToolChainConflict) {
			return ObserveResponse{}, bad(err)
		}
		return ObserveResponse{}, err
	}
	out, err := encodeGob(result)
	return ObserveResponse{Result: out}, err
}

// notePending puts a first step of an egress chain that an actor-window
// operation is about to store (an observe, or a prepare at PreToolUse) in
// the memo and its saved copy first: a leader that stops before the read
// back restarts stricter, never laxer.
func (s *Service) notePending(e *actorEntry, scope Scope, p guardrail.ToolChainProjection) error {
	if scope != ScopeActor || !startsEgressChain(p.DetectionStepMask) {
		return nil
	}
	e.memo.notePending(s.stamp(e, s.opts.Now()), p)
	return s.writeState(e)
}

// syncMemo makes the actor's egress memo the store's own state of the
// actor window (GAP-0179). It is the one way the memo learns a step: every
// path that writes the actor window calls it afterwards, with the actor's
// calls ordered (the actor lock, or a store not yet published): the hook
// operations, the fork copy, the revert barrier and the worker's egress
// record, and the worker for a memo a new leader could not restore. The
// state file is saved when the memo changed. A failed read leaves the memo
// cold, so the egress check answers unavailable (the callout's chain
// failure mode decides) and the worker reads it again.
func (s *Service) syncMemo(ctx context.Context, st *audit.Store, e *actorEntry) {
	changed, err := s.readMemo(ctx, st, e)
	if err != nil {
		e.memo.invalidate()
		s.warnf("chain memo of %s/%s: %v", e.actor.Atespace, e.actor.UID, err)
		return
	}
	if !changed {
		return
	}
	if err := s.writeState(e); err != nil {
		s.warnf("state of %s/%s: %v", e.actor.Atespace, e.actor.UID, err)
	}
}

// readMemo reads the actor window into the memo; it reports whether the
// memo changed.
func (s *Service) readMemo(ctx context.Context, st *audit.Store, e *actorEntry) (bool, error) {
	instance, err := audit.ToolChainSubstrateInstanceID(e.actor.Atespace, e.actor.UID)
	if err != nil {
		return false, err
	}
	repo, err := s.repo(ctx, st, e, ScopeActor)
	if err != nil {
		return false, err
	}
	state, err := repo.ScopeState(ctx, instance, egressStep1Mask)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	for _, ev := range state.Events {
		s.raiseLocked(e, ev.ReceivedAt)
	}
	for _, p := range state.Pending {
		s.raiseLocked(e, p.PreparedAt)
	}
	s.mu.Unlock()
	return e.memo.set(memoWindow{Ruleset: state.RulesetFingerprint, Next: state.NextSequence,
		Events: state.Events, Pending: state.Pending}), nil
}

// warmMemo is the worker's read back of a cold memo.
func (s *Service) warmMemo(ctx context.Context, a Actor) error {
	e, release, err := s.acquire(a)
	if err != nil {
		return err
	}
	defer release()
	st, _, err := s.storeOf(ctx, e)
	if err != nil {
		return err
	}
	defer s.lock(a)()
	if _, err := s.readMemo(ctx, st, e); err != nil {
		return err
	}
	return s.writeState(e)
}

// AttachResult is OpAttach's answer.
type AttachResult struct{ Attached bool }

// AttachInput is OpAttach's input.
type AttachInput struct {
	ReceiptIDs   []string
	EvaluationID string
	AuditEventID string
}

func (s *Service) intents(e *actorEntry) *intentstore.Process {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.intents == nil {
		e.intents = intentstore.NewProcess(intentstore.Limits{MaxSessions: intentMaxSessions, MaxPrior: intentMaxPrior, TTL: intentTTL})
	}
	return e.intents
}

// toResponse is a session's context. A --task actor's task text is its
// verified intent and always comes first; a prompt in the session (from the
// agent, so a claim) is shown after it, never in its place (GAP-0093).
func toResponse(snap intentstore.Snapshot, task string) IntentResponse {
	out := IntentResponse{UserIntent: snap.UserIntent}
	if task != "" {
		out.UserIntent, out.Task = task, true
		if snap.UserIntent != "" && snap.UserIntent != task {
			out.UserIntent = task + "\n\nLatest prompt in this session (from the agent, not verified):\n" + snap.UserIntent
		}
	}
	for _, c := range snap.Prior {
		out.Prior = append(out.Prior, IntentCall{Tool: c.Tool, Args: c.Args})
	}
	return out
}

// IntentGet serves IntentGet: a session's context without recording. Found
// reports a context for the key or a task of the actor. Only the actor's
// own store is read: the leader keys every store by the verified actor.
func (s *Service) IntentGet(_ context.Context, in IntentRequest) (IntentResponse, error) {
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return IntentResponse{}, err
	}
	defer release()
	s.touch(e)
	snap, found := s.intents(e).Peek(in.Key)
	task := s.stateOf(e).Task
	out := toResponse(snap, task)
	out.Found = found || task != ""
	return out, nil
}

// IntentPut serves IntentPut.
func (s *Service) IntentPut(ctx context.Context, in IntentRequest) (IntentResponse, error) {
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return IntentResponse{}, err
	}
	defer release()
	if in.Op != IntentTask && in.Key == "" {
		return IntentResponse{}, bad(errors.New("chainstate: an intent needs its session key"))
	}
	if in.Op != IntentTask {
		// The launcher registers the task; every other operation is the actor's.
		s.touch(e)
	}
	p := s.intents(e)
	switch in.Op {
	case IntentPrompt:
		return IntentResponse{}, p.ObservePrompt(ctx, in.Key, in.Text)
	case IntentAppend:
		snap, err := p.AppendToolCall(ctx, in.Key, intentstore.ToolCall{Tool: in.Tool, Args: in.Args})
		return toResponse(snap, s.stateOf(e).Task), err
	case IntentReset:
		return IntentResponse{}, p.Reset(ctx, in.Key)
	case IntentTask:
		text := in.Text
		if len(text) > taskMaxBytes {
			text = text[:taskMaxBytes]
		}
		defer s.lock(in.Actor)()
		st := s.stateOf(e)
		st.Task = text
		return IntentResponse{}, s.setState(e, st)
	}
	return IntentResponse{}, bad(fmt.Errorf("chainstate: unknown intent operation %q", in.Op))
}

// Running serves ChainRunning: the controller saw these actors running, so
// each runs at the leader's receive time (actorState.active), as for one of
// its own requests (GAP-0539). Only an actor the leader keeps chain state
// for is touched; others have no window to age, and an unknown or purged
// one gets no entry. It is saved with the actor's next state write: a
// leader that stops before loses only running time.
func (s *Service) Running(_ context.Context, in RunningRequest) (struct{}, error) {
	if len(in.Actors) > MaxRunningActors {
		return struct{}{}, bad(fmt.Errorf("chainstate: a running report names at most %d actors", MaxRunningActors))
	}
	for _, a := range in.Actors {
		if err := a.Validate(); err != nil {
			return struct{}{}, bad(err)
		}
	}
	now := s.opts.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range in.Actors {
		if e := s.actors[a.key()]; e != nil && !e.purged && !e.purgeIdle {
			e.state = e.state.active(now)
		}
	}
	return struct{}{}, nil
}

// Lifecycle serves ChainLifecycle. Times are the controller's; zero is the
// leader's receive time.
func (s *Service) Lifecycle(ctx context.Context, in LifecycleEvent) (LifecycleResult, error) {
	if err := in.Actor.Validate(); err != nil {
		return LifecycleResult{}, bad(err)
	}
	at := s.opts.Now()
	if in.AtUnixNano > 0 {
		at = time.Unix(0, in.AtUnixNano)
	}
	if in.Event == LifecycleDeleted {
		if s.opts.Deleted != nil {
			gone, err := s.opts.Deleted(ctx, in.Actor.Atespace, in.Actor.UID)
			if err != nil {
				return LifecycleResult{}, err
			}
			if !gone {
				// Not the controller's delete of a gone actor: keep the
				// chains (an ignored event is not retried).
				s.warnf("delete of %s/%s ignored: its registration is not marked deleted", in.Actor.Atespace, in.Actor.UID)
				return LifecycleResult{Ignored: true}, nil
			}
		}
		s.mu.Lock()
		s.goneLocked(in.Actor.key())
		if e := s.actors[in.Actor.key()]; e != nil {
			if e.refs > 0 {
				// Calls still hold the store: purge when the last returns,
				// and admit no new ones.
				e.purgeIdle = true
			} else {
				s.purgeLocked(e)
			}
		}
		s.mu.Unlock()
		s.runPurges()
		return LifecycleResult{}, nil
	}
	if in.Event == LifecycleCrashed {
		if s.opts.OnCrashed != nil {
			s.opts.OnCrashed(ctx, in.Actor)
		}
		return LifecycleResult{}, nil
	}
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return LifecycleResult{}, err
	}
	defer release()
	switch in.Event {
	case LifecycleSuspended, LifecycleResumed:
		defer s.lock(in.Actor)()
		st := s.stateOf(e)
		if at.UnixNano() < st.LastEventUnixNano {
			// A late event older than the last one applied (GAP-0092).
			return LifecycleResult{Ignored: true}, nil
		}
		st.LastEventUnixNano = at.UnixNano()
		if in.Event == LifecycleSuspended {
			if st.SinceUnixNano == 0 {
				st.SinceUnixNano = at.UnixNano()
			}
		} else {
			st.SinceUnixNano, st.Retired = 0, false
		}
		return LifecycleResult{}, s.setState(e, st)
	case LifecycleForked:
		if in.Parent == nil {
			return LifecycleResult{}, bad(errors.New("chainstate: a fork names its parent"))
		}
		if s.opts.ParentOf != nil {
			// The parent is the verified registration's, never the
			// caller's word alone (GAP-0142).
			parent, err := s.opts.ParentOf(ctx, in.Actor.Atespace, in.Actor.UID)
			if err != nil {
				return LifecycleResult{}, err
			}
			if parent == "" || parent != in.Parent.UID || in.Parent.Atespace != in.Actor.Atespace {
				s.warnf("fork event for %s/%s ignored: its registration names parent %q", in.Actor.Atespace, in.Actor.UID, parent)
				return LifecycleResult{Ignored: true}, nil
			}
		}
		st, instance, err := s.storeOf(ctx, e)
		if err != nil {
			return LifecycleResult{}, err
		}
		defer s.lock(in.Actor)()
		return s.copyFork(ctx, e, st, instance, *in.Parent, at)
	case LifecycleReverted:
		return s.revert(ctx, e, at)
	}
	return LifecycleResult{}, bad(fmt.Errorf("chainstate: unknown lifecycle event %q", in.Event))
}

// lifecycleSession is the session join of events the leader makes itself.
func lifecycleSession(name string) string {
	d, _ := audit.ToolChainSubstrateSessionDigest("substrate", name)
	return d
}

// syntheticEvent records a leader-made event in the actor's store.
func (s *Service) syntheticEvent(ctx context.Context, st *audit.Store, instance audit.ConnectorInstanceID,
	e *actorEntry, name, session string, wall time.Time) (audit.SemanticEventID, string, error) {
	id, err := audit.NewSemanticEventID()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(name + "\x00" + string(id)))
	fp := hex.EncodeToString(sum[:])
	err = st.RecordToolChainJoin(ctx, audit.ToolChainJoin{ConnectorInstanceID: instance, SemanticEventID: id,
		EventName: name, InputFingerprint: fp, ReceivedAt: s.stamp(e, wall), SessionDigest: session})
	return id, fp, err
}

// revert puts an artifact mutation barrier into every window of the actor:
// the files may differ from what the window saw, so no same-artifact chain
// joins across it. Findings and receipts stay.
func (s *Service) revert(ctx context.Context, e *actorEntry, at time.Time) (LifecycleResult, error) {
	st, instance, err := s.storeOf(ctx, e)
	if err != nil {
		return LifecycleResult{}, err
	}
	defer s.lock(e.actor)()
	windows, err := st.ToolChainInstanceWindows(ctx, instance)
	if err != nil {
		return LifecycleResult{}, err
	}
	// A revert never ends an egress chain: the snapshot the actor returns
	// to may hold what it read (a revert of a suspended actor whose
	// snapshot is uploaded returns to that very snapshot), so the actor
	// window takes no barrier while it holds a secret read; the session
	// windows still do (GAP-0292).
	keepEgress := s.holdsEgress(e)
	barrier := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusNotApplicable,
		DetectionStepMask: guardrail.ToolChainArtifactMutationBarrier}
	n := 0
	for _, w := range windows {
		scope, session := ScopeSession, w.ScopeDigest
		if w.Scope == audit.ToolChainScopeRoot {
			scope, session = ScopeActor, lifecycleSession("revert")
			if keepEgress {
				continue
			}
		}
		repo, err := s.repo(ctx, st, e, scope)
		if err != nil {
			return LifecycleResult{Barriers: n}, err
		}
		id, fp, err := s.syntheticEvent(ctx, st, instance, e, "substrate.revert", session, at)
		if err != nil {
			return LifecycleResult{Barriers: n}, err
		}
		if _, err := repo.Observe(ctx, audit.ToolChainObserveInput{SemanticEventID: id, ConnectorInstanceID: instance,
			InputFingerprint: fp, RulesetFingerprint: w.RulesetDigest, Projection: barrier}); err != nil {
			return LifecycleResult{Barriers: n}, err
		}
		n++
	}
	s.syncMemo(ctx, st, e)
	return LifecycleResult{Barriers: n}, nil
}

// Egress serves ChainEgress: the callout's synchronous chain check. It
// answers from the actor's memo (no store access, GAP-0179) and hands an
// allowed step to the egress worker, which records it in the actor window
// under its active ruleset. A refused request sent nothing, so it is not
// recorded as a step: refused attempts never use up the steps of a chain's
// event window. They are the actor's own requests, though, so they do run
// its clock (touch, stamp), and the window's time limit still ages a secret
// read across them (GAP-0319). A cold memo answers errWarming and the worker reads it
// back. A new forked actor's memo is linked to its parent's first
// (linkMemo).
//
// The UID comes from the callout's name cache, which may still hold a
// deleted incarnation, or one a same-name actor replaced. Such a UID is
// answered stale, never from state: its windows are not the running
// actor's. Current is read before the entry is taken and again while it is
// held, and a deleted actor's entry is never made again (Service.gone), so
// a delete racing the check cannot give the purged UID a fresh, empty entry
// that answers allow (GAP-0234).
func (s *Service) Egress(ctx context.Context, in EgressRequest) (EgressVerdict, error) {
	if s.opts.Current != nil {
		if in.Name == "" {
			return EgressVerdict{}, bad(errors.New("chainstate: an egress check names the actor"))
		}
		if err := in.Actor.Validate(); err != nil {
			return EgressVerdict{}, bad(err)
		}
		live, err := s.opts.Current(ctx, in.Actor.Atespace, in.Name, in.Actor.UID)
		if err != nil {
			return EgressVerdict{}, err
		}
		if !live {
			return staleVerdict, nil
		}
	}
	e, release, created, err := s.acquireEntry(in.Actor, true)
	switch {
	case errors.Is(err, errGone), errors.Is(err, errEvicted):
		// Deleted, or its purge (a delete's, or the atespace cap's) still
		// running: there is no state to answer from. Stale, not an error,
		// which the callout would take as unchecked (allowed with an alert
		// on an attended OSS install); a UID stale twice is refused,
		// retryable.
		return staleVerdict, nil
	case err != nil:
		return EgressVerdict{}, err
	}
	defer release()
	if s.opts.Current != nil {
		// Asked again while the entry is held. A delete marks the
		// registration first, then purges; from here on its purge waits
		// for this call. So a UID current now is answered from its own
		// state, and one deleted (or replaced) since the first read gets
		// stale, and the entry this call made for it is dropped
		// (GAP-0234).
		live, err := s.opts.Current(ctx, in.Actor.Atespace, in.Name, in.Actor.UID)
		if err != nil || !live {
			if created {
				s.mu.Lock()
				e.purgeIdle = true
				s.mu.Unlock()
			}
			if err != nil {
				return EgressVerdict{}, err
			}
			return staleVerdict, nil
		}
	}
	if err := s.linkMemo(ctx, e); err != nil {
		return EgressVerdict{}, err
	}
	s.touch(e)
	now := s.stamp(e, s.opts.Now())
	v, ok := e.memo.verdict(now, s.EgressAction())
	if ok {
		st := s.stateOf(e)
		v.Unrecorded = noteWithin(st.UnrecordedUnixNano, st.UnrecordedWhy, now)
		if v.Rule == guardrail.ToolChainSecretReadThenEgress {
			if why := noteWithin(st.UnclearedUnixNano, st.UnclearedWhy, now); why != "" {
				v.Reason += " The " + why + "."
			}
		}
	}
	switch {
	case !ok:
		s.egress.push(egressRecord{actor: e.actor, sync: true})
		return EgressVerdict{}, errWarming
	case !v.Deny:
		// A detection under the alert action is answered, as a hit is.
		if len(v.Detected) == 0 && s.starting() && !s.bornInTerm(ctx, in.Actor) {
			// Not recorded: as during the outage, the callout refuses a
			// send and the step is not the actor's yet.
			return EgressVerdict{}, errStarting
		}
		s.egress.push(egressRecord{actor: e.actor, in: in})
	}
	return v, nil
}

// errStarting answers a clear egress check within opts.StartGrace of the
// leader's first one (GAP-0601). The leader client retries unavailable, so
// the callout usually reports the check as timed out.
var errStarting = &leader.WireError{Code: leader.CodeUnavailable,
	Message: "the gateway leader started moments ago; tool calls a gateway could not record while no leader answered may still be arriving"}

// starting reports whether a clear egress check is within opts.StartGrace
// of the first one this leader term answered, and within startGraceCap of
// the term's start.
func (s *Service) starting() bool {
	if s.opts.StartGrace <= 0 {
		return false
	}
	s.graceMu.Lock()
	defer s.graceMu.Unlock()
	now := s.opts.Now()
	if now.Sub(s.termAt) >= startGraceCap(s.opts.StartGrace) {
		return false
	}
	if !s.served {
		s.servingAt, s.served = now, true
	}
	return now.Sub(s.servingAt) < s.opts.StartGrace
}

// bornInTerm reports whether the actor was registered in this leader term
// and is not a fork. Then the start grace has nothing to wait for
// (GAP-0642). The grace waits for a gateway's note of a tool step it could
// not record while no leader answered. A registration is written through
// the leader, so an actor registered in this term did not exist during that
// outage and took no such step. Its first clone right after a restart is
// answered at once. Before, it was refused for up to the grace, and a run
// --clone right after a rollout failed with 503. A fork starts from its
// parent's windows, which may still be waiting for a note, so it waits like
// any older actor.
func (s *Service) bornInTerm(ctx context.Context, a Actor) bool {
	if s.opts.Born == nil || a.UID == "" {
		return false
	}
	s.graceMu.Lock()
	term := s.termAt
	s.graceMu.Unlock()
	created, parent, err := s.opts.Born(ctx, a.Atespace, a.UID)
	return err == nil && parent == "" && !created.IsZero() && !created.Before(term)
}

// startGraceCap is how long after the start of a leader term the start
// grace can last at most: twice the grace (30 s on the leader). A new
// leader is reachable within its readiness period (5 s) and the Service
// endpoint update; a gateway's waiting note then arrives within one retry
// (5 s) and its timeout (2 s). A clear check later than that cannot be
// ahead of a note, so it is answered: before the cap, the first git clone
// after any leader restart was refused (GAP-0601, IB5 TST-2593).
func startGraceCap(grace time.Duration) time.Duration { return 2 * grace }

// Leading starts the leader term (leader.Elector OnStarted, once per
// process: the elector leads once per Run, and the leader exits when Run
// ends): the start grace and its cap run from here, not from New, which
// can come a lease duration earlier while the old leader's lease expires.
func (s *Service) Leading() {
	if s == nil {
		return
	}
	s.graceMu.Lock()
	defer s.graceMu.Unlock()
	s.served, s.servingAt = false, time.Time{}
	s.termAt = s.opts.Now()
}

// staleVerdict answers an egress check under a UID that is not the
// actor's live incarnation.
var staleVerdict = EgressVerdict{Stale: true, Deny: true, Rule: "actor_not_current",
	Reason: "DefenseClaw's registrations say this actor UID was deleted or replaced by a newer actor of the same name."}

// recordEgress is the worker's exact record of an egress step: the event
// in the actor window, then the memo read back from the store.
func (s *Service) recordEgress(ctx context.Context, in EgressRequest) error {
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return err
	}
	defer release()
	st, instance, err := s.storeOf(ctx, e)
	if err != nil {
		return err
	}
	defer s.lock(in.Actor)()
	windows, err := st.ToolChainInstanceWindows(ctx, instance)
	if err != nil {
		return err
	}
	ruleset := ""
	for _, w := range windows {
		if w.Scope == audit.ToolChainScopeRoot {
			ruleset = w.RulesetDigest
		}
	}
	if ruleset != "" {
		// With no actor window there is nothing to join the step to.
		err = s.recordEgressStep(ctx, st, instance, e, ruleset)
	}
	s.syncMemo(ctx, st, e)
	return err
}

// recordEgressStep records one egress step in the actor window.
func (s *Service) recordEgressStep(ctx context.Context, st *audit.Store, instance audit.ConnectorInstanceID, e *actorEntry, ruleset string) error {
	repo, err := s.repo(ctx, st, e, ScopeActor)
	if err != nil {
		return err
	}
	id, fp, err := s.syntheticEvent(ctx, st, instance, e, "substrate.egress", lifecycleSession("egress"), s.opts.Now())
	if err != nil {
		return err
	}
	_, err = repo.Observe(ctx, audit.ToolChainObserveInput{SemanticEventID: id, ConnectorInstanceID: instance,
		InputFingerprint: fp, RulesetFingerprint: ruleset, Projection: egressStep})
	return err
}

// SweepResult counts what a sweep did.
type SweepResult struct {
	Retired int
	Purged  int
}

// Sweep retires actors suspended past the retention (the atespace cap
// evicts them first) and purges actors suspended, or silent, past
// PurgeAfter whose window holds no secret read (GAP-0292).
//
// A window that holds a secret read is purged past PurgeAfter only for an
// actor Deleted confirms gone: a delete the controller never sent (it keeps
// its actor list in memory, so an actor deleted while it was down or
// restarting is never reported). Such an actor makes no requests, so its
// clock is frozen and its window would hold forever (GAP-0311). An actor
// that exists, or one the lookup cannot answer for, is kept.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	now := s.opts.Now()
	var res SweepResult
	var retired []*actorEntry
	var held []Actor
	s.mu.Lock()
	for _, e := range s.actors {
		if e.refs != 0 {
			continue
		}
		since := e.lastUsed
		if e.state.SinceUnixNano != 0 {
			since = time.Unix(0, e.state.SinceUnixNano)
		}
		old := now.Sub(since) > s.opts.PurgeAfter
		switch {
		case old && !s.holdsEgressLocked(e):
			s.purgeLocked(e)
			res.Purged++
			continue
		case old && s.opts.Deleted != nil:
			held = append(held, e.actor)
		}
		if e.state.SinceUnixNano != 0 && !e.state.Retired && now.Sub(since) > s.opts.Retention {
			e.state.Retired = true
			retired = append(retired, e)
		}
	}
	s.mu.Unlock()
	res.Purged += s.purgeDeleted(ctx, held)
	s.runPurges()
	for _, e := range retired {
		if err := s.writeState(e); err != nil {
			return res, err
		}
		res.Retired++
	}
	return res, nil
}

// purgeDeleted purges the actors in held whose registration Deleted
// confirms gone, as their delete event would have (GAP-0311). The lookups
// run outside mu; an actor in use again since, or one the lookup fails
// for, is kept.
func (s *Service) purgeDeleted(ctx context.Context, held []Actor) int {
	n := 0
	for _, a := range held {
		gone, err := s.opts.Deleted(ctx, a.Atespace, a.UID)
		if err != nil {
			s.warnf("sweep: %s/%s kept, its registration could not be read: %v", a.Atespace, a.UID, err)
			continue
		}
		if !gone {
			continue
		}
		s.mu.Lock()
		if e := s.actors[a.key()]; e != nil && e.refs == 0 {
			s.goneLocked(a.key())
			s.purgeLocked(e)
			n++
		}
		s.mu.Unlock()
	}
	return n
}

// Run sweeps every 10 minutes, and checkpoints the open stores every
// WALGuardEvery, until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	wal := time.NewTicker(s.opts.WALGuardEvery)
	defer wal.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wal.C:
			s.guardWALs(ctx)
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil {
				s.warnf("sweep: %v", err)
			}
		}
	}
}

// The WAL guard of the per-actor stores: the log is copied on every pass,
// the writer is taken for at most storeWALWriterBudget when the log is over
// storeWALLimitBytes, and an idle log is cut back (audit.Store.
// CheckpointWALIfLarge, the gateway's pass for audit.db).
const (
	storeWALLimitBytes   = 4 << 20
	storeWALWriterBudget = 50 * time.Millisecond
	storeWALPassTimeout  = 10 * time.Second
)

// guardWALs checkpoints the write-ahead log of every open per-actor store.
// An audit store runs with SQLite's own checkpoints off
// (wal_autocheckpoint=0): its owner copies the log, as the gateway's WAL
// guard does for audit.db. Nothing did for the chain stores, so each actor's
// log grew with every call it made, about 300 KiB per hook call (81 MB after
// 270 calls), on the leader's volume and in its memory (GAP-0404). A store
// closed or purged meanwhile answers not ready and is skipped.
func (s *Service) guardWALs(ctx context.Context) {
	s.mu.Lock()
	stores := make([]*audit.Store, 0, s.open)
	for _, e := range s.actors {
		if e.store != nil {
			stores = append(stores, e.store)
		}
	}
	s.mu.Unlock()
	for _, st := range stores {
		if ctx.Err() != nil {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, storeWALPassTimeout)
		_, err := st.CheckpointWALIfLarge(pctx, storeWALLimitBytes, storeWALWriterBudget)
		cancel()
		if err != nil && ctx.Err() == nil && st.Ready() && !errors.Is(err, context.DeadlineExceeded) {
			s.warnf("chain store WAL checkpoint: %v", err)
		}
	}
}

func actorFromKey(k string) (Actor, bool) {
	i := strings.IndexByte(k, '/')
	if i < 0 {
		return Actor{}, false
	}
	a := Actor{Atespace: k[:i], UID: k[i+1:]}
	return a, a.Validate() == nil
}

func encodeGob(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decodeGob(raw []byte, v any) error {
	if len(raw) == 0 {
		return errors.New("chainstate: empty operation input")
	}
	return gob.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// EgressAction is the chain egress action in force.
func (s *Service) EgressAction() string { return *s.action.Load() }

// SetEgressAction changes the chain egress action (a config.yaml change,
// GAP-0276). The memo keeps no verdict of the old action: the next check
// answers with the new one.
func (s *Service) SetEgressAction(action string) error {
	switch action {
	case "":
		action = EgressBlock
	case EgressBlock, EgressAlert:
	default:
		return fmt.Errorf("chainstate: egress action %q is not block or alert", action)
	}
	s.action.Store(&action)
	return nil
}

// Unrecorded keeps that a gateway could not record one of the actor's tool
// steps in its chain window, at the actor's running time, for the egress
// checks of the chain window (GAP-0339).
func (s *Service) Unrecorded(ctx context.Context, in UnrecordedRequest) (struct{}, error) {
	if err := in.Actor.Validate(); err != nil {
		return struct{}{}, bad(err)
	}
	why := strings.TrimSpace(in.Why)
	if why == "" {
		why = "a tool step was not recorded"
	}
	if len(why) > maxUnrecordedWhy {
		why = why[:maxUnrecordedWhy]
	}
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return struct{}{}, err
	}
	defer release()
	defer s.lock(in.Actor)()
	s.touch(e)
	st := s.stateOf(e)
	at := s.stamp(e, s.opts.Now()).UnixNano()
	if in.Uncleared {
		st.UnclearedUnixNano, st.UnclearedWhy = at, why
	} else {
		st.UnrecordedUnixNano, st.UnrecordedWhy = at, why
	}
	return struct{}{}, s.setState(e, st)
}

// unrecordedWindow is how long, in running time, an unrecorded step counts
// for egress: the secret-read chain's window.
var unrecordedWindow = func() time.Duration {
	if d, ok := guardrail.ToolChainDefinitionByID(guardrail.ToolChainSecretReadThenEgress); ok {
		return d.TimeWindow
	}
	return 30 * time.Minute
}()

// noteWithin is why when its step at (running time) is within the window
// at running time now, else "".
func noteWithin(at int64, why string, now time.Time) string {
	if at == 0 || now.UnixNano()-at > int64(unrecordedWindow) {
		return ""
	}
	return why
}
