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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
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
	// silent) that long is kept before it is purged.
	DefaultPurgeAfter = 7 * 24 * time.Hour
	// DefaultMaxActors bounds the actors with chain state per atespace
	// (the 4,096-partition cap of a host store, per atespace).
	DefaultMaxActors = guardrail.ToolChainMaxPartitions
	// DefaultMaxOpenStores bounds the open SQLite handles; idle ones close.
	DefaultMaxOpenStores = 128
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
	// long (default 7 days). A deleted actor is purged at once.
	PurgeAfter time.Duration
	// MaxActors bounds the actors with state per atespace (default 4,096):
	// a new actor past it evicts a retired actor first, else the one used
	// least recently.
	MaxActors int
	// MaxOpenStores bounds the open per-actor stores (default 128).
	MaxOpenStores int
	// ParentOf returns the parent UID of a forked actor from its verified
	// registration ("" for none). The leader copies the parent's windows the
	// first time it sees the child, whatever comes first (GAP-0091).
	ParentOf func(ctx context.Context, atespace, uid string) (string, error)
	// Deleted reports whether the actor's registration is marked deleted
	// (true also when it has none). A deleted event purges only then: the
	// controller marks the registration first, and a peer that cannot write
	// registrations cannot wipe a live actor's chains (GAP-0142).
	Deleted func(ctx context.Context, atespace, uid string) (bool, error)
	// OnCrashed closes the actor's open asks when it crashes (the ask store).
	OnCrashed func(ctx context.Context, actor Actor)
	// Now replaces the clock (tests).
	Now func() time.Time
	// Warn receives operational warnings (default stderr).
	Warn io.Writer
}

// Service is the leader's chain and intent state. Every actor has its own
// store file, state file and intent map: an actor's expiries, prunes and
// LRU run on its own running-time clock and never touch another actor's
// rows (GAP-0089), and everything an actor holds is removed with it.
type Service struct {
	opts Options

	mu      sync.Mutex
	actors  map[string]*actorEntry // atespace/uid
	open    int
	closed  bool
	stripes [256]sync.Mutex
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
	openMu   sync.Mutex
	purged   bool
	// purgeIdle is a delete that waits for the calls holding the entry.
	purgeIdle bool
}

// actorState is what the leader keeps of an actor on the volume: its
// running-time clock, the order of its lifecycle events, and its task.
type actorState struct {
	// SuspendedNanos is the time suspended before the current run;
	// SinceUnixNano the start of the current suspension (0 while running).
	SuspendedNanos int64 `json:"suspended_nanos"`
	SinceUnixNano  int64 `json:"since_unix_nano,omitempty"`
	// LastEventUnixNano is the time of the last suspend or resume applied;
	// an older one arriving late is ignored (GAP-0092).
	LastEventUnixNano int64 `json:"last_event_unix_nano,omitempty"`
	Retired           bool  `json:"retired,omitempty"`
	// Forked is set once the child's clock started from its parent's; a
	// later or repeated fork event copies missing windows only (GAP-0142).
	Forked bool `json:"forked,omitempty"`
	// Task is the launcher-registered --task text.
	Task string `json:"task,omitempty"`
}

// running is wall in the actor's running time.
func (c actorState) running(wall time.Time) time.Time {
	off := c.SuspendedNanos
	if c.SinceUnixNano != 0 && wall.UnixNano() > c.SinceUnixNano {
		off += wall.UnixNano() - c.SinceUnixNano
	}
	return wall.Add(-time.Duration(off))
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
	}
	s := &Service{opts: opts, actors: map[string]*actorEntry{}}
	if err := s.load(); err != nil {
		return nil, err
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

// Close closes every store.
func (s *Service) Close() error {
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

// acquire returns the actor's entry with a reference; release returns it.
// An actor seen for the first time gets an entry (evicting another when the
// atespace is full).
func (s *Service) acquire(a Actor) (*actorEntry, func(), error) {
	if err := a.Validate(); err != nil {
		return nil, nil, bad(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, &leader.WireError{Code: leader.CodeUnavailable, Message: "chain store closed"}
	}
	e := s.actors[a.key()]
	if e != nil && e.purgeIdle {
		return nil, nil, errEvicted
	}
	if e == nil {
		s.makeRoomLocked(a.Atespace)
		e = &actorEntry{actor: a, lastUsed: s.opts.Now()}
		s.actors[a.key()] = e
	}
	e.refs++
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
		for _, st := range toClose {
			_ = st.Close()
		}
	}, nil
}

// makeRoomLocked evicts one actor of atespace when it is full: a retired
// actor first, else the least recently used; never one in use.
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
	sort.Slice(in, func(i, j int) bool {
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

// purgeLocked removes everything the leader holds of an actor.
func (s *Service) purgeLocked(e *actorEntry) {
	if e.store != nil {
		_ = e.store.Close()
		e.store = nil
		s.open--
	}
	e.purged = true
	delete(s.actors, e.actor.key())
	db := s.dbPath(e.actor)
	for _, p := range []string{db, db + "-wal", db + "-shm", s.statePath(e.actor)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.warnf("purge %s/%s: %v", e.actor.Atespace, e.actor.UID, err)
		}
	}
}

// storeOf opens the actor's store (a held entry). A store opened for the
// first time for an actor with a parent starts from the parent's windows.
func (s *Service) storeOf(ctx context.Context, e *actorEntry) (*audit.Store, audit.ConnectorInstanceID, error) {
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
	st, err = audit.NewStore(path)
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
	s.mu.Lock()
	if e.purged {
		s.mu.Unlock()
		_ = st.Close()
		return nil, "", errEvicted
	}
	e.store = st
	s.open++
	s.mu.Unlock()
	if fresh && s.opts.ParentOf != nil {
		parent, err := s.opts.ParentOf(ctx, e.actor.Atespace, e.actor.UID)
		if err != nil {
			s.warnf("parent of %s/%s: %v", e.actor.Atespace, e.actor.UID, err)
		} else if parent != "" && parent != e.actor.UID {
			if _, err := s.copyFork(ctx, e, st, instance, Actor{Atespace: e.actor.Atespace, UID: parent}, s.opts.Now()); err != nil {
				s.warnf("fork copy for %s/%s: %v", e.actor.Atespace, e.actor.UID, err)
			}
		}
	}
	return st, instance, nil
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
	if pe := s.actors[parent.key()]; pe != nil {
		pst = pe.state
	}
	cst := child.state
	s.mu.Unlock()
	if !cst.Forked {
		// The child's clock starts from the parent's running time once; a
		// late or repeated fork event never resets the child's own time.
		cst.SuspendedNanos = pst.SuspendedNanos
		if pst.SinceUnixNano != 0 && at.UnixNano() > pst.SinceUnixNano {
			cst.SuspendedNanos += at.UnixNano() - pst.SinceUnixNano
		}
		cst.SinceUnixNano, cst.Forked = 0, true
	}
	if cst.Task == "" {
		cst.Task = pst.Task
	}
	result := LifecycleResult{}
	if _, err := os.Stat(s.dbPath(parent)); err == nil {
		r, err := st.CopyToolChainFork(ctx, s.dbPath(parent), audit.ToolChainForkCopy{
			ParentInstance: parentInstance, ChildInstance: childInstance,
			ParentActorDigest: parentDigest, ChildActorDigest: childDigest, At: cst.running(at),
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
	return result, s.setState(child, cst)
}

func (s *Service) stateOf(e *actorEntry) actorState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return e.state
}

func (s *Service) setState(e *actorEntry, st actorState) error {
	s.mu.Lock()
	e.state = st
	s.mu.Unlock()
	return writeFileAtomic(s.statePath(e.actor), mustJSON(st))
}

func (s *Service) repo(ctx context.Context, st *audit.Store, e *actorEntry, scope Scope) (*audit.ToolChainRepository, error) {
	opts := []audit.ToolChainOption{audit.WithToolChainClock(func() time.Time {
		return s.stateOf(e).running(s.opts.Now())
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
			ReceivedAt: s.stateOf(e).running(s.opts.Now()), SessionDigest: in.Join.SessionDigest,
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
		result, err = repo.Observe(ctx, x)
	case OpResolve:
		var x audit.ToolChainResolvePendingInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		x.ConnectorInstanceID = instance
		result, err = repo.ResolvePending(ctx, x)
	case OpPrepare:
		var x audit.ToolChainPreparePendingInput
		if err := decodeGob(in.Input, &x); err != nil {
			return ObserveResponse{}, bad(err)
		}
		x.ConnectorInstanceID = instance
		result, err = repo.PreparePending(ctx, x)
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
	if err != nil {
		if errors.Is(err, audit.ErrToolChainIntegrity) || errors.Is(err, audit.ErrToolChainConflict) {
			return ObserveResponse{}, bad(err)
		}
		return ObserveResponse{}, err
	}
	out, err := encodeGob(result)
	return ObserveResponse{Result: out}, err
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

// IntentGet serves IntentGet: a session's context without recording.
func (s *Service) IntentGet(_ context.Context, in IntentRequest) (IntentResponse, error) {
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return IntentResponse{}, err
	}
	defer release()
	snap, _ := s.intents(e).Peek(in.Key)
	return toResponse(snap, s.stateOf(e).Task), nil
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
			if st.SinceUnixNano != 0 && at.UnixNano() > st.SinceUnixNano {
				st.SuspendedNanos += at.UnixNano() - st.SinceUnixNano
			}
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
		EventName: name, InputFingerprint: fp, ReceivedAt: s.stateOf(e).running(wall), SessionDigest: session})
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
	barrier := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusNotApplicable,
		DetectionStepMask: guardrail.ToolChainArtifactMutationBarrier}
	n := 0
	for _, w := range windows {
		scope, session := ScopeSession, w.ScopeDigest
		if w.Scope == audit.ToolChainScopeRoot {
			scope, session = ScopeActor, lifecycleSession("revert")
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
	return LifecycleResult{Barriers: n}, nil
}

// Egress serves ChainEgress: the callout's observed egress step, recorded in
// the actor window under its active ruleset at the leader's receive time and
// checked against the egress chains. An actor with no actor window has
// nothing to match.
func (s *Service) Egress(ctx context.Context, in EgressRequest) (EgressVerdict, error) {
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return EgressVerdict{}, err
	}
	defer release()
	st, instance, err := s.storeOf(ctx, e)
	if err != nil {
		return EgressVerdict{}, err
	}
	defer s.lock(in.Actor)()
	windows, err := st.ToolChainInstanceWindows(ctx, instance)
	if err != nil {
		return EgressVerdict{}, err
	}
	ruleset := ""
	for _, w := range windows {
		if w.Scope == audit.ToolChainScopeRoot {
			ruleset = w.RulesetDigest
		}
	}
	if ruleset == "" {
		return EgressVerdict{}, nil
	}
	var mask uint64
	for _, id := range egressChains {
		if bit, ok := guardrail.ToolChainStepMask(id, 2); ok {
			mask |= bit
		}
	}
	repo, err := s.repo(ctx, st, e, ScopeActor)
	if err != nil {
		return EgressVerdict{}, err
	}
	id, fp, err := s.syntheticEvent(ctx, st, instance, e, "substrate.egress", lifecycleSession("egress"), s.opts.Now())
	if err != nil {
		return EgressVerdict{}, err
	}
	result, err := repo.Observe(ctx, audit.ToolChainObserveInput{SemanticEventID: id, ConnectorInstanceID: instance,
		InputFingerprint: fp, RulesetFingerprint: ruleset,
		Projection: guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: mask}})
	if err != nil {
		return EgressVerdict{}, err
	}
	v := EgressVerdict{Detected: result.DetectedChainIDs}
	for _, chain := range result.DetectedChainIDs {
		if egressDenyChains[chain] {
			v.Rule = chain
			v.Reason = "Earlier in this actor's work it read a secret; DefenseClaw blocks sending data off the cluster after that."
			v.Deny = s.opts.EgressAction == EgressBlock
			break
		}
	}
	return v, nil
}

// SweepResult counts what a sweep did.
type SweepResult struct {
	Retired int
	Purged  int
}

// Sweep retires actors suspended past the retention (the atespace cap
// evicts them first) and purges actors suspended, or silent, past
// PurgeAfter.
func (s *Service) Sweep(_ context.Context) (SweepResult, error) {
	now := s.opts.Now()
	var res SweepResult
	var retired []*actorEntry
	s.mu.Lock()
	for _, e := range s.actors {
		if e.refs != 0 {
			continue
		}
		since := e.lastUsed
		if e.state.SinceUnixNano != 0 {
			since = time.Unix(0, e.state.SinceUnixNano)
		}
		switch {
		case now.Sub(since) > s.opts.PurgeAfter:
			s.purgeLocked(e)
			res.Purged++
		case e.state.SinceUnixNano != 0 && !e.state.Retired && now.Sub(since) > s.opts.Retention:
			e.state.Retired = true
			retired = append(retired, e)
		}
	}
	s.mu.Unlock()
	for _, e := range retired {
		if err := writeFileAtomic(s.statePath(e.actor), mustJSON(s.stateOf(e))); err != nil {
			return res, err
		}
		res.Retired++
	}
	return res, nil
}

// Run sweeps every 10 minutes until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil {
				s.warnf("sweep: %v", err)
			}
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
