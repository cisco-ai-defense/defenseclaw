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

// Intent bounds per atespace: the tool judge's own (llm_judge.go), with room
// for every live session of an atespace.
const (
	intentMaxSessions = 4096
	intentMaxPrior    = 7
	intentTTL         = 30 * time.Minute
	taskMaxBytes      = 4096
	// DefaultRetention is how long a suspended actor's windows stay ahead of
	// finished actors' in the partition LRU.
	DefaultRetention = 24 * time.Hour
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
	// Retention is how long a suspended actor counts as live (default 24 h).
	Retention time.Duration
	// OnCrashed closes the actor's open asks when it crashes (the ask store).
	OnCrashed func(ctx context.Context, actor Actor)
	// Now replaces the clock (tests).
	Now func() time.Time
	// Warn receives operational warnings (default stderr).
	Warn io.Writer
}

// Service is the leader's chain and intent state.
type Service struct {
	opts Options

	mu       sync.Mutex
	ensureMu sync.Mutex
	stores   map[string]*audit.Store
	// ensured is guarded by ensureMu.
	ensured map[audit.ConnectorInstanceID]bool
	clocks  map[string]*clock
	intents map[string]*intentstore.Process
	tasks   map[string]string
	stripes [256]sync.Mutex
	closed  bool
}

// clock is an actor's running-time state: the time it spent suspended
// before, and the start of the current suspension.
type clock struct {
	SuspendedNanos int64 `json:"suspended_nanos"`
	SinceUnixNano  int64 `json:"since_unix_nano,omitempty"`
	Retired        bool  `json:"retired,omitempty"`
}

// running is wall in the actor's running time.
func (c clock) running(wall time.Time) time.Time {
	off := c.SuspendedNanos
	if c.SinceUnixNano != 0 && wall.UnixNano() > c.SinceUnixNano {
		off += wall.UnixNano() - c.SinceUnixNano
	}
	return wall.Add(-time.Duration(off))
}

// New opens a Service on opts.Dir.
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
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Warn == nil {
		opts.Warn = os.Stderr
	}
	for _, d := range []string{"chains", "clocks", "tasks"} {
		if err := os.MkdirAll(filepath.Join(opts.Dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	return &Service{opts: opts, stores: map[string]*audit.Store{}, ensured: map[audit.ConnectorInstanceID]bool{},
		clocks: map[string]*clock{}, intents: map[string]*intentstore.Process{}, tasks: map[string]string{}}, nil
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

// Close closes every store.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	var errs []error
	for _, st := range s.stores {
		errs = append(errs, st.Close())
	}
	s.stores = map[string]*audit.Store{}
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

func (s *Service) store(atespace string) (*audit.Store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, &leader.WireError{Code: leader.CodeUnavailable, Message: "chain store closed"}
	}
	if st, ok := s.stores[atespace]; ok {
		return st, nil
	}
	st, err := audit.NewStore(filepath.Join(s.opts.Dir, "chains", atespace+".db"))
	if err != nil {
		return nil, err
	}
	if err := st.Init(); err != nil {
		_ = st.Close()
		return nil, err
	}
	s.stores[atespace] = st
	return st, nil
}

// actorStore returns the actor's store and instance, the instance recorded.
func (s *Service) actorStore(ctx context.Context, a Actor) (*audit.Store, audit.ConnectorInstanceID, error) {
	if err := a.Validate(); err != nil {
		return nil, "", bad(err)
	}
	instance, err := audit.ToolChainSubstrateInstanceID(a.Atespace, a.UID)
	if err != nil {
		return nil, "", bad(err)
	}
	st, err := s.store(a.Atespace)
	if err != nil {
		return nil, "", err
	}
	// The first calls of a new actor arrive together; one records the
	// instance and the others wait for it.
	s.ensureMu.Lock()
	defer s.ensureMu.Unlock()
	if !s.ensured[instance] {
		if err := st.EnsureToolChainSubstrateInstance(ctx, instance); err != nil {
			return nil, "", s.internal("record actor instance", err)
		}
		s.ensured[instance] = true
	}
	return st, instance, nil
}

// internal logs an error the leader cannot hand to the caller (the
// transport answers only "internal") and returns it.
func (s *Service) internal(what string, err error) error {
	var we *leader.WireError
	if err != nil && !errors.As(err, &we) {
		fmt.Fprintf(s.opts.Warn, "[chainstate] warning: %s: %v\n", what, err)
	}
	return err
}

func (s *Service) clockPath(a Actor) string {
	return filepath.Join(s.opts.Dir, "clocks", a.Atespace, a.UID+".json")
}

// clockOf returns a copy of the actor's clock state.
func (s *Service) clockOf(a Actor) clock {
	s.mu.Lock()
	c, ok := s.clocks[a.key()]
	s.mu.Unlock()
	if ok {
		return *c
	}
	var loaded clock
	if raw, err := os.ReadFile(s.clockPath(a)); err == nil {
		_ = json.Unmarshal(raw, &loaded)
	}
	s.mu.Lock()
	if c, ok := s.clocks[a.key()]; ok {
		loaded = *c
	} else {
		s.clocks[a.key()] = &loaded
	}
	s.mu.Unlock()
	return loaded
}

func (s *Service) setClock(a Actor, c clock) error {
	s.mu.Lock()
	cp := c
	s.clocks[a.key()] = &cp
	s.mu.Unlock()
	return writeFileAtomic(s.clockPath(a), mustJSON(c))
}

// runningNow is the actor's running clock for its repositories.
func (s *Service) runningNow(a Actor) func() time.Time {
	return func() time.Time { return s.clockOf(a).running(s.opts.Now()) }
}

func (s *Service) repo(ctx context.Context, st *audit.Store, a Actor, scope Scope) (*audit.ToolChainRepository, error) {
	opts := []audit.ToolChainOption{audit.WithToolChainClock(s.runningNow(a))}
	switch scope {
	case ScopeSession:
	case ScopeActor:
		opts = append(opts, audit.WithToolChainActorScope(a.Atespace, a.UID))
	default:
		return nil, bad(errors.New("chainstate: scope is session or actor"))
	}
	return st.ToolChainRepositoryWith(ctx, opts...)
}

// Observe serves ChainObserve: one hook chain operation.
func (s *Service) Observe(ctx context.Context, in ObserveRequest) (ObserveResponse, error) {
	st, instance, err := s.actorStore(ctx, in.Actor)
	if err != nil {
		return ObserveResponse{}, err
	}
	defer s.lock(in.Actor)()
	repo, err := s.repo(ctx, st, in.Actor, in.Scope)
	if err != nil {
		return ObserveResponse{}, err
	}
	if in.Op != OpAttach {
		if in.Join == nil {
			return ObserveResponse{}, bad(errors.New("chainstate: the operation needs its join"))
		}
		received := s.clockOf(in.Actor).running(time.Unix(0, in.Join.ReceivedUnixNano))
		if err := st.RecordToolChainJoin(ctx, audit.ToolChainJoin{
			ConnectorInstanceID: instance, SemanticEventID: audit.SemanticEventID(in.Join.SemanticEventID),
			EventName: in.Join.EventName, InputFingerprint: in.Join.InputFingerprint,
			ReceivedAt: received, SessionDigest: in.Join.SessionDigest,
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

func (s *Service) intentProcess(atespace string) *intentstore.Process {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.intents[atespace]
	if !ok {
		p = intentstore.NewProcess(intentstore.Limits{MaxSessions: intentMaxSessions, MaxPrior: intentMaxPrior, TTL: intentTTL})
		s.intents[atespace] = p
	}
	return p
}

func (s *Service) taskPath(a Actor) string {
	return filepath.Join(s.opts.Dir, "tasks", a.Atespace, a.UID+".task")
}

// task is the launcher-registered task text of an actor, or "".
func (s *Service) task(a Actor) string {
	s.mu.Lock()
	t, ok := s.tasks[a.key()]
	s.mu.Unlock()
	if ok {
		return t
	}
	raw, _ := os.ReadFile(s.taskPath(a))
	t = string(raw)
	s.mu.Lock()
	s.tasks[a.key()] = t
	s.mu.Unlock()
	return t
}

func intentKey(a Actor, key string) string { return a.UID + "\x00" + key }

func toResponse(snap intentstore.Snapshot, task string) IntentResponse {
	out := IntentResponse{UserIntent: snap.UserIntent}
	if out.UserIntent == "" && task != "" {
		out.UserIntent, out.Task = task, true
	}
	for _, c := range snap.Prior {
		out.Prior = append(out.Prior, IntentCall{Tool: c.Tool, Args: c.Args})
	}
	return out
}

// IntentGet serves IntentGet: a session's context without recording.
func (s *Service) IntentGet(_ context.Context, in IntentRequest) (IntentResponse, error) {
	if err := in.Actor.Validate(); err != nil {
		return IntentResponse{}, bad(err)
	}
	snap, _ := s.intentProcess(in.Actor.Atespace).Peek(intentKey(in.Actor, in.Key))
	return toResponse(snap, s.task(in.Actor)), nil
}

// IntentPut serves IntentPut. For a --task actor the launcher's task text
// (a verified source) is the intent until a user prompt replaces it.
func (s *Service) IntentPut(ctx context.Context, in IntentRequest) (IntentResponse, error) {
	if err := in.Actor.Validate(); err != nil {
		return IntentResponse{}, bad(err)
	}
	p := s.intentProcess(in.Actor.Atespace)
	key := intentKey(in.Actor, in.Key)
	if in.Op != IntentTask && in.Key == "" {
		return IntentResponse{}, bad(errors.New("chainstate: an intent needs its session key"))
	}
	switch in.Op {
	case IntentPrompt:
		return IntentResponse{}, p.ObservePrompt(ctx, key, in.Text)
	case IntentAppend:
		snap, err := p.AppendToolCall(ctx, key, intentstore.ToolCall{Tool: in.Tool, Args: in.Args})
		return toResponse(snap, s.task(in.Actor)), err
	case IntentReset:
		return IntentResponse{}, p.Reset(ctx, key)
	case IntentTask:
		text := in.Text
		if len(text) > taskMaxBytes {
			text = text[:taskMaxBytes]
		}
		if err := writeFileAtomic(s.taskPath(in.Actor), []byte(text)); err != nil {
			return IntentResponse{}, err
		}
		s.mu.Lock()
		s.tasks[in.Actor.key()] = text
		s.mu.Unlock()
		return IntentResponse{}, nil
	}
	return IntentResponse{}, bad(fmt.Errorf("chainstate: unknown intent operation %q", in.Op))
}

func (s *Service) at(nanos int64) time.Time {
	if nanos > 0 {
		return time.Unix(0, nanos)
	}
	return s.opts.Now()
}

// Lifecycle serves ChainLifecycle.
func (s *Service) Lifecycle(ctx context.Context, in LifecycleEvent) (LifecycleResult, error) {
	if err := in.Actor.Validate(); err != nil {
		return LifecycleResult{}, bad(err)
	}
	at := s.at(in.AtUnixNano)
	switch in.Event {
	case LifecycleSuspended:
		defer s.lock(in.Actor)()
		c := s.clockOf(in.Actor)
		if c.SinceUnixNano == 0 {
			c.SinceUnixNano = at.UnixNano()
		}
		return LifecycleResult{}, s.setClock(in.Actor, c)
	case LifecycleResumed:
		defer s.lock(in.Actor)()
		c := s.clockOf(in.Actor)
		if c.SinceUnixNano != 0 && at.UnixNano() > c.SinceUnixNano {
			c.SuspendedNanos += at.UnixNano() - c.SinceUnixNano
		}
		c.SinceUnixNano, c.Retired = 0, false
		return LifecycleResult{}, s.setClock(in.Actor, c)
	case LifecycleForked:
		return s.fork(ctx, in, at)
	case LifecycleReverted:
		return s.revert(ctx, in.Actor, at)
	case LifecycleDeleted:
		st, instance, err := s.actorStore(ctx, in.Actor)
		if err != nil {
			return LifecycleResult{}, err
		}
		defer s.lock(in.Actor)()
		if err := st.RetireToolChainInstance(ctx, instance); err != nil {
			return LifecycleResult{}, err
		}
		c := s.clockOf(in.Actor)
		c.Retired = true
		return LifecycleResult{}, s.setClock(in.Actor, c)
	case LifecycleCrashed:
		if s.opts.OnCrashed != nil {
			s.opts.OnCrashed(ctx, in.Actor)
		}
		return LifecycleResult{}, nil
	}
	return LifecycleResult{}, bad(fmt.Errorf("chainstate: unknown lifecycle event %q", in.Event))
}

// fork starts the child's windows from the parent's, its clock from the
// parent's running time, and its task intent from the parent's. Asks and
// approvals are never copied.
func (s *Service) fork(ctx context.Context, in LifecycleEvent, at time.Time) (LifecycleResult, error) {
	if in.Parent == nil {
		return LifecycleResult{}, bad(errors.New("chainstate: a fork names its parent"))
	}
	parent, child := *in.Parent, in.Actor
	if parent.Atespace != child.Atespace {
		// Windows never cross an atespace (one store each); the child is
		// judged on its own history.
		return LifecycleResult{}, bad(errors.New("chainstate: a fork into another atespace inherits no windows"))
	}
	st, parentInstance, err := s.actorStore(ctx, parent)
	if err != nil {
		return LifecycleResult{}, err
	}
	_, childInstance, err := s.actorStore(ctx, child)
	if err != nil {
		return LifecycleResult{}, err
	}
	parentDigest, _ := audit.ToolChainActorScopeDigest(parent.Atespace, parent.UID)
	childDigest, _ := audit.ToolChainActorScopeDigest(child.Atespace, child.UID)
	unlockParent := s.lock(parent)
	pc := s.clockOf(parent)
	unlockParent()
	cc := clock{SuspendedNanos: pc.SuspendedNanos}
	if pc.SinceUnixNano != 0 && at.UnixNano() > pc.SinceUnixNano {
		cc.SuspendedNanos += at.UnixNano() - pc.SinceUnixNano
	}
	defer s.lock(child)()
	copied, err := st.CopyToolChainFork(ctx, audit.ToolChainForkCopy{
		ParentInstance: parentInstance, ChildInstance: childInstance,
		ParentActorDigest: parentDigest, ChildActorDigest: childDigest, At: cc.running(at),
	})
	if errors.Is(err, audit.ErrToolChainForkAlreadyStarted) {
		return LifecycleResult{}, nil
	}
	if err != nil {
		return LifecycleResult{}, err
	}
	if err := s.setClock(child, cc); err != nil {
		return LifecycleResult{}, err
	}
	if t := s.task(parent); t != "" {
		if err := writeFileAtomic(s.taskPath(child), []byte(t)); err != nil {
			return LifecycleResult{}, err
		}
		s.mu.Lock()
		s.tasks[child.key()] = t
		s.mu.Unlock()
	}
	return LifecycleResult{CopiedEvents: copied}, nil
}

// lifecycleSession is the session join of events the leader makes itself.
func lifecycleSession(name string) string {
	d, _ := audit.ToolChainSubstrateSessionDigest("substrate", name)
	return d
}

// syntheticEvent records a leader-made event in the actor's store.
func (s *Service) syntheticEvent(ctx context.Context, st *audit.Store, instance audit.ConnectorInstanceID,
	a Actor, name, session string, wall time.Time) (audit.SemanticEventID, string, error) {
	id, err := audit.NewSemanticEventID()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(name + "\x00" + string(id)))
	fp := hex.EncodeToString(sum[:])
	err = st.RecordToolChainJoin(ctx, audit.ToolChainJoin{ConnectorInstanceID: instance, SemanticEventID: id,
		EventName: name, InputFingerprint: fp, ReceivedAt: s.clockOf(a).running(wall), SessionDigest: session})
	return id, fp, err
}

// revert puts an artifact mutation barrier into every window of the actor:
// the files may differ from what the window saw, so no same-artifact chain
// joins across it. Findings and receipts stay.
func (s *Service) revert(ctx context.Context, a Actor, at time.Time) (LifecycleResult, error) {
	st, instance, err := s.actorStore(ctx, a)
	if err != nil {
		return LifecycleResult{}, err
	}
	defer s.lock(a)()
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
		repo, err := s.repo(ctx, st, a, scope)
		if err != nil {
			return LifecycleResult{Barriers: n}, err
		}
		id, fp, err := s.syntheticEvent(ctx, st, instance, a, "substrate.revert", session, at)
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
// the actor window under its active ruleset and checked against the egress
// chains. An actor with no actor window has nothing to match.
func (s *Service) Egress(ctx context.Context, in EgressRequest) (EgressVerdict, error) {
	st, instance, err := s.actorStore(ctx, in.Actor)
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
	repo, err := s.repo(ctx, st, in.Actor, ScopeActor)
	if err != nil {
		return EgressVerdict{}, err
	}
	id, fp, err := s.syntheticEvent(ctx, st, instance, in.Actor, "substrate.egress", lifecycleSession("egress"), s.at(in.AtUnixNano))
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

// Sweep marks actors suspended for longer than the retention as finished, so
// the partition LRU evicts them before live actors. It returns how many.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	now := s.opts.Now()
	s.mu.Lock()
	var due []Actor
	for k, c := range s.clocks {
		if c.SinceUnixNano != 0 && !c.Retired && now.UnixNano()-c.SinceUnixNano > int64(s.opts.Retention) {
			if a, ok := actorFromKey(k); ok {
				due = append(due, a)
			}
		}
	}
	s.mu.Unlock()
	n := 0
	for _, a := range due {
		st, instance, err := s.actorStore(ctx, a)
		if err != nil {
			return n, err
		}
		unlock := s.lock(a)
		err = st.RetireToolChainInstance(ctx, instance)
		if err == nil {
			c := s.clockOf(a)
			c.Retired = true
			err = s.setClock(a, c)
		}
		unlock()
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Run sweeps every 10 minutes until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	if err := s.loadClocks(); err != nil {
		fmt.Fprintf(s.opts.Warn, "[chainstate] warning: clock files not loaded: %v\n", err)
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil {
				fmt.Fprintf(s.opts.Warn, "[chainstate] warning: retention sweep: %v\n", err)
			}
		}
	}
}

// loadClocks reads every persisted clock (a new leader after failover).
func (s *Service) loadClocks() error {
	root := filepath.Join(s.opts.Dir, "clocks")
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		a, ok := actorFromKey(filepath.ToSlash(rel[:len(rel)-len(".json")]))
		if !ok {
			return nil
		}
		s.clockOf(a)
		return nil
	})
}

func actorFromKey(k string) (Actor, bool) {
	for i := 0; i < len(k); i++ {
		if k[i] == '/' {
			a := Actor{Atespace: k[:i], UID: k[i+1:]}
			return a, a.Validate() == nil
		}
	}
	return Actor{}, false
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
