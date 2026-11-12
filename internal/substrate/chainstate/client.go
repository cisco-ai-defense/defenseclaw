// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Client is the gateway replicas', the callout's and the controller's side
// of the leader's chain state.
type Client struct {
	Leader *leader.Client
}

func (c *Client) call(ctx context.Context, method string, in, out any) error {
	if c == nil || c.Leader == nil {
		return errors.New("chainstate: no leader client")
	}
	return c.Leader.Call(ctx, method, leader.NewRequestID(), in, out)
}

// Binding is one hook call's view of one window scope of a verified actor.
// It has the repository's method set, so the hook chain stage uses it where
// a host uses *audit.ToolChainRepository. ConnectorInstanceID fields of the
// inputs are ignored: the leader names the actor's instance itself.
type Binding struct {
	client    *Client
	actor     Actor
	scope     Scope
	session   string
	eventName string
	received  time.Time
}

// Bind returns the binding of one hook call: the actor, the scope, the
// connector and session id (a claim that only ever selects a window of this
// actor), the hook event name and the gateway's receive time.
func (c *Client) Bind(actor Actor, scope Scope, connector, sessionID, eventName string, received time.Time) (*Binding, error) {
	if err := actor.Validate(); err != nil {
		return nil, err
	}
	if scope != ScopeSession && scope != ScopeActor {
		return nil, errors.New("chainstate: scope is session or actor")
	}
	if sessionID == "" {
		// One window for the calls of a connector that names no session.
		sessionID = "-"
	}
	session, err := audit.ToolChainSubstrateSessionDigest(connector, sessionID)
	if err != nil {
		return nil, err
	}
	if received.IsZero() {
		received = time.Now()
	}
	return &Binding{client: c, actor: actor, scope: scope, session: session, eventName: eventName, received: received}, nil
}

// Scope reports the binding's scope as a repository would.
func (b *Binding) Scope() audit.ToolChainScope {
	if b.scope == ScopeActor {
		return audit.ToolChainScopeRoot
	}
	return audit.ToolChainScopeSession
}

func (b *Binding) op(ctx context.Context, op Op, semantic audit.SemanticEventID, fingerprint string, in, out any) error {
	raw, err := encodeGob(in)
	if err != nil {
		return err
	}
	req := ObserveRequest{Actor: b.actor, Scope: b.scope, Op: op, Input: raw}
	if op != OpAttach {
		req.Join = &Join{SemanticEventID: string(semantic), EventName: b.eventName, InputFingerprint: fingerprint,
			ReceivedUnixNano: b.received.UnixNano(), SessionDigest: b.session}
	}
	var resp ObserveResponse
	if err := b.client.call(ctx, leader.MethodChainObserve, req, &resp); err != nil {
		return err
	}
	return decodeGob(resp.Result, out)
}

// Observe is ToolChainRepository.Observe on the leader.
func (b *Binding) Observe(ctx context.Context, in audit.ToolChainObserveInput) (audit.ToolChainObserveResult, error) {
	var out audit.ToolChainObserveResult
	err := b.op(ctx, OpObserve, in.SemanticEventID, in.InputFingerprint, in, &out)
	return out, err
}

// ResolvePending is ToolChainRepository.ResolvePending on the leader.
func (b *Binding) ResolvePending(ctx context.Context, in audit.ToolChainResolvePendingInput) (audit.ToolChainResolvePendingResult, error) {
	var out audit.ToolChainResolvePendingResult
	err := b.op(ctx, OpResolve, in.TerminalSemanticEventID, in.TerminalInputFingerprint, in, &out)
	return out, err
}

// PreparePending is ToolChainRepository.PreparePending on the leader.
func (b *Binding) PreparePending(ctx context.Context, in audit.ToolChainPreparePendingInput) (audit.ToolChainPreparePendingResult, error) {
	var out audit.ToolChainPreparePendingResult
	err := b.op(ctx, OpPrepare, in.PreSemanticEventID, in.PreInputFingerprint, in, &out)
	return out, err
}

// DiscardPendingForEventSession is the repository method on the leader.
func (b *Binding) DiscardPendingForEventSession(ctx context.Context, in audit.ToolChainDiscardPendingForEventSessionInput) (audit.ToolChainDiscardPendingForEventSessionResult, error) {
	var out audit.ToolChainDiscardPendingForEventSessionResult
	err := b.op(ctx, OpDiscard, in.TerminalSemanticEventID, in.TerminalInputFingerprint, in, &out)
	return out, err
}

// ResetForTerminalEventSession is the repository method on the leader.
func (b *Binding) ResetForTerminalEventSession(ctx context.Context, in audit.ToolChainResetForTerminalEventSessionInput) (audit.ToolChainResetForTerminalEventSessionResult, error) {
	var out audit.ToolChainResetForTerminalEventSessionResult
	err := b.op(ctx, OpReset, in.TerminalSemanticEventID, in.TerminalInputFingerprint, in, &out)
	return out, err
}

// AttachFinalization is the repository method on the leader.
func (b *Binding) AttachFinalization(ctx context.Context, receiptIDs []string, evaluationID, auditEventID string) error {
	var out AttachResult
	return b.op(ctx, OpAttach, "", "", AttachInput{ReceiptIDs: receiptIDs, EvaluationID: evaluationID, AuditEventID: auditEventID}, &out)
}

// Lifecycle sends one controller lifecycle event.
func (c *Client) Lifecycle(ctx context.Context, ev LifecycleEvent) (LifecycleResult, error) {
	var out LifecycleResult
	err := c.call(ctx, MethodChainLifecycle, ev, &out)
	return out, err
}

// PutTask registers the --task text of an actor (the launcher, at create).
func (c *Client) PutTask(ctx context.Context, actor Actor, text string) error {
	return c.call(ctx, leader.MethodIntentPut, IntentRequest{Actor: actor, Op: IntentTask, Text: text}, nil)
}

// CheckEgress records one observed egress step in the actor window and
// reports an egress chain it completes.
func (c *Client) CheckEgress(ctx context.Context, in EgressRequest) (EgressVerdict, error) {
	var out EgressVerdict
	err := c.call(ctx, MethodChainEgress, in, &out)
	return out, err
}

// IntentStore is intentstore.Store on the leader for verified actors' calls;
// calls of anything else use Fallback (the process-local store).
type IntentStore struct {
	Client *Client
	// Namespace separates the contexts of judges with different roles.
	Namespace string
	// ActorOf returns the verified actor of a call.
	ActorOf  func(ctx context.Context) (Actor, bool)
	Fallback intentstore.Store
}

// key is the leader's key of a judge's session key.
func (s *IntentStore) key(key string) string {
	if s.Namespace == "" {
		return key
	}
	return s.Namespace + "\x00" + key
}

var _ intentstore.Store = (*IntentStore)(nil)

func (s *IntentStore) actor(ctx context.Context) (Actor, bool) {
	if s == nil || s.ActorOf == nil {
		return Actor{}, false
	}
	return s.ActorOf(ctx)
}

func (s *IntentStore) fallback() (intentstore.Store, error) {
	if s.Fallback == nil {
		return nil, errors.New("chainstate: no intent store for a call that is not an actor's")
	}
	return s.Fallback, nil
}

// ObservePrompt implements intentstore.Store.
func (s *IntentStore) ObservePrompt(ctx context.Context, key, intent string) error {
	a, ok := s.actor(ctx)
	if !ok {
		f, err := s.fallback()
		if err != nil {
			return err
		}
		return f.ObservePrompt(ctx, key, intent)
	}
	return s.Client.call(ctx, leader.MethodIntentPut, IntentRequest{Actor: a, Op: IntentPrompt, Key: s.key(key), Text: intent}, nil)
}

// AppendToolCall implements intentstore.Store.
func (s *IntentStore) AppendToolCall(ctx context.Context, key string, call intentstore.ToolCall) (intentstore.Snapshot, error) {
	a, ok := s.actor(ctx)
	if !ok {
		f, err := s.fallback()
		if err != nil {
			return intentstore.Snapshot{}, err
		}
		return f.AppendToolCall(ctx, key, call)
	}
	var out IntentResponse
	if err := s.Client.call(ctx, leader.MethodIntentPut, IntentRequest{Actor: a, Op: IntentAppend, Key: s.key(key),
		Tool: call.Tool, Args: call.Args}, &out); err != nil {
		return intentstore.Snapshot{}, err
	}
	snap := intentstore.Snapshot{UserIntent: out.UserIntent}
	for _, p := range out.Prior {
		snap.Prior = append(snap.Prior, intentstore.ToolCall{Tool: p.Tool, Args: p.Args})
	}
	return snap, nil
}

// Reset implements intentstore.Store. An actor's reset needs the actor in
// ctx; a reset without it goes to the fallback (an actor's session that
// starts over still begins a new context with its next prompt).
func (s *IntentStore) Reset(ctx context.Context, key string) error {
	a, ok := s.actor(ctx)
	if !ok {
		f, err := s.fallback()
		if err != nil {
			return err
		}
		return f.Reset(ctx, key)
	}
	return s.Client.call(ctx, leader.MethodIntentPut, IntentRequest{Actor: a, Op: IntentReset, Key: s.key(key)}, nil)
}
