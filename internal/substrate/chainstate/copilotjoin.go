// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/copilotjoin"
)

// The Copilot permission join on the leader (substrate-1 GAP-0269): an
// argumentless native Copilot permissionRequest callback is bound to the
// calls of the actor's last allowed preToolUse, which can have landed on
// another gateway replica. The leader keeps that join state per verified
// actor (never a request claim), in memory, for copilotjoin.TTL; a state
// that is gone only means the callback keeps its own unparsed decision.

// Leader methods of the Copilot permission join.
const (
	MethodCopilotJoinRecord = "CopilotJoinRecord"
	MethodCopilotJoinTake   = "CopilotJoinTake"
)

// Bounds of one join request.
const (
	copilotJoinMaxScope = 4096
	copilotJoinMaxTool  = 256
	copilotJoinMaxCalls = 64
	copilotJoinMaxArgs  = 256 << 10
)

// CopilotJoinCall is one call of a preToolUse.
type CopilotJoinCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

// CopilotJoinRequest is the CopilotJoinRecord and CopilotJoinTake body.
type CopilotJoinRequest struct {
	Actor    Actor             `json:"actor"`
	Scope    string            `json:"scope"`
	Tool     string            `json:"tool,omitempty"`
	Readable bool              `json:"readable,omitempty"`
	Allowed  bool              `json:"allowed,omitempty"`
	Calls    []CopilotJoinCall `json:"calls,omitempty"`
}

// CopilotJoinResponse is CopilotJoinTake's answer.
type CopilotJoinResponse struct {
	Found     bool              `json:"found,omitempty"`
	Ambiguous bool              `json:"ambiguous,omitempty"`
	Calls     []CopilotJoinCall `json:"calls,omitempty"`
}

func (in CopilotJoinRequest) check() error {
	if in.Scope == "" || len(in.Scope) > copilotJoinMaxScope {
		return fmt.Errorf("chainstate: a Copilot join scope has 1 to %d bytes", copilotJoinMaxScope)
	}
	if len(in.Tool) > copilotJoinMaxTool {
		return fmt.Errorf("chainstate: a Copilot join tool has at most %d bytes", copilotJoinMaxTool)
	}
	if len(in.Calls) > copilotJoinMaxCalls {
		return fmt.Errorf("chainstate: a Copilot join records at most %d calls", copilotJoinMaxCalls)
	}
	for _, c := range in.Calls {
		if len(c.Name) > copilotJoinMaxTool || len(c.Args) > copilotJoinMaxArgs {
			return errors.New("chainstate: a Copilot join call is too large")
		}
	}
	return nil
}

func toJoinCalls(in []copilotargs.NativeCall) []CopilotJoinCall {
	out := make([]CopilotJoinCall, 0, len(in))
	for _, c := range in {
		out = append(out, CopilotJoinCall{Name: c.Name, Args: c.Args})
	}
	return out
}

func fromJoinCalls(in []CopilotJoinCall) []copilotargs.NativeCall {
	out := make([]copilotargs.NativeCall, 0, len(in))
	for _, c := range in {
		out = append(out, copilotargs.NativeCall{Name: c.Name, Args: c.Args})
	}
	return out
}

func (s *Service) copilotJoin(e *actorEntry) *copilotjoin.Process {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.copilot == nil {
		e.copilot = &copilotjoin.Process{Now: s.opts.Now}
	}
	return e.copilot
}

// CopilotJoinRecord serves CopilotJoinRecord.
func (s *Service) CopilotJoinRecord(ctx context.Context, in CopilotJoinRequest) (struct{}, error) {
	if err := in.check(); err != nil {
		return struct{}{}, bad(err)
	}
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return struct{}{}, err
	}
	defer release()
	return struct{}{}, s.copilotJoin(e).Record(ctx, in.Scope, in.Readable, in.Allowed, fromJoinCalls(in.Calls))
}

// CopilotJoinTake serves CopilotJoinTake. It changes the state (a callback
// consumes what it takes), so a retry of the same request gets the answer
// the first one got.
func (s *Service) CopilotJoinTake(ctx context.Context, in CopilotJoinRequest) (CopilotJoinResponse, error) {
	if err := in.check(); err != nil {
		return CopilotJoinResponse{}, bad(err)
	}
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return CopilotJoinResponse{}, err
	}
	defer release()
	entry, found, err := s.copilotJoin(e).Take(ctx, in.Scope, in.Tool)
	if err != nil || !found {
		return CopilotJoinResponse{}, err
	}
	return CopilotJoinResponse{Found: true, Ambiguous: entry.Ambiguous, Calls: toJoinCalls(entry.Calls)}, nil
}

// CopilotJoinStore is copilotjoin.Store on the leader for a verified actor's
// calls. The gateway uses it only for those; a call without an actor is an
// error here, never another actor's state.
type CopilotJoinStore struct {
	Client  *Client
	ActorOf func(ctx context.Context) (Actor, bool)
}

var _ copilotjoin.Store = (*CopilotJoinStore)(nil)

func (s *CopilotJoinStore) actor(ctx context.Context) (Actor, error) {
	if s == nil || s.ActorOf == nil {
		return Actor{}, errors.New("chainstate: no Copilot join store")
	}
	a, ok := s.ActorOf(ctx)
	if !ok {
		return Actor{}, errors.New("chainstate: the Copilot join on the leader is only for a verified actor's call")
	}
	return a, nil
}

// Record implements copilotjoin.Store.
func (s *CopilotJoinStore) Record(ctx context.Context, scope string, readable, allowed bool, calls []copilotargs.NativeCall) error {
	a, err := s.actor(ctx)
	if err != nil {
		return err
	}
	return s.Client.call(ctx, MethodCopilotJoinRecord, CopilotJoinRequest{Actor: a, Scope: scope,
		Readable: readable, Allowed: allowed, Calls: toJoinCalls(calls)}, nil)
}

// Take implements copilotjoin.Store.
func (s *CopilotJoinStore) Take(ctx context.Context, scope, tool string) (copilotjoin.Entry, bool, error) {
	a, err := s.actor(ctx)
	if err != nil {
		return copilotjoin.Entry{}, false, err
	}
	var out CopilotJoinResponse
	if err := s.Client.call(ctx, MethodCopilotJoinTake, CopilotJoinRequest{Actor: a, Scope: scope, Tool: tool}, &out); err != nil {
		return copilotjoin.Entry{}, false, err
	}
	if !out.Found {
		return copilotjoin.Entry{}, false, nil
	}
	return copilotjoin.Entry{Ambiguous: out.Ambiguous, Calls: fromJoinCalls(out.Calls)}, true, nil
}
