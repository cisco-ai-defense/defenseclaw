// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/historystore"
)

// The guardrail proxy's inspect-once record on the leader (substrate-1
// GAP-0266): every gateway replica reads and writes an actor's record here,
// so a turn refused on one replica is known as refused on the others and the
// session is not locked by where its next request lands. Like the intent
// store, the record is kept per verified actor (never a request claim), in
// memory, bounded (historystore.MaxScopesPerCaller scopes of at most
// historyMaxPerScope hashes per actor), and lost on a leader restart: a
// record that is gone only means the history is inspected once more. Only
// segment hashes, verdicts and rule identifiers cross the wire.

// Leader methods of the inspect-once record.
const (
	MethodHistorySeen   = "HistorySeen"
	MethodHistoryRecord = "HistoryRecord"
)

// Bounds of one record request and of an actor's record.
const (
	historyMaxHashes   = 4096
	historyMaxScope    = 1024
	historyMaxRule     = 64
	historyMaxPerScope = 8192
)

// HistoryRequest is the HistorySeen and HistoryRecord body: a scope of the
// actor's record and segment hashes (hex); Verdict, Rule and Max for a
// record.
type HistoryRequest struct {
	Actor   Actor    `json:"actor"`
	Scope   string   `json:"scope"`
	Hashes  []string `json:"hashes"`
	Verdict uint8    `json:"verdict,omitempty"`
	Rule    string   `json:"rule,omitempty"`
	Max     int      `json:"max,omitempty"`
}

// HistoryKnown is one hash the scope holds.
type HistoryKnown struct {
	Hash    string `json:"hash"`
	Verdict uint8  `json:"verdict"`
	Rule    string `json:"rule,omitempty"`
}

// HistoryResponse is HistorySeen's answer.
type HistoryResponse struct {
	Known []HistoryKnown `json:"known,omitempty"`
}

func historyHashes(in []string) ([]historystore.Hash, error) {
	if len(in) > historyMaxHashes {
		return nil, fmt.Errorf("chainstate: more than %d history hashes", historyMaxHashes)
	}
	out := make([]historystore.Hash, 0, len(in))
	for _, s := range in {
		var h historystore.Hash
		if len(s) != 2*len(h) {
			return nil, errors.New("chainstate: a history hash is not 32 hex digits")
		}
		if _, err := hex.Decode(h[:], []byte(s)); err != nil {
			return nil, errors.New("chainstate: a history hash is not 32 hex digits")
		}
		out = append(out, h)
	}
	return out, nil
}

func (in HistoryRequest) check() ([]historystore.Hash, error) {
	if in.Scope == "" || len(in.Scope) > historyMaxScope {
		return nil, fmt.Errorf("chainstate: a history scope has 1 to %d bytes", historyMaxScope)
	}
	if len(in.Rule) > historyMaxRule {
		return nil, fmt.Errorf("chainstate: a history rule has at most %d bytes", historyMaxRule)
	}
	if in.Verdict > uint8(historystore.Refused) {
		return nil, errors.New("chainstate: unknown history verdict")
	}
	return historyHashes(in.Hashes)
}

func (s *Service) history(e *actorEntry) *historystore.Process {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.history == nil {
		e.history = &historystore.Process{}
	}
	return e.history
}

// HistorySeen serves HistorySeen.
func (s *Service) HistorySeen(ctx context.Context, in HistoryRequest) (HistoryResponse, error) {
	hashes, err := in.check()
	if err != nil {
		return HistoryResponse{}, bad(err)
	}
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return HistoryResponse{}, err
	}
	defer release()
	known, err := s.history(e).Seen(ctx, in.Scope, hashes)
	if err != nil {
		return HistoryResponse{}, err
	}
	var out HistoryResponse
	for h, ent := range known {
		out.Known = append(out.Known, HistoryKnown{Hash: hex.EncodeToString(h[:]), Verdict: uint8(ent.Verdict), Rule: ent.Rule})
	}
	return out, nil
}

// HistoryRecord serves HistoryRecord. Every scope of an actor counts as the
// actor's own (historystore.MaxScopesPerCaller).
func (s *Service) HistoryRecord(ctx context.Context, in HistoryRequest) (struct{}, error) {
	hashes, err := in.check()
	if err != nil {
		return struct{}{}, bad(err)
	}
	max := in.Max
	if max <= 0 || max > historyMaxPerScope {
		return struct{}{}, bad(fmt.Errorf("chainstate: a history scope keeps 1 to %d hashes", historyMaxPerScope))
	}
	e, release, err := s.acquire(in.Actor)
	if err != nil {
		return struct{}{}, err
	}
	defer release()
	return struct{}{}, s.history(e).Record(ctx, "actor", in.Scope, hashes,
		historystore.Entry{Verdict: historystore.Verdict(in.Verdict), Rule: in.Rule}, max)
}

// historyCallTimeout bounds one leader call of the record: the record is on
// the hot path of every model call, and a leader that does not answer (a
// leader change takes about 30 s) only means the history is inspected in
// full meanwhile (the proxy reads a failed store as empty).
const historyCallTimeout = 2 * time.Second

// HistoryStore is historystore.Store on the leader for verified actors'
// calls; the calls of anything else use Fallback (a process-local store).
type HistoryStore struct {
	Client *Client
	// ActorOf returns the verified actor of a call.
	ActorOf  func(ctx context.Context) (Actor, bool)
	Fallback historystore.Store
}

var _ historystore.Store = (*HistoryStore)(nil)

func (s *HistoryStore) target(ctx context.Context) (Actor, historystore.Store, error) {
	if s.ActorOf != nil {
		if a, ok := s.ActorOf(ctx); ok {
			return a, nil, nil
		}
	}
	if s.Fallback == nil {
		return Actor{}, nil, errors.New("chainstate: no history store for a call that is not an actor's")
	}
	return Actor{}, s.Fallback, nil
}

func (s *HistoryStore) call(ctx context.Context, method string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, historyCallTimeout)
	defer cancel()
	return s.Client.call(ctx, method, in, out)
}

func hexHashes(hashes []historystore.Hash) []string {
	out := make([]string, len(hashes))
	for i, h := range hashes {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}

// Seen implements historystore.Store.
func (s *HistoryStore) Seen(ctx context.Context, scope string, hashes []historystore.Hash) (map[historystore.Hash]historystore.Entry, error) {
	a, local, err := s.target(ctx)
	if err != nil {
		return nil, err
	}
	if local != nil {
		return local.Seen(ctx, scope, hashes)
	}
	var out map[historystore.Hash]historystore.Entry
	for len(hashes) > 0 {
		n := min(len(hashes), historyMaxHashes)
		var resp HistoryResponse
		if err := s.call(ctx, MethodHistorySeen, HistoryRequest{Actor: a, Scope: scope, Hashes: hexHashes(hashes[:n])}, &resp); err != nil {
			return nil, err
		}
		for _, k := range resp.Known {
			h, err := historyHashes([]string{k.Hash})
			if err != nil || k.Verdict > uint8(historystore.Refused) {
				return nil, errors.New("chainstate: the leader answered a malformed history entry")
			}
			if out == nil {
				out = map[historystore.Hash]historystore.Entry{}
			}
			out[h[0]] = historystore.Entry{Verdict: historystore.Verdict(k.Verdict), Rule: k.Rule}
		}
		hashes = hashes[n:]
	}
	return out, nil
}

// Record implements historystore.Store.
func (s *HistoryStore) Record(ctx context.Context, caller, scope string, hashes []historystore.Hash, e historystore.Entry, max int) error {
	a, local, err := s.target(ctx)
	if err != nil {
		return err
	}
	if local != nil {
		return local.Record(ctx, caller, scope, hashes, e, max)
	}
	if len(hashes) == 0 || max <= 0 {
		return nil
	}
	if max > historyMaxPerScope {
		max = historyMaxPerScope
	}
	for len(hashes) > 0 {
		n := min(len(hashes), historyMaxHashes)
		if err := s.call(ctx, MethodHistoryRecord, HistoryRequest{Actor: a, Scope: scope, Hashes: hexHashes(hashes[:n]),
			Verdict: uint8(e.Verdict), Rule: e.Rule, Max: max}, nil); err != nil {
			return err
		}
		hashes = hashes[n:]
	}
	return nil
}
