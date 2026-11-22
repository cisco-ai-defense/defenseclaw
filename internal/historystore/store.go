// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package historystore keeps the guardrail proxy's inspect-once record
// (substrate-1 GAP-0244, GAP-0254): per scope (a verified caller, its
// session and what decides a verdict), the hash of every history segment the
// proxy inspected and what became of its request. The proxy reads and writes
// it through Store. A gateway on one machine uses the process-local Process
// (the default); a gateway with several replicas (Agent Substrate) puts the
// leader's store behind the same interface, so a turn refused on one replica
// is known as refused on every other one (GAP-0266).
//
// Only hashes, verdicts and rule identifiers are kept: never content.
package historystore

import (
	"container/list"
	"context"
	"sync"
)

// Hash is the truncated SHA-256 of a segment's text.
type Hash [16]byte

// Verdict is what became of a segment's request when it was inspected. A
// higher verdict wins over a lower one.
type Verdict uint8

const (
	Allowed Verdict = iota
	Alerted
	Refused
)

// Entry is a segment's record: its verdict and, for a refusal, the rule.
type Entry struct {
	Verdict Verdict
	Rule    string
}

// Store keeps the record of each scope. caller is the verified caller the
// scope belongs to (the per-caller bound counts its scopes).
type Store interface {
	// Seen returns the entries scope holds for hashes (a hash it does not
	// hold is absent) and marks them recently used.
	Seen(ctx context.Context, scope string, hashes []Hash) (map[Hash]Entry, error)
	// Record notes hashes under scope with e; an entry keeps the higher of
	// its verdict and e's. max is the most hashes the scope keeps (the least
	// recently used go first).
	Record(ctx context.Context, caller, scope string, hashes []Hash, e Entry, max int) error
}

// MaxScopes is the most scopes a Process keeps in all, and
// MaxScopesPerCaller the most one caller keeps: a caller that rotates
// sessions drops its own oldest record, not another caller's.
const (
	MaxScopes          = 256
	MaxScopesPerCaller = 32
)

type entry struct {
	hash Hash
	Entry
}

// scopeSet is the LRU of one scope: front is the most recently used hash.
type scopeSet struct {
	key    string
	caller string
	byHash map[Hash]*list.Element // of *entry
	order  list.List
}

// Process is the process-local Store: bounded, lost on restart. The zero
// value is ready to use.
type Process struct {
	mu        sync.Mutex
	scopes    map[string]*list.Element // of *scopeSet
	order     list.List                // front is the most recently used scope
	perCaller map[string]int
}

var _ Store = (*Process)(nil)

// Seen implements Store.
func (p *Process) Seen(_ context.Context, scope string, hashes []Hash) (map[Hash]Entry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.scopes[scope]
	if !ok {
		return nil, nil
	}
	p.order.MoveToFront(e)
	set := e.Value.(*scopeSet)
	var out map[Hash]Entry
	for _, h := range hashes {
		if el, ok := set.byHash[h]; ok {
			set.order.MoveToFront(el)
			if out == nil {
				out = map[Hash]Entry{}
			}
			out[h] = el.Value.(*entry).Entry
		}
	}
	return out, nil
}

// Record implements Store.
func (p *Process) Record(_ context.Context, caller, scope string, hashes []Hash, rec Entry, max int) error {
	if len(hashes) == 0 || max <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scopes == nil {
		p.scopes = map[string]*list.Element{}
		p.perCaller = map[string]int{}
	}
	e, ok := p.scopes[scope]
	if ok {
		p.order.MoveToFront(e)
	} else {
		if p.perCaller[caller] >= MaxScopesPerCaller {
			for old := p.order.Back(); old != nil; old = old.Prev() {
				if old.Value.(*scopeSet).caller == caller {
					p.dropLocked(old)
					break
				}
			}
		}
		e = p.order.PushFront(&scopeSet{key: scope, caller: caller, byHash: map[Hash]*list.Element{}})
		p.scopes[scope] = e
		p.perCaller[caller]++
		for p.order.Len() > MaxScopes {
			p.dropLocked(p.order.Back())
		}
	}
	set := e.Value.(*scopeSet)
	for _, h := range hashes {
		if el, ok := set.byHash[h]; ok {
			if ent := el.Value.(*entry); rec.Verdict > ent.Verdict {
				ent.Entry = rec
			}
			set.order.MoveToFront(el)
			continue
		}
		set.byHash[h] = set.order.PushFront(&entry{hash: h, Entry: rec})
	}
	for set.order.Len() > max {
		old := set.order.Back()
		delete(set.byHash, old.Value.(*entry).hash)
		set.order.Remove(old)
	}
	return nil
}

func (p *Process) dropLocked(e *list.Element) {
	set := e.Value.(*scopeSet)
	delete(p.scopes, set.key)
	if p.perCaller[set.caller]--; p.perCaller[set.caller] <= 0 {
		delete(p.perCaller, set.caller)
	}
	p.order.Remove(e)
}

// Stats reports how many scopes the store keeps, how many hashes scope
// holds and how many scopes caller holds (tests and diagnostics).
func (p *Process) Stats(scope, caller string) (scopes, hashes, callerScopes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.scopes[scope]; ok {
		hashes = e.Value.(*scopeSet).order.Len()
	}
	return len(p.scopes), hashes, p.perCaller[caller]
}
