// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"container/list"
	"crypto/sha256"
	"net/http"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// Inspect once (substrate-1 GAP-0244). A client writes its own history: the
// earlier turns of a request (an assistant turn, a user turn, a tool result,
// an instruction) are whatever it puts there, so the proxy cannot assume an
// earlier request carried them. It inspects every history segment (one
// string of the walker, walkTurns) this actor or session has not sent
// before, keyed by a hash of its text, in the same single inspection as the
// rest of the request. A segment the proxy has inspected keeps the verdict
// it had then and is not inspected again: a blocked prompt that the client
// keeps in its history does not block every later turn, and a long chat is
// not inspected again on every turn.
//
// The current scope of a request (system, developer and instructions text,
// tool definitions, the turns after the model's last one) is inspected on
// every request as before, so a refused request sent again is refused again.
//
// The record is bounded and fails safe: one LRU of segment hashes per actor
// or session (guardrail.history_seen_max, default
// config.DefaultHistorySeenMax), and at most historySeenMaxScopes actors or
// sessions (the least recently used one is dropped whole). A segment that is
// not in the record, evicted or never seen, is inspected; nothing is skipped
// on a miss.
//
// The record is kept per verified caller (historyScope): the verified Agent
// Substrate actor (its actor token), else a verified host caller (sandbox
// binding, verified subject or the gateway's own credential) and its
// session. A caller the gateway did not verify has no record: every segment
// of its history is inspected on every request.

// historySeenMaxScopes is the most actors or sessions the record keeps.
const historySeenMaxScopes = 256

type historyHash [16]byte

func historyHashOf(s string) historyHash {
	sum := sha256.Sum256([]byte(s))
	var h historyHash
	copy(h[:], sum[:len(h)])
	return h
}

// historyVerdict is the verdict a segment had when it was inspected.
type historyVerdict uint8

const (
	historyAllowed historyVerdict = iota
	historyAlerted
	historyBlocked
)

func historyVerdictOf(v *ScanVerdict) historyVerdict {
	switch {
	case v == nil || v.Action == "" || v.Action == "allow":
		return historyAllowed
	case v.Action == "block":
		return historyBlocked
	}
	return historyAlerted
}

type historyEntry struct {
	hash    historyHash
	verdict historyVerdict
}

// historyScopeSet is the LRU of one actor or session: front is the most
// recently used segment.
type historyScopeSet struct {
	key    string
	byHash map[historyHash]*list.Element // of *historyEntry
	order  list.List
}

// historySeen is the inspect-once record of a proxy. The zero value is
// ready to use.
type historySeen struct {
	mu     sync.Mutex
	scopes map[string]*list.Element // of *historyScopeSet
	order  list.List                // front is the most recently used scope
}

// fresh is the segments of segs the scope has not had inspected, each once,
// in order. A segment the scope has is moved to the front of its LRU. An
// empty scope (an unverified caller) has no record: every segment is fresh.
func (s *historySeen) fresh(scope string, segs []string) []string {
	if len(segs) == 0 {
		return nil
	}
	out := make([]string, 0, len(segs))
	dup := make(map[historyHash]bool, len(segs))
	s.mu.Lock()
	defer s.mu.Unlock()
	var set *historyScopeSet
	if e, ok := s.scopes[scope]; ok && scope != "" {
		set = e.Value.(*historyScopeSet)
		s.order.MoveToFront(e)
	}
	for _, seg := range segs {
		h := historyHashOf(seg)
		if dup[h] {
			continue
		}
		dup[h] = true
		if set != nil {
			if e, ok := set.byHash[h]; ok {
				set.order.MoveToFront(e)
				continue
			}
		}
		out = append(out, seg)
	}
	return out
}

// record notes that segs were inspected for scope with verdict v. A verdict
// the guardrail could not reach (a failed judge) records nothing, so those
// segments are inspected again. max is the per-scope cap (0: the default).
func (s *historySeen) record(scope string, segs []string, v *ScanVerdict, max int) {
	if scope == "" || len(segs) == 0 || v == nil || v.JudgeFailed {
		return
	}
	if max <= 0 {
		max = config.DefaultHistorySeenMax
	}
	verdict := historyVerdictOf(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scopes == nil {
		s.scopes = map[string]*list.Element{}
	}
	e, ok := s.scopes[scope]
	if ok {
		s.order.MoveToFront(e)
	} else {
		e = s.order.PushFront(&historyScopeSet{key: scope, byHash: map[historyHash]*list.Element{}})
		s.scopes[scope] = e
		for s.order.Len() > historySeenMaxScopes {
			old := s.order.Back()
			delete(s.scopes, old.Value.(*historyScopeSet).key)
			s.order.Remove(old)
		}
	}
	set := e.Value.(*historyScopeSet)
	for _, seg := range segs {
		h := historyHashOf(seg)
		if el, ok := set.byHash[h]; ok {
			if ent := el.Value.(*historyEntry); verdict > ent.verdict {
				ent.verdict = verdict
			}
			set.order.MoveToFront(el)
			continue
		}
		set.byHash[h] = set.order.PushFront(&historyEntry{hash: h, verdict: verdict})
	}
	for set.order.Len() > max {
		old := set.order.Back()
		delete(set.byHash, old.Value.(*historyEntry).hash)
		set.order.Remove(old)
	}
}

// historySeenMax is guardrail.history_seen_max (0: the default).
func (p *GuardrailProxy) historySeenMax() int {
	if p.cfg != nil {
		return p.cfg.HistorySeenMax
	}
	return 0
}

// historyScope is the key of the inspect-once record of r's caller: the
// verified Substrate actor; else a verified host caller and the session it
// names; "" for a caller the gateway did not verify (no record).
func (p *GuardrailProxy) historyScope(r *http.Request) string {
	ctx := r.Context()
	if actor, ok := substrateActorFrom(ctx); ok {
		return "actor\x00" + actor.RegistrationKey
	}
	caller := ""
	if b, ok := sandboxauth.FromContext(ctx); ok && b.ID != "" {
		caller = "sandbox\x00" + b.ID
	} else if subject, ok := verifiedSubjectFromContext(ctx); ok && subject.UserID != "" {
		caller = "subject\x00" + subject.UserID
	} else if p.presentsOwnerCredential(r) {
		caller = "owner"
	}
	if caller == "" {
		return ""
	}
	session := firstNonEmpty(SessionIDFromContext(ctx), r.Header.Get("X-Conversation-ID"))
	return "host\x00" + p.connectorName() + "\x00" + caller + "\x00" + session
}

// promptSegments is the current scope of a request followed by the history
// it inspects (fresh), as one list for joinPromptSegments and record.
func promptSegments(current, fresh []string) []string {
	out := make([]string, 0, len(current)+len(fresh))
	return append(append(out, current...), fresh...)
}
