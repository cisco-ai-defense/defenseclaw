// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// Inspect once (substrate-1 GAP-0244). A client writes its own history: the
// earlier turns of a request (an assistant turn, a user turn, a tool result,
// an instruction) are whatever it puts there, so the proxy cannot assume an
// earlier request carried them. It inspects every history segment (one
// string of the walker, walkTurns) this caller has not sent before, keyed by
// a hash of its text, in the same single inspection as the rest of the
// request. A segment the proxy has inspected keeps the verdict it had then
// and is not inspected again, so a long chat is not inspected again on every
// turn.
//
// A segment of a request the proxy refused never reaches the upstream later
// (GAP-0254): when the client sends it back as history, the proxy replaces
// its text with historyRedactedText (the turn and the role order stay, the
// refused text goes) and writes an audit row per redaction, without content.
// So a refused prompt does not block the later turns, and it is not
// forwarded either. A body the proxy cannot rewrite (a signed Bedrock body)
// is refused while it carries the refused turn. In observe mode nothing is
// refused, so nothing is redacted.
//
// The current scope of a request (system, developer and instructions text,
// tool definitions, the turns after the model's last one) is inspected on
// every request as before, so a refused request sent again is refused again.
//
// Only a verdict the guardrail reached is recorded (GAP-0255): an inspection
// in which a stage failed open (AI Defense unreachable or unwired, a failed
// judge, a recovered panic) records nothing it allowed.
//
// The record is kept per verified caller and per what decides a verdict
// (historyScope, GAP-0256): the verified Agent Substrate actor (its actor
// token), else a verified host caller (sandbox binding, verified subject or
// the gateway's own credential) and its session; and the mode, the
// guardrail profile and the policy generation. A change of any of them
// starts a new record, so the history is inspected once more under the new
// rules. A caller the gateway did not verify has no record: every segment of
// its history is inspected on every request.
//
// The record is bounded and fails safe: one LRU of segment hashes per scope
// (guardrail.history_seen_max, default config.DefaultHistorySeenMax), at most
// historySeenMaxScopesPerCaller scopes per caller and historySeenMaxScopes in
// all (the least recently used scope is dropped whole). A segment that is
// not in the record, evicted or never seen, is inspected; nothing is skipped
// on a miss. An evicted refused segment is inspected again and refused again.

// historySeenMaxScopes is the most scopes the record keeps in all, and
// historySeenMaxScopesPerCaller the most one caller keeps: a caller that
// rotates sessions drops its own oldest record, not another caller's.
const (
	historySeenMaxScopes          = 256
	historySeenMaxScopesPerCaller = 32
)

// historyRedactedText replaces the text of a refused turn the client sends
// back. It does not start with the block banner, so laundering keeps it.
const historyRedactedText = "(Removed by DefenseClaw policy: this turn was refused when it was sent, and its text is not forwarded.)"

// historyRefusedFinding is the finding of a request refused because it
// carries a refused turn the proxy cannot remove.
const historyRefusedFinding = "PROXY-HISTORY-REFUSED-TURN"

type historyHash [16]byte

func historyHashOf(s string) historyHash {
	sum := sha256.Sum256([]byte(s))
	var h historyHash
	copy(h[:], sum[:len(h)])
	return h
}

// historyVerdict is what became of a segment's request when it was
// inspected.
type historyVerdict uint8

const (
	historyAllowed historyVerdict = iota
	historyAlerted
	historyRefused
)

type historyEntry struct {
	hash    historyHash
	verdict historyVerdict
	rule    string // the rule that refused it (historyRefused only)
}

// historyScopeSet is the LRU of one scope: front is the most recently used
// segment.
type historyScopeSet struct {
	key    string
	caller string
	byHash map[historyHash]*list.Element // of *historyEntry
	order  list.List
}

// historySeen is the inspect-once record of a proxy. The zero value is
// ready to use.
type historySeen struct {
	mu        sync.Mutex
	scopes    map[string]*list.Element // of *historyScopeSet
	order     list.List                // front is the most recently used scope
	perCaller map[string]int
}

// historyRefusal is a history segment whose request was refused, and the
// rule that refused it.
type historyRefusal struct {
	text string
	rule string
}

// fresh splits the history segments of a request: the ones the scope has not
// had inspected (fresh, each once, in order) and the ones whose request was
// refused (refused, by hash). A segment the scope has is moved to the front
// of its LRU. An empty scope (an unverified caller) has no record: every
// segment is fresh.
func (s *historySeen) fresh(scope string, segs []string) (fresh []string, refused map[historyHash]historyRefusal) {
	if len(segs) == 0 {
		return nil, nil
	}
	fresh = make([]string, 0, len(segs))
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
				if ent := e.Value.(*historyEntry); ent.verdict == historyRefused {
					if refused == nil {
						refused = map[historyHash]historyRefusal{}
					}
					refused[h] = historyRefusal{text: seg, rule: ent.rule}
				}
				continue
			}
		}
		fresh = append(fresh, seg)
	}
	return fresh, refused
}

// historyRule names the rule of a refusal for its audit row: an identifier,
// never content.
func historyRule(v *ScanVerdict) string {
	rule := ""
	switch {
	case v == nil:
	case len(v.RuleIDs) > 0:
		rule = v.RuleIDs[0]
	case len(v.Findings) > 0:
		rule, _, _ = strings.Cut(v.Findings[0], ":")
	default:
		rule = v.Scanner
	}
	rule = strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return -1
		}
		return r
	}, rule)
	if len(rule) > 64 {
		rule = rule[:64]
	}
	if rule == "" {
		rule = "guardrail"
	}
	return rule
}

// record notes that segs were inspected for scope (of caller) with verdict
// v; refused is whether the request was refused. An allowed or alerted
// verdict of a degraded inspection (a stage failed open, or the judge
// failed) records nothing, so those segments are inspected again; a refusal
// is recorded whatever stage decided it. max is the per-scope cap (0: the
// default).
func (s *historySeen) record(caller, scope string, segs []string, v *ScanVerdict, refused, degraded bool, max int) {
	if scope == "" || len(segs) == 0 || v == nil {
		return
	}
	if !refused && (degraded || v.JudgeFailed) {
		return
	}
	if max <= 0 {
		max = config.DefaultHistorySeenMax
	}
	verdict, rule := historyAllowed, ""
	switch {
	case refused:
		verdict, rule = historyRefused, historyRule(v)
	case v.Action != "" && v.Action != "allow":
		verdict = historyAlerted
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scopes == nil {
		s.scopes = map[string]*list.Element{}
		s.perCaller = map[string]int{}
	}
	e, ok := s.scopes[scope]
	if ok {
		s.order.MoveToFront(e)
	} else {
		if s.perCaller[caller] >= historySeenMaxScopesPerCaller {
			for old := s.order.Back(); old != nil; old = old.Prev() {
				if old.Value.(*historyScopeSet).caller == caller {
					s.dropLocked(old)
					break
				}
			}
		}
		e = s.order.PushFront(&historyScopeSet{key: scope, caller: caller, byHash: map[historyHash]*list.Element{}})
		s.scopes[scope] = e
		s.perCaller[caller]++
		for s.order.Len() > historySeenMaxScopes {
			s.dropLocked(s.order.Back())
		}
	}
	set := e.Value.(*historyScopeSet)
	for _, seg := range segs {
		h := historyHashOf(seg)
		if el, ok := set.byHash[h]; ok {
			if ent := el.Value.(*historyEntry); verdict > ent.verdict {
				ent.verdict, ent.rule = verdict, rule
			}
			set.order.MoveToFront(el)
			continue
		}
		set.byHash[h] = set.order.PushFront(&historyEntry{hash: h, verdict: verdict, rule: rule})
	}
	for set.order.Len() > max {
		old := set.order.Back()
		delete(set.byHash, old.Value.(*historyEntry).hash)
		set.order.Remove(old)
	}
}

func (s *historySeen) dropLocked(e *list.Element) {
	set := e.Value.(*historyScopeSet)
	delete(s.scopes, set.key)
	if s.perCaller[set.caller]--; s.perCaller[set.caller] <= 0 {
		delete(s.perCaller, set.caller)
	}
	s.order.Remove(e)
}

// historySeenMax is guardrail.history_seen_max (0: the default).
func (p *GuardrailProxy) historySeenMax() int {
	if p.cfg != nil {
		return p.cfg.HistorySeenMax
	}
	return 0
}

// historyScope is the key of the inspect-once record of r: caller is the
// verified caller (the Substrate actor, or a verified host caller), scope
// adds its session, the mode, the guardrail profile and the policy
// generation. Both are "" for a caller the gateway did not verify (no
// record).
func (p *GuardrailProxy) historyScope(r *http.Request, mode string) (caller, scope string) {
	ctx := r.Context()
	session := ""
	if actor, ok := substrateActorFrom(ctx); ok {
		caller = "actor\x00" + actor.RegistrationKey
	} else {
		who := ""
		if b, ok := sandboxauth.FromContext(ctx); ok && b.ID != "" {
			who = "sandbox\x00" + b.ID
		} else if subject, ok := verifiedSubjectFromContext(ctx); ok && subject.UserID != "" {
			who = "subject\x00" + subject.UserID
		} else if p.presentsOwnerCredential(r) {
			who = "owner"
		}
		if who == "" {
			return "", ""
		}
		caller = "host\x00" + p.connectorName() + "\x00" + who
		session = firstNonEmpty(SessionIDFromContext(ctx), r.Header.Get("X-Conversation-ID"))
	}
	prof := proxyGuardrailProfileTelemetryFor(ctx)
	profName, _ := prof.Name.Get()
	profDigest, _ := prof.Digest.Get()
	policy := ""
	if g := requestGeneration(ctx); g != nil {
		policy = firstNonEmpty(g.Digest, strconv.FormatUint(g.N, 10))
	}
	scope = strings.Join([]string{caller, session, mode, profName, profDigest, policy}, "\x00")
	return caller, scope
}

// promptSegments is the current scope of a request followed by the history
// it inspects (fresh), as one list for joinPromptSegments and record.
func promptSegments(current, fresh []string) []string {
	out := make([]string, 0, len(current)+len(fresh))
	return append(append(out, current...), fresh...)
}

// redactHistoryMessages is msgs with the text of every message that holds a
// refused segment replaced by historyRedactedText, for the inspectors that
// read the messages: they see the request the upstream gets.
func redactHistoryMessages(msgs []ChatMessage, refused map[historyHash]historyRefusal) []ChatMessage {
	var out []ChatMessage
	for i, m := range msgs {
		hit := false
		for _, rf := range refused {
			if strings.Contains(m.Content, rf.text) || strings.Contains(string(m.RawContent), rf.text) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if out == nil {
			out = append([]ChatMessage(nil), msgs...)
		}
		out[i].Content, out[i].RawContent = historyRedactedText, nil
	}
	if out == nil {
		return msgs
	}
	return out
}

// auditHistoryRedactions writes one audit row per refused history turn the
// proxy removed: the session, the turn index and the rule, never content.
func (p *GuardrailProxy) auditHistoryRedactions(r *http.Request, reds []historyRedaction) {
	if len(reds) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[guardrail] redacted %d refused turn(s) from request history (path=%s)\n", len(reds), r.URL.Path)
	if p.logger == nil {
		return
	}
	session := firstNonEmpty(SessionIDFromContext(r.Context()), r.Header.Get("X-Conversation-ID"), "-")
	for _, red := range reds {
		_ = p.logger.LogActionCtx(r.Context(), string(audit.ActionGuardrailLaunder), r.URL.Path,
			fmt.Sprintf("redacted a refused turn from request history: session=%s turn=%d rule=%s", session, red.Turn, red.Rule))
	}
}

// historyBlameMax is the most current-turn segments a refusal is attributed
// among, one inspection each; with more, every segment is recorded refused.
const historyBlameMax = 8

// refusedSegments is what a refused request records as refused (GAP-0257):
// only the segments the refusal is attributed to, so the text sent next to
// a refused one (a benign co-turn, a tool result) is not removed when the
// client sends it back.
//
//   - A refusal that is not a guardrail block (an audit that failed closed)
//     is attributed to nothing: the guardrail allowed the text.
//   - A request with one inspected segment: that one.
//   - Otherwise each current-turn segment (at most historyBlameMax) is
//     inspected alone, and the ones the guardrail blocks alone are blamed.
//     This runs only on a refusal.
//   - When that blames none (the refusal came from the system text, the
//     history or the segments together) or there are too many candidates,
//     the refusal cannot be attributed and every current-scope segment is
//     recorded refused, as before (fail safe).
func (p *GuardrailProxy) refusedSegments(ctx context.Context, v *ScanVerdict, current, turn, fresh []string, label, mode string) []string {
	if v == nil || v.Action != "block" {
		return nil
	}
	if inspected := uniqueSegments(promptSegments(current, fresh)); len(inspected) == 1 {
		return inspected
	}
	cands := uniqueSegments(turn)
	if len(cands) == 0 || len(cands) > historyBlameMax || p.inspector == nil {
		return current
	}
	var blamed []string
	for _, s := range cands {
		if alone := p.inspector.Inspect(ctx, "prompt", promptInspectionText(s), nil, label, mode); alone != nil && alone.Action == "block" {
			blamed = append(blamed, s)
		}
	}
	if len(blamed) == 0 {
		return current
	}
	return blamed
}

func uniqueSegments(segs []string) []string {
	seen := make(map[string]bool, len(segs))
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		if !seen[s] && strings.TrimSpace(s) != "" {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// refusedHistoryVerdict is the verdict of a request that carries a refused
// turn the proxy cannot remove (a signed body): refused, fail closed.
func refusedHistoryVerdict() *ScanVerdict {
	return &ScanVerdict{Action: "block", Severity: "HIGH", Scanner: "proxy", Findings: []string{historyRefusedFinding},
		Reason: "the request history carries a turn DefenseClaw refused, and the request body cannot be rewritten to remove it"}
}

// ---- degraded inspections (GAP-0255) -----------------------------------------

type inspectDegradedKey struct{}

// inspectDegradedMark is set when a stage of one inspection failed open.
type inspectDegradedMark struct{ on atomic.Bool }

// withInspectDegraded returns ctx carrying a new mark for one inspection.
func withInspectDegraded(ctx context.Context) (context.Context, *inspectDegradedMark) {
	m := &inspectDegradedMark{}
	return context.WithValue(ctx, inspectDegradedKey{}, m), m
}

// markInspectDegraded notes on ctx's inspection that a stage failed open (no
// verdict was reached for it); a no-op outside one.
func markInspectDegraded(ctx context.Context) {
	if ctx == nil {
		return
	}
	if m, ok := ctx.Value(inspectDegradedKey{}).(*inspectDegradedMark); ok {
		m.on.Store(true)
	}
}

func (m *inspectDegradedMark) degraded() bool { return m != nil && m.on.Load() }
