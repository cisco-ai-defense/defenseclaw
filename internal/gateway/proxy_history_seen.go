// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/historystore"
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
// The current scope of a request (the top-level system text, instructions
// and tool definitions, the system and developer turns a turn list starts
// with, the turns after the model's last one) is inspected on every request
// as before, so a refused request sent again is refused again. A system or
// developer turn the client puts between the others is placed like any turn
// (turnPlaces, GAP-0265).
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
// historystore.MaxScopesPerCaller scopes per caller and
// historystore.MaxScopes in all (the least recently used scope is dropped
// whole). A segment that is not in the record, evicted or never seen, is
// inspected; nothing is skipped on a miss. An evicted refused segment is
// inspected again and refused again.
//
// The record lives in a historystore.Store (GAP-0266): the proxy's own
// process store by default (one gateway), the leader's store on Agent
// Substrate (useSubstrateChains), whose gateway runs several replicas: a turn
// refused on one replica is refused-known on every other, so the session is
// not locked by where the next request lands. Only hashes, verdicts and rule
// identifiers reach the store. A store that fails is warned about and read as
// empty: every segment is inspected and nothing is skipped or removed, so a
// store failure never launders a segment.

// historyRedactedText replaces the text of a refused turn the client sends
// back. It does not start with the block banner, so laundering keeps it.
const historyRedactedText = "(Removed by DefenseClaw policy: this turn was refused when it was sent, and its text is not forwarded.)"

// historyRefusedFinding is the finding of a request refused because it
// carries a refused turn the proxy cannot remove.
const historyRefusedFinding = "PROXY-HISTORY-REFUSED-TURN"

type historyHash = historystore.Hash

func historyHashOf(s string) historyHash {
	sum := sha256.Sum256([]byte(s))
	var h historyHash
	copy(h[:], sum[:len(h)])
	return h
}

// substrateHistoryStore, when set (a gateway replica on Agent Substrate),
// is the inspect-once record of every proxy that has no store of its own.
var substrateHistoryStore atomic.Pointer[historystore.Store]

// setSubstrateHistoryStore sets (nil clears) the shared record.
func setSubstrateHistoryStore(store historystore.Store) {
	if store == nil {
		substrateHistoryStore.Store(nil)
		return
	}
	substrateHistoryStore.Store(&store)
}

// historySeen is the inspect-once record of a proxy. The zero value is
// ready to use: it uses the shared store when one is set, else its own
// process store.
type historySeen struct {
	// store, when set, is used in place of the shared and process stores
	// (tests: two proxies that share one record).
	store historystore.Store
	own   historystore.Process
	// lastWarn rate-limits the store warnings (unix nanoseconds).
	lastWarn atomic.Int64
}

func (s *historySeen) recordStore() historystore.Store {
	if s.store != nil {
		return s.store
	}
	if shared := substrateHistoryStore.Load(); shared != nil {
		return *shared
	}
	return &s.own
}

// historyStoreWarnEvery is the shortest time between two store warnings of
// one proxy.
const historyStoreWarnEvery = time.Minute

// warn writes a rate-limited warning that the record could not be read or
// written; the request goes on with every segment inspected.
func (s *historySeen) warn(op string, err error) {
	now := time.Now().UnixNano()
	last := s.lastWarn.Load()
	if now-last < int64(historyStoreWarnEvery) || !s.lastWarn.CompareAndSwap(last, now) {
		return
	}
	fmt.Fprintf(os.Stderr, "[guardrail] warning: the inspect-once record could not be %s (%v); the request history is inspected in full\n", op, err)
}

// historyRefusal is what the record holds of a history segment whose request
// was refused: the rule that refused it (the segment is keyed by its hash).
type historyRefusal struct {
	rule string
}

// fresh splits the history segments of a request: the ones the scope has not
// had inspected (fresh, each once, in order) and the ones whose request was
// refused (refused, by hash). An empty scope (an unverified caller) has no
// record, and a store that fails is read as empty: every segment is fresh.
func (s *historySeen) fresh(ctx context.Context, scope string, segs []string) (fresh []string, refused map[historyHash]historyRefusal) {
	if len(segs) == 0 {
		return nil, nil
	}
	fresh = make([]string, 0, len(segs))
	dup := make(map[historyHash]bool, len(segs))
	hashes := make([]historyHash, 0, len(segs))
	uniq := make([]string, 0, len(segs))
	for _, seg := range segs {
		h := historyHashOf(seg)
		if !dup[h] {
			dup[h] = true
			hashes = append(hashes, h)
			uniq = append(uniq, seg)
		}
	}
	var known map[historyHash]historystore.Entry
	if scope != "" {
		var err error
		if known, err = s.recordStore().Seen(ctx, scope, hashes); err != nil {
			s.warn("read", err)
			known = nil
		}
	}
	for i, seg := range uniq {
		ent, ok := known[hashes[i]]
		if !ok {
			fresh = append(fresh, seg)
			continue
		}
		if ent.Verdict == historystore.Refused {
			if refused == nil {
				refused = map[historyHash]historyRefusal{}
			}
			refused[hashes[i]] = historyRefusal{rule: ent.Rule}
		}
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
// default). A store that fails is warned about; nothing is recorded.
func (s *historySeen) record(ctx context.Context, caller, scope string, segs []string, v *ScanVerdict, refused, degraded bool, max int) {
	if scope == "" || len(segs) == 0 || v == nil {
		return
	}
	if !refused && (degraded || v.JudgeFailed) {
		return
	}
	if max <= 0 {
		max = config.DefaultHistorySeenMax
	}
	ent := historystore.Entry{Verdict: historystore.Allowed}
	switch {
	case refused:
		ent = historystore.Entry{Verdict: historystore.Refused, Rule: historyRule(v)}
	case v.Action != "" && v.Action != "allow":
		ent.Verdict = historystore.Alerted
	}
	hashes := make([]historyHash, 0, len(segs))
	for _, seg := range segs {
		hashes = append(hashes, historyHashOf(seg))
	}
	if err := s.recordStore().Record(ctx, caller, scope, hashes, ent, max); err != nil {
		s.warn("written", err)
	}
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

// historyHashSet is the set of the hashes of segs (the current scope of a
// request: the refused text it sends again there is inspected, not removed).
func historyHashSet(segs []string) map[historyHash]bool {
	out := make(map[historyHash]bool, len(segs))
	for _, s := range segs {
		out[historyHashOf(s)] = true
	}
	return out
}

// historyAllKept reports that every refused segment is also in the current
// scope (keep): there is nothing to remove, and the inspection reads them.
func historyAllKept(refused map[historyHash]historyRefusal, keep map[historyHash]bool) bool {
	for h := range refused {
		if !keep[h] {
			return false
		}
	}
	return true
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

// historyBlameMax is the most attribution inspections one refusal makes
// (one more judge or AI Defense call each).
const historyBlameMax = 8

// refusedSegments is what a refused request records as refused (GAP-0257):
// only the segments the refusal is attributed to, so the text sent next to
// a refused one (a benign co-turn, a tool result) is not removed when the
// client sends it back. The candidates are every segment the request had
// inspected for the first time: its current turns and its fresh history
// (GAP-0300). A text can first reach the proxy as history (the model's own
// reply quoting an injection it declined, a compaction summary); blaming
// only the current turn left that text unrecorded, so it was inspected and
// refused again on every later request and the session was locked.
//
// Only what an inspection shows is blamed (substrate-1 GAP-0308). The
// segments of a refused request that are not blamed are not recorded, so the
// next request inspects them again: blaming one cause of a refusal never
// lets another one through. In all, at most historyBlameMax attribution
// inspections, every probe counted (GAP-0309).
//
//   - A refusal that is not a guardrail block (an audit that failed closed)
//     is attributed to nothing: the guardrail allowed the text.
//   - No fresh history: among the current turns. One current turn (the
//     walker's Turn: not a leading system or developer turn, the
//     instructions or the tool definitions, GAP-0265) is blamed with no
//     further inspection, so a refusal keeps managed AI Defense at one call;
//     two to historyBlameMax are each inspected alone and the ones that block
//     alone are blamed; none blamed, none, or more: the current scope is
//     recorded refused (fail safe).
//   - Fresh history: the current turns are inspected first, as one text.
//     When they block, the refusal is attributed among them as above, with
//     one call fewer (up to historyBlameMax-1 turns each alone), and the
//     history is not blamed. When they do not, the fresh history is in the
//     cause: the fresh history and the current turns are inspected together,
//     and when that does not block either (the refusal came from the text
//     inspected on every request, the system text, or from a history text
//     the proxy had already seen), the current scope and the fresh history
//     are recorded refused (fail safe). When it blocks, the fresh history is
//     split, in order, into groups of consecutive segments (as many as the
//     calls left can search: 2^left) and the smallest newest-first run of
//     groups that blocks together with the current turns is found by binary
//     search. Its oldest group is blamed: without it the rest of the run is
//     allowed. A refusal of two parts together (one in the history, one in
//     the current turn, or both in the history) blames the older part and
//     removes no benign turn.
func (p *GuardrailProxy) refusedSegments(ctx context.Context, v *ScanVerdict, current, turn, fresh []string, label, mode string) []string {
	if v == nil || v.Action != "block" {
		return nil
	}
	cands := uniqueSegments(turn)
	hist := uniqueSegments(fresh)
	if len(hist) == 0 || p.inspector == nil {
		return p.blameAmong(ctx, cands, current, historyBlameMax, label, mode)
	}
	left := historyBlameMax
	if len(cands) > 0 {
		left--
		if p.blocksAlone(ctx, cands, label, mode) {
			return p.blameAmong(ctx, cands, current, left, label, mode)
		}
	}
	failSafe := append(append(make([]string, 0, len(current)+len(hist)), current...), hist...)
	run := func(from [][]string) []string {
		var out []string
		for _, g := range from {
			out = append(out, g...)
		}
		return append(out, cands...)
	}
	left--
	if !p.blocksAlone(ctx, run([][]string{hist}), label, mode) {
		return failSafe
	}
	// The run of every group blocks; the current turns alone (the run of
	// none) do not. Binary search keeps hi a run that blocks and lo one that
	// does not: ceil(log2(len(groups))) <= left calls.
	groups := historyGroups(hist, 1<<left)
	hi, lo := 0, len(groups)
	for lo-hi > 1 {
		mid := (hi + lo) / 2
		if p.blocksAlone(ctx, run(groups[mid:]), label, mode) {
			hi = mid
		} else {
			lo = mid
		}
	}
	return groups[hi]
}

// blameAmong attributes a refusal among the current turns cands (GAP-0257),
// inspecting each alone when there are at most limit of them.
func (p *GuardrailProxy) blameAmong(ctx context.Context, cands, current []string, limit int, label, mode string) []string {
	if len(cands) == 1 {
		return cands
	}
	if len(cands) == 0 || len(cands) > limit || p.inspector == nil {
		return current
	}
	var blamed []string
	for _, s := range cands {
		if p.blocksAlone(ctx, []string{s}, label, mode) {
			blamed = append(blamed, s)
		}
	}
	if len(blamed) == 0 {
		return current
	}
	return blamed
}

// blocksAlone inspects segs alone, as one text, once.
func (p *GuardrailProxy) blocksAlone(ctx context.Context, segs []string, label, mode string) bool {
	v := p.inspector.Inspect(ctx, "prompt", promptInspectionText(strings.Join(segs, "\n")), nil, label, mode)
	return v != nil && v.Action == "block"
}

// historyGroups splits segs, in order, into at most n groups of consecutive
// segments.
func historyGroups(segs []string, n int) [][]string {
	size := (len(segs) + n - 1) / n
	var out [][]string
	for i := 0; i < len(segs); i += size {
		out = append(out, segs[i:min(i+size, len(segs))])
	}
	return out
}

// historyRequestPrint names a whole request (every segment it carries, in
// order): a refused request records it, so the same request sent again is
// refused again rather than redacted (GAP-0244), while a session that went
// on after the refusal has its refused turns removed (GAP-0300).
func historyRequestPrint(segments, history []string) string {
	sum := sha256.New()
	for _, part := range [][]string{segments, history} {
		for _, s := range part {
			sum.Write([]byte(s))
			sum.Write([]byte{0})
		}
		sum.Write([]byte{1})
	}
	return "\x00defenseclaw-refused-request\x00" + string(sum.Sum(nil))
}

// retried reports that scope recorded the request named print as refused:
// the client sends the refused request again.
func (s *historySeen) retried(ctx context.Context, scope, print string) bool {
	_, refused := s.fresh(ctx, scope, []string{print})
	return len(refused) > 0
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
