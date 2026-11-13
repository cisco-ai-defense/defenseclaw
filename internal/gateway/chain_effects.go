// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/flow"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// chain.sensitive_read_then_unscoped_send (S7, rel-1-0-10 chain-effects).
//
// Two ordered steps in one session, on the Secret flow tracking state:
//
//  1. Arm. A completed tool call returned sensitive material: a secret or a
//     regulated personal identifier the content rules name (content proof), or
//     a read tool that returned content (a bare read, the weaker arm). The
//     session records which, and the arm only ever tightens inside the session.
//  2. Fire. A later call sends data to a destination none of the prompts the
//     owner typed in this session names (the intent scope floor's definition of
//     "named", read by callSendDestinations and namedScopeTargets).
//
// It adds no word list of its own: the send reader, the named-scope reader and
// the content rules are the existing ones. It needs no judge: the scope comes
// from the user turn the gateway already observes (observeUserTurn). It rides
// guardrail.secret_flow (mode, sink actions, destination allowlist): shadow
// records the hit, on alerts in default and blocks in strict and managed. A
// bare-read arm alerts and never blocks. A session with no typed prompt has no
// scope to check against, so the chain stays silent for it; a typed prompt that
// names no destination is a scope that names none, and every send is outside it.

// chainEffectsRuleID is the rule id of the chain's finding.
const chainEffectsRuleID = "chain.sensitive_read_then_unscoped_send"

const (
	// maxChainArmSets bounds the label sets one session records.
	maxChainArmSets = 4
	// maxChainScopeTargets bounds the named targets one session keeps.
	maxChainScopeTargets = maxSessionScopeTargets
	// chainBareReadMinBytes is the smallest result a bare read must return to
	// arm: an empty or trivial answer holds nothing to send.
	chainBareReadMinBytes = 16
)

// chainEffectsOff is the kill switch the tests flip; the lane itself is gated
// by guardrail.secret_flow.mode and guardrail.effects_rules.
var chainEffectsOff atomic.Bool

// chainEffectsEntry is the chain's per-session state, held on flowSessionEntry
// (bounded and evicted with it).
type chainEffectsEntry struct {
	armed  bool
	strong bool // content proof (a secret or regulated identifier), not only a read
	sets   []string
	source string // the tool that armed it, redacted to its name
	scope  []string
	// scopeSeen: a typed prompt was observed, so the session has a scope to
	// check against (possibly one that names nothing). Without it the chain
	// stays silent.
	scopeSeen bool
}

// noteScope records the targets a typed prompt names for the session.
func (s *flowSessionStore) noteScope(id string, prompt string) {
	targets := namedScopeTargets(prompt)
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entryLocked(id)
	if len(targets) > 0 {
		e.chain.scope = mergeTargets(e.chain.scope, targets, maxChainScopeTargets)
	}
	e.chain.scopeSeen = true
}

// arm records that a completed call returned sensitive material.
func (s *flowSessionStore) arm(id string, sets []string, strong bool, source string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entryLocked(id)
	c := &e.chain
	if c.armed && c.strong && !strong {
		return
	}
	c.armed = true
	if strong {
		c.strong = true
	}
	c.sets = mergeTargets(c.sets, sets, maxChainArmSets)
	if c.source == "" || strong {
		c.source = source
	}
}

// chainView is what the fire step reads: a copy, so no lock is held while the
// call's destinations are compared.
type chainView struct {
	armed, strong, scopeSeen bool
	sets                     []string
	source                   string
	scope                    []string
}

func (s *flowSessionStore) chainOf(id string) chainView {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return chainView{}
	}
	c := e.chain
	return chainView{armed: c.armed, strong: c.strong, scopeSeen: c.scopeSeen, sets: append([]string(nil), c.sets...), source: c.source, scope: append([]string(nil), c.scope...)}
}

// resetChain forgets the chain state of a session at a lifecycle boundary.
func (s *flowSessionStore) resetChain(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok {
		e.chain = chainEffectsEntry{}
	}
}

// entryLocked returns the entry of a session, creating it with the package
// default bounds. Callers hold s.mu.
func (s *flowSessionStore) entryLocked(id string) *flowSessionEntry {
	now := time.Now()
	if e, ok := s.m[id]; ok {
		e.last = now
		return e
	}
	s.evictLocked(now)
	e := &flowSessionEntry{st: flow.NewState(0, 0), last: now}
	s.m[id] = e
	return e
}

func mergeTargets(have, add []string, limit int) []string {
	seen := make(map[string]bool, len(have))
	for _, t := range have {
		seen[t] = true
	}
	out := append([]string(nil), have...)
	for _, t := range add {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// chainScanContent is the content-rule scan of one rule-pack category; the tests
// replace it.
var chainScanContent = scanContentRuleCategoryForConnector

// chainResultSensitivity reads one tool result. sets are value-free class names
// ("secret", "regulated", "private-read"); strong is true when the content
// rules name the material. One classifier: the rule pack's secret and
// enterprise-data categories, the same ones the result scan runs.
func chainResultSensitivity(connector, tool, result string) (sets []string, strong bool) {
	if strings.TrimSpace(result) == "" {
		return nil, false
	}
	if len(chainScanContent(connector, result, tool, ruleContentScopeUntrusted, "secret")) > 0 {
		sets = append(sets, "secret")
		strong = true
	}
	for _, f := range chainScanContent(connector, result, tool, ruleContentScopeUntrusted, "enterprise-data") {
		if guardrailSeverityRank(f.Severity) >= guardrailSeverityRank("HIGH") {
			sets = append(sets, "regulated")
			strong = true
			break
		}
	}
	if !strong {
		if _, reads := scopeToolVerb(tool); reads && len(result) >= chainBareReadMinBytes {
			sets = append(sets, "private-read")
		}
	}
	return sets, strong
}

// armChainEffectsFromResult is called for every post-tool event. It arms the
// session when the finished call returned sensitive material. A failed, denied
// or model-response event never arms (secretFlowResultEvent).
func armChainEffectsFromResult(ctx context.Context, req agentHookRequest) {
	defer func() {
		if r := recover(); r != nil {
			secretFlowPanics.Add(1)
		}
	}()
	if chainEffectsOff.Load() || !secretFlowResultEvent(req.HookEventName) {
		return
	}
	sid := SessionIDFromContext(ctx)
	if sid == "" {
		sid = req.SessionID
	}
	if sid == "" || !chainEffectsLaneOn() {
		return
	}
	result := secretFlowResultText(req.Payload, req.Content)
	sets, strong := chainResultSensitivity(req.ConnectorName, req.ToolName, result)
	if len(sets) == 0 {
		return
	}
	secretFlowSessions.arm(sid, sets, strong, sanitizeToolName(req.ToolName))
}

// noteChainScope records the targets a typed prompt names. scopeText is the
// part of the prompt known to be what the owner typed ("" when it is not).
func noteChainScope(ctx context.Context, scopeText string) {
	defer func() {
		if r := recover(); r != nil {
			secretFlowPanics.Add(1)
		}
	}()
	if chainEffectsOff.Load() {
		return
	}
	sid := SessionIDFromContext(ctx)
	if sid == "" || !chainEffectsLaneOn() {
		return
	}
	secretFlowSessions.noteScope(sid, scopeText)
}

// chainEffectsLaneOn reports the shared lane is not off (the rollout key and
// the feature switch, as secretFlowLaneMode folds them).
func chainEffectsLaneOn() bool {
	g := currentGeneration()
	return g != nil && g.Config != nil && secretFlowLaneMode(g.Config.Guardrail) != flowLaneOff
}

// chainEffectsHit is the fire step for one call: a hit when the session is
// armed and the call sends to a destination the prompts do not name. The
// second result is the action the active mode takes for it.
func chainEffectsHit(sid string, in actionfacts.Input, cfg flow.Config) (flow.Hit, flow.Action, bool) {
	if chainEffectsOff.Load() || sid == "" {
		return flow.Hit{}, flow.ActionAllow, false
	}
	v := secretFlowSessions.chainOf(sid)
	st, haveState := secretFlowSessions.lookup(sid)
	// The credential label of the session (a labeled read, a copied labeled
	// file) is content proof as well.
	if haveState && st.Labeled() && !v.armed {
		v.armed, v.strong = true, true
		v.sets = append(v.sets, "credentials")
		v.source = "session-label"
	}
	if !v.armed || !v.scopeSeen {
		return flow.Hit{}, flow.ActionAllow, false
	}
	args := string(in.Args)
	if args == "" && in.Command != "" {
		if b, err := json.Marshal(map[string]string{"command": in.Command}); err == nil {
			args = string(b)
		}
	}
	if args == "" {
		return flow.Hit{}, flow.ActionAllow, false
	}
	var trunc bounded.Truncated
	dests := callSendDestinations(in.Tool, args, &trunc)
	dest := ""
	for _, d := range dests {
		if d.mailbox != "" {
			if scopeNamedMailbox(d.mailbox, v.scope) {
				continue
			}
			dest = d.mailbox[strings.LastIndex(d.mailbox, "@")+1:]
		} else {
			if scopeLoopback(d.host) || scopeNamedHost(d.host, v.scope) || cfg.HostAllowed(d.host) {
				continue
			}
			dest = d.host
		}
		break
	}
	if dest == "" && !trunc.Any() {
		return flow.Hit{}, flow.ActionAllow, false
	}
	sets := append([]string(nil), v.sets...)
	sort.Strings(sets)
	hit := flow.Hit{Kind: flow.HitScopeSend, Program: in.Tool, Host: dest, Sets: sets, Source: v.source}
	action := flow.ActionAlert
	if v.strong && cfg.StrictOrManaged {
		if cfg.Managed {
			action = cfg.SinkManaged
		} else {
			action = cfg.SinkStrict
		}
	}
	return hit, action, true
}
