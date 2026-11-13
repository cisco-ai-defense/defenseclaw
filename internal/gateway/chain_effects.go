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
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/flow"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// Two scope chains on the Secret flow tracking session state (S7, rel-1-0-10
// chain-effects). Both ask one question of a call that sends data: is its
// destination one the owner named in a prompt of this session, given that the
// session holds sensitive material?
//
//   - chain.sensitive_value_then_unscoped_send (lane chain_effects_value, the
//     value-join subset): the call sends a value or a file that secret flow
//     labelled from an earlier sensitive read, to a destination outside the
//     named scope. The proof that the sensitive bytes are the ones leaving is
//     flow's own (a keyed value digest, a labelled file); the scope narrows it.
//   - chain.sensitive_read_then_unscoped_send (lane chain_effects): the session
//     holds sensitive material (a result the content rules name, or the answer
//     of a read tool) and a later call sends to a destination outside the named
//     scope, with no proof that the sensitive bytes are what is sent.
//
// There is no word list and no text pattern here. Destinations come from the
// one extractor the intent scope floor uses (callSendDestinations: the parsed
// network facts of a shell call, the destination arguments of a tool call; its
// owner is the intent lane). The scope is read from the prompts the owner typed
// (observeUserTurn), kept per session without the judge. The content proof of
// a result is the rule pack's secret and enterprise-data categories, the same
// classifier the result scan runs. A session with no typed prompt has no scope
// to check against, and a send whose destination could not be read is not
// reported (no proof of where it goes).
//
// Each chain is a lane under guardrail.cascade.lanes (default shadow): shadow
// records the hit in the session's explain ring and the audit row and changes
// no answer; on adds one finding (alert by default; block in strict and managed
// where the sensitive material is content-proven or value-joined, alert for the
// bare-read arm). The flow lane's own switches (guardrail.secret_flow) govern
// the flow step; the allowlist and sink actions are shared.

const (
	chainEffectsRuleID      = "chain.sensitive_read_then_unscoped_send"
	chainEffectsValueRuleID = "chain.sensitive_value_then_unscoped_send"

	chainLaneGeneral = "chain_effects"
	chainLaneValue   = "chain_effects_value"

	maxChainArmSets      = 4
	maxChainScopeTargets = maxSessionScopeTargets
	// chainBareReadMinBytes is the smallest answer a bare read must return to
	// arm: an empty or trivial answer holds nothing to send.
	chainBareReadMinBytes = 16
)

// chainEffectsOff is a kill switch for tests; the lanes are the product switch.
var chainEffectsOff atomic.Bool

// chainScanContent is the content-rule scan of one rule-pack category; tests
// replace it.
var chainScanContent = scanContentRuleCategoryForConnector

// chainEffectsEntry is the chain's per-session state, held on flowSessionEntry
// (bounded and evicted with it).
type chainEffectsEntry struct {
	armed  bool
	strong bool // content proof (a secret or a regulated identifier), not only a read
	sets   []string
	source string // the tool that armed it
	scope  []string
	// scopeSeen: a typed prompt was observed, so the session has a scope to
	// check against (possibly one that names nothing).
	scopeSeen bool
}

// chainCallState carries what the flow step found on one call to the chain
// step that runs after it (dispatch order), so a call is reported once.
type chainCallState struct {
	valueFired bool
}

// chainLaneMode resolves a chain lane for a connector: off, shadow or on. A
// missing generation or config is off.
func chainLaneMode(connector, lane string) string {
	if chainEffectsOff.Load() {
		return config.CascadeLaneOff
	}
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return config.CascadeLaneOff
	}
	return g.Config.ResolveCascade(connector).LaneMode(lane)
}

// --- session state ---

func (s *flowSessionStore) noteScope(id string, prompt string) {
	if id == "" {
		return
	}
	targets := namedScopeTargets(prompt)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entryLocked(id)
	if len(targets) > 0 {
		e.chain.scope = mergeTargets(e.chain.scope, targets, maxChainScopeTargets)
	}
	e.chain.scopeSeen = true
}

func (s *flowSessionStore) arm(id string, sets []string, strong bool, source string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entryLocked(id)
	c := &e.chain
	c.armed = true
	if strong {
		c.strong = true
	}
	c.sets = mergeTargets(c.sets, sets, maxChainArmSets)
	if c.source == "" || strong {
		c.source = source
	}
}

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

// --- arming and scope, from the hook's events ---

// chainResultSensitivity reads one tool result. sets are value-free class names;
// strong is true when the content rules name the material.
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

// armChainEffectsFromResult is called for every post-tool event. A failed,
// denied or model-response event never arms (secretFlowResultEvent).
func armChainEffectsFromResult(ctx context.Context, req agentHookRequest) {
	defer func() {
		if r := recover(); r != nil {
			secretFlowPanics.Add(1)
		}
	}()
	if !secretFlowResultEvent(req.HookEventName) || chainLaneMode(req.ConnectorName, chainLaneGeneral) == config.CascadeLaneOff {
		return
	}
	sid := SessionIDFromContext(ctx)
	if sid == "" {
		sid = req.SessionID
	}
	if sid == "" {
		return
	}
	sets, strong := chainResultSensitivity(req.ConnectorName, req.ToolName, secretFlowResultText(req.Payload, req.Content))
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
	sid := SessionIDFromContext(ctx)
	if sid == "" || (chainLaneMode("", chainLaneGeneral) == config.CascadeLaneOff && chainLaneMode("", chainLaneValue) == config.CascadeLaneOff) {
		return
	}
	secretFlowSessions.noteScope(sid, scopeText)
}

// --- the check at a send ---

// chainOutside reads where a call sends and whether any destination is outside
// the session's named scope. ok is false when there is nothing to report: the
// call does not send, its destinations could not be read, or the session has no
// scope to check against.
func chainOutside(v chainView, in actionfacts.Input, allow flow.Config) (dest string, ok bool) {
	if !v.scopeSeen {
		return "", false
	}
	args := string(in.Args)
	if args == "" && in.Command != "" {
		if b, err := json.Marshal(map[string]string{"command": in.Command}); err == nil {
			args = string(b)
		}
	}
	if args == "" {
		return "", false
	}
	var trunc bounded.Truncated
	dests, unreadable := callSendDestinations(in.Tool, args, &trunc)
	if unreadable || trunc.Any() {
		return "", false
	}
	for _, d := range dests {
		if d.mailbox != "" {
			if scopeNamedMailbox(d.mailbox, v.scope) {
				continue
			}
			return d.mailbox[strings.LastIndex(d.mailbox, "@")+1:], true
		}
		if scopeLoopback(d.host) || scopeNamedHost(d.host, v.scope) || allow.HostAllowed(d.host) {
			continue
		}
		return d.host, true
	}
	return "", false
}

func chainSecretFlowSettings() (cfg flow.Config, sinkAction func(strict, managed bool) flow.Action) {
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return flow.Config{}, func(bool, bool) flow.Action { return flow.ActionAlert }
	}
	sf := g.Config.Guardrail.SecretFlow
	return flow.Config{DestinationAllowlist: sf.DestinationAllowlist}, func(strict, managed bool) flow.Action {
		return flow.Action(sf.SinkActionFor(strict, managed))
	}
}

// chainValueJoin is the value-join subset: flow's own proof on this call (a
// labelled file or a seen secret value) and a destination outside the named
// scope. It runs inside the flow step's runner, with its result.
func chainValueJoin(ctx context.Context, request trustedActionRequest, sid string, out flow.Result, flowCfg flow.Config, cc *chainCallState) []RuleFinding {
	mode := chainLaneMode(request.Connector, chainLaneValue)
	if mode == config.CascadeLaneOff || sid == "" {
		return nil
	}
	var proof *flow.Hit
	for i := range out.Hits {
		if k := out.Hits[i].Kind; k == flow.HitValueMatch || k == flow.HitLabeledFile {
			proof = &out.Hits[i]
			break
		}
	}
	if proof == nil {
		return nil
	}
	dest, ok := chainOutside(secretFlowSessions.chainOf(sid), request.Input, flowCfg)
	if !ok {
		return nil
	}
	cc.valueFired = true
	hit := flow.Hit{Kind: flow.HitScopeValue, Program: proof.Program, Host: dest, Sets: proof.Sets, Source: proof.Source}
	_, sink := chainSecretFlowSettings()
	action := sink(request.StrictPolicy, request.ManagedInstall)
	return chainEmit(ctx, request, sid, mode, chainEffectsValueRuleID, hit, action)
}

// runChainEffects is the read-then-unscoped-send chain, run once per call after
// the flow step.
func runChainEffects(ctx context.Context, request trustedActionRequest, cc *chainCallState) (findings []RuleFinding) {
	defer func() {
		if r := recover(); r != nil {
			secretFlowPanics.Add(1)
			findings = nil
		}
	}()
	mode := chainLaneMode(request.Connector, chainLaneGeneral)
	sid := SessionIDFromContext(ctx)
	if mode == config.CascadeLaneOff || sid == "" || (cc != nil && cc.valueFired) {
		return nil
	}
	v := secretFlowSessions.chainOf(sid)
	strong := v.strong
	if !v.armed {
		// The credential label of the session (a labelled read, a copy of a
		// labelled file) is content proof as well.
		if st, ok := secretFlowSessions.lookup(sid); ok && st.Labeled() {
			v.armed, strong = true, true
			v.sets, v.source = []string{"credentials"}, "session-label"
		}
	}
	if !v.armed {
		return nil
	}
	flowCfg, sink := chainSecretFlowSettings()
	dest, ok := chainOutside(v, request.Input, flowCfg)
	if !ok {
		return nil
	}
	sets := append([]string(nil), v.sets...)
	sort.Strings(sets)
	hit := flow.Hit{Kind: flow.HitScopeSend, Program: request.Input.Tool, Host: dest, Sets: sets, Source: v.source}
	action := flow.ActionAlert
	if strong {
		action = sink(request.StrictPolicy, request.ManagedInstall)
	}
	return chainEmit(ctx, request, sid, mode, chainEffectsRuleID, hit, action)
}

// chainEmit records the hit in the session's explain ring and, in shadow, the
// audit row; in on it returns the finding (through the proof boundary).
func chainEmit(ctx context.Context, request trustedActionRequest, sid, mode, ruleID string, hit flow.Hit, action flow.Action) []RuleFinding {
	rec := FlowHitRecord{Time: time.Now().UTC().Format(time.RFC3339), Kind: string(hit.Kind), Program: hit.Program, Host: redactHost(hit.Host), Sets: hit.Sets, Source: hit.Source, Action: string(action)}
	secretFlowSessions.recordHits(sid, []FlowHitRecord{rec})
	if mode != config.CascadeLaneOn {
		emitSecretFlowShadowAudit(ctx, flowLaneShadow, request.Connector, []FlowHitRecord{rec})
		return nil
	}
	if action == flow.ActionAllow {
		return nil
	}
	tags := append([]string{"secret_flow", "chain", string(hit.Kind)}, hit.Sets...)
	sort.Strings(tags)
	title := "Sensitive data was read in this session, then sent to a destination the user never named"
	if ruleID == chainEffectsValueRuleID {
		title = "Sensitive data this session read was sent to a destination the user never named"
	}
	f := RuleFinding{RuleID: ruleID, Title: title, Severity: "HIGH", Confidence: 0.85, Tags: tags}
	f.disposition = findingDispositionFlowSecretEgress
	f.proof = newFindingProof(findingProofFlow, ruleID, true)
	if action == flow.ActionAlert {
		f.enforcement = findingEnforcementAlertOnly
	} else {
		f.enforcement = findingEnforcementInherit
	}
	return applyTrustedActionProofBoundary([]RuleFinding{f}, request.EnforcementCapable)
}
