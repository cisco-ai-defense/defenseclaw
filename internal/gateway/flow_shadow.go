// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/flow"
)

// The Secret flow tracking lane (S7, 1.0.10). It runs the pure effect
// extractor (internal/effects) and the flow step (internal/flow) over a small
// bounded per-session state, beside today's rules. Its rollout rides the
// shared guardrail.effects_rules lane (off disables it entirely, no cost);
// guardrail.secret_flow.mode is the feature's own switch (off, shadow, on).
// The lane ships shadow: it computes and records a verdict without changing the
// answer. In on, the verdict participates.
//
// It replaces the credential-read-then-egress chain entry
// (chain.secret_read_then_egress) once it is on; that entry stays until then
// (see the chain catalog note) so turning the flow lane off keeps today's
// behavior.

type flowLaneMode string

const (
	flowLaneOff    flowLaneMode = "off"
	flowLaneShadow flowLaneMode = "shadow"
	flowLaneOn     flowLaneMode = "on"
)

// maxFlowSessions bounds the number of live per-session states the gateway
// holds. A session is a cheap struct; the real memory is inside each state,
// itself bounded by guardrail.secret_flow.memory.
const maxFlowSessions = 4096

// flowSessionTTL evicts a session state untouched for this long.
const flowSessionTTL = 2 * time.Hour

// secretFlowSessions is the process-wide bounded session store. One gateway
// process serves one per-user install (or one managed host), so a package
// global is the session scope.
var secretFlowSessions = newFlowSessionStore(maxFlowSessions)

type flowSessionEntry struct {
	st   *flow.State
	last time.Time
	// hits is a small bounded ring of the most recent redacted hits on this
	// session, for `defenseclaw guardrail secret-flow explain`. It holds no
	// path or secret value, only the redacted fields the finding already
	// carries (kind, program, host, label sets, a basename or set tag).
	hits []FlowHitRecord
}

// FlowHitRecord is one redacted recent hit for the explain view.
type FlowHitRecord struct {
	Time    string   `json:"time"`
	Kind    string   `json:"kind"`
	Program string   `json:"program,omitempty"`
	Host    string   `json:"host,omitempty"`
	Sets    []string `json:"sets,omitempty"`
	Source  string   `json:"source,omitempty"`
	Action  string   `json:"action"`
}

// maxFlowHitRing is how many recent hits a session keeps for explain.
const maxFlowHitRing = 16

// FlowSessionView is the read-only explain payload for one session.
type FlowSessionView struct {
	Session      string          `json:"session"`
	Found        bool            `json:"found"`
	Label        string          `json:"label"`
	LabeledPaths int             `json:"labeled_paths"`
	ValueDigests int             `json:"value_digests"`
	Hits         []FlowHitRecord `json:"hits"`
}

type flowSessionStore struct {
	mu  sync.Mutex
	m   map[string]*flowSessionEntry
	max int
}

func newFlowSessionStore(max int) *flowSessionStore {
	return &flowSessionStore{m: make(map[string]*flowSessionEntry), max: max}
}

// session returns the state for id, creating it with the configured bounds on
// first use. It evicts stale and over-cap entries so the store stays bounded.
func (s *flowSessionStore) session(id string, cfg flow.Config) *flow.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if e, ok := s.m[id]; ok {
		e.last = now
		return e.st
	}
	s.evictLocked(now)
	st := flow.NewState(cfg.MaxLabeledPaths, cfg.MaxValueDigests)
	s.m[id] = &flowSessionEntry{st: st, last: now}
	return st
}

// lookup returns an existing session state without creating one.
func (s *flowSessionStore) lookup(id string) (*flow.State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok {
		e.last = time.Now()
		return e.st, true
	}
	return nil, false
}

func (s *flowSessionStore) evictLocked(now time.Time) {
	for id, e := range s.m {
		if now.Sub(e.last) > flowSessionTTL {
			delete(s.m, id)
		}
	}
	for len(s.m) >= s.max {
		var oldestID string
		var oldest time.Time
		first := true
		for id, e := range s.m {
			if first || e.last.Before(oldest) {
				oldestID, oldest, first = id, e.last, false
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.m, oldestID)
	}
}

// recordHits appends redacted hit records for a session (bounded ring).
func (s *flowSessionStore) recordHits(id string, recs []FlowHitRecord) {
	if len(recs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return
	}
	e.hits = append(e.hits, recs...)
	if len(e.hits) > maxFlowHitRing {
		e.hits = e.hits[len(e.hits)-maxFlowHitRing:]
	}
}

// view returns the read-only explain payload for a session.
func (s *flowSessionStore) view(id string) FlowSessionView {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return FlowSessionView{Session: id, Found: false}
	}
	hits := append([]FlowHitRecord(nil), e.hits...)
	return FlowSessionView{
		Session:      id,
		Found:        true,
		Label:        e.st.Label.String(),
		LabeledPaths: e.st.LabeledPaths(),
		ValueDigests: e.st.ValueDigests(),
		Hits:         hits,
	}
}

// recentHits returns up to n of the most recent redacted hits across all live
// sessions, newest first, for the status/TUI view.
func (s *flowSessionStore) recentHits(n int) []FlowHitRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []FlowHitRecord
	for _, e := range s.m {
		all = append(all, e.hits...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Time > all[j].Time })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// reset drops every session state (a test seam and a config-reload hook).
func (s *flowSessionStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[string]*flowSessionEntry)
}

// secretFlowConfig builds the engine config from the live generation and the
// call's trusted context. ok is false when the lane should not run.
func secretFlowConfig(ctx context.Context, request trustedActionRequest) (flow.Config, flowLaneMode, bool) {
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return flow.Config{}, flowLaneOff, false
	}
	mode := secretFlowLaneMode(g.Config.Guardrail)
	if mode == flowLaneOff {
		return flow.Config{}, flowLaneOff, false
	}
	sf := g.Config.Guardrail.SecretFlow
	flavor := effects.FlavorPOSIX
	switch request.Input.DialectHint {
	case actionfacts.DialectPowerShell, actionfacts.DialectCMD:
		flavor = effects.FlavorWindows
	}
	strictOrManaged := request.StrictPolicy || request.ManagedInstall
	cfg := flow.Config{
		Credentials:          sf.CredentialsEnabled(),
		ExtraPathGlobs:       sf.LabelSets.ExtraPathGlobs,
		ExtraSecretPatterns:  sf.LabelSets.ExtraSecretPatterns,
		Reencodings:          sf.Reencodings,
		MaxLabeledPaths:      sf.Memory.MaxLabeledPaths,
		MaxValueDigests:      sf.Memory.MaxValueDigests,
		DestinationAllowlist: sf.DestinationAllowlist,
		SinkDefault:          flow.Action(sf.SinkActionFor(false, false)),
		SinkStrict:           flow.Action(sf.SinkActionFor(true, false)),
		SinkManaged:          flow.Action(sf.SinkActionFor(false, true)),
		StrictOrManaged:      strictOrManaged,
		Managed:              request.ManagedInstall,
		Home:                 request.Input.ActiveHome,
		Flavor:               flavor,
	}
	return cfg, mode, true
}

// secretFlowLaneMode folds the rollout key (guardrail.effects_rules) and the
// feature switch (guardrail.secret_flow.mode) into one effective mode. The
// lane runs only when the effect lane is enabled; the verdict participates
// only when both are on.
func secretFlowLaneMode(g config.GuardrailConfig) flowLaneMode {
	rollout := g.EffectsRules
	if rollout == "off" {
		return flowLaneOff
	}
	switch g.SecretFlow.Mode {
	case "off":
		return flowLaneOff
	case "on":
		if rollout == "on" {
			return flowLaneOn
		}
		return flowLaneShadow
	default: // "shadow" or unset
		return flowLaneShadow
	}
}

// runSecretFlowShadow runs the flow step for one call and returns findings.
// In shadow the findings are detection-only; in on an egress finding may
// participate. It is called once at the outermost trusted-action dispatch.
func runSecretFlowShadow(ctx context.Context, request trustedActionRequest) []RuleFinding {
	cfg, mode, ok := secretFlowConfig(ctx, request)
	if !ok {
		return nil
	}
	sid := SessionIDFromContext(ctx)
	if sid == "" {
		// No session continuity: this is a twin, a benchmark/evaluate call, a
		// proxy or a background dispatch (context.Background). The lane keeps
		// per-session state, so a session-less call must not create or mutate
		// a shared state. Skip it (recorded by its absence from the store).
		return nil
	}
	call, opts, has := effectCall(request.Connector, request.Input)
	if !has {
		return nil
	}
	opts.Flavor = cfg.Flavor
	res := effects.Extract(call, opts)
	// scanText is the call's raw command / argument text, scanned at a sink for
	// secret values the effect model does not surface as Data (headers, MCP
	// argument values).
	scanText := request.Input.Command
	if scanText == "" && len(request.Input.Args) > 0 {
		scanText = string(request.Input.Args)
	}
	st := secretFlowSessions.session(sid, cfg)
	out := st.Step(res, scanText, cfg)
	if len(out.Hits) > 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		recs := make([]FlowHitRecord, 0, len(out.Hits))
		for _, h := range out.Hits {
			recs = append(recs, FlowHitRecord{
				Time: now, Kind: string(h.Kind), Program: h.Program,
				Host: redactHost(h.Host), Sets: h.Sets, Source: h.Source, Action: string(out.Action),
			})
		}
		secretFlowSessions.recordHits(sid, recs)
	}
	// P1-1: shadow is record-only (the hit is kept in the explain ring above,
	// never in the live findings). Only the ON lane contributes a finding, and
	// it passes through the same proof boundary as every enforcing finding so
	// a non-enforcement-capable connector is demoted to detection-only.
	if mode != flowLaneOn {
		return nil
	}
	return applyTrustedActionProofBoundary(flowShadowFindings(out, mode), request.EnforcementCapable)
}

// flowShadowFindings turns a flow verdict into findings. A clean or allow
// verdict carries nothing. An alert-tier verdict is capped at alert-only in
// every profile; a block-tier verdict contributes to enforcement so the
// profile threshold maps its severity. The proof is authoritative only when
// the lane is on.
func flowShadowFindings(out flow.Result, mode flowLaneMode) []RuleFinding {
	if out.Action == flow.ActionAllow || len(out.Hits) == 0 {
		return nil
	}
	sets := map[string]bool{}
	kinds := map[string]bool{}
	var host string
	for _, h := range out.Hits {
		for _, s := range h.Sets {
			sets[s] = true
		}
		kinds[string(h.Kind)] = true
		if host == "" {
			host = h.Host
		}
	}
	tags := []string{"secret_flow", string(mode)}
	for s := range sets {
		tags = append(tags, s)
	}
	for k := range kinds {
		tags = append(tags, k)
	}
	sort.Strings(tags)
	severity := "HIGH"
	f := RuleFinding{
		RuleID:     flow.RuleIDEgress,
		Title:      "Secret flow tracking: a labeled secret reached an external sink",
		Severity:   severity,
		Confidence: 0.9,
		Tags:       tags,
	}
	f.disposition = findingDispositionFlowSecretEgress
	f.proof = newFindingProof(findingProofFlow, flow.RuleIDEgress, mode == flowLaneOn)
	if out.Action == flow.ActionAlert {
		f.enforcement = findingEnforcementAlertOnly
	} else {
		f.enforcement = findingEnforcementInherit
	}
	return []RuleFinding{f}
}

// addSecretFlowResultValues feeds the secret-shaped values of a successful
// sensitive-read tool result into the session so a later outbound call that
// sends the value (even re-encoded) is caught by the value lane. It runs on
// PostToolUse. It stores only keyed digests, never the raw value. It is a
// no-op when the lane is off or no state exists for the session yet.
func addSecretFlowResultValues(ctx context.Context, req agentHookRequest) {
	if req.SessionID == "" {
		return
	}
	g := currentGeneration()
	if g == nil || g.Config == nil || secretFlowLaneMode(g.Config.Guardrail) == flowLaneOff {
		return
	}
	if canonicalEvent(req.HookEventName) != "posttooluse" {
		return
	}
	result := stringifyHookValue(firstValue(req.Payload, "tool_response", "toolResponse", "tool_result", "toolResult", "result"))
	if strings.TrimSpace(result) == "" {
		return
	}
	// Index the result only when the flow label set labels the read target
	// (one classifier, same as the file labeler). Indexing every tool output
	// would waste the digest budget.
	sf := g.Config.Guardrail.SecretFlow
	home := hookActiveHome(ctx)
	fcfg := flow.Config{
		Credentials:         sf.CredentialsEnabled(),
		ExtraPathGlobs:      sf.LabelSets.ExtraPathGlobs,
		ExtraSecretPatterns: sf.LabelSets.ExtraSecretPatterns,
		Reencodings:         sf.Reencodings,
		MaxValueDigests:     sf.Memory.MaxValueDigests,
		Home:                home,
		Flavor:              effects.FlavorPOSIX,
	}
	call, opts, has := effectCall(req.ConnectorName, actionfacts.Input{
		Tool: req.ToolName, Args: req.ToolArgs, CWD: req.CWD, ActiveHome: home,
	})
	if !has {
		return
	}
	res := effects.Extract(call, opts)
	labeled := false
	for i := range res.Effects {
		e := &res.Effects[i]
		if e.Kind != effects.KindRead {
			continue
		}
		if _, _, ok := fcfg.LabelForTarget(e.Target); ok {
			labeled = true
			break
		}
	}
	if !labeled {
		return
	}
	st, ok := secretFlowSessions.lookup(req.SessionID)
	if !ok {
		st = secretFlowSessions.session(req.SessionID, flow.Config{
			MaxLabeledPaths: sf.Memory.MaxLabeledPaths,
			MaxValueDigests: sf.Memory.MaxValueDigests,
		})
	}
	st.AddResultValues([]byte(result), "tool_result", fcfg)

}

// redactHost reduces a destination host to its registrable-ish tail (the last
// two dotted labels) so a model-built host that smuggles data in a long
// subdomain label is not echoed whole into the ring, endpoint or explain.
// An IP literal and a short host pass through.
func redactHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return h
	}
	host := h
	port := ""
	if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.IndexByte(host, ':') == i {
		host, port = host[:i], host[i:]
	}
	labels := strings.Split(host, ".")
	if len(labels) > 2 {
		host = strings.Join(labels[len(labels)-2:], ".")
	}
	return host + port
}

// handleSecretFlow serves the Secret flow tracking read-only view at
// /v1/guardrail/secret-flow. With no query it returns the live config summary
// and the number of tracked sessions. With ?session=ID it returns that
// session's redacted explain view (label, counts, recent hits). It never
// returns a path or a secret value.
func (a *APIServer) handleSecretFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if sid := strings.TrimSpace(r.URL.Query().Get("session")); sid != "" {
		a.writeJSON(w, http.StatusOK, secretFlowSessions.view(sid))
		return
	}
	resp := map[string]interface{}{"mode": "off"}
	if live := a.runtimeConfigSnapshot(); live != nil {
		sf := live.Guardrail.SecretFlow
		resp["mode"] = string(secretFlowLaneMode(live.Guardrail))
		resp["configured_mode"] = sf.Mode
		resp["effects_rules"] = live.Guardrail.EffectsRules
		resp["credentials"] = sf.CredentialsEnabled()
		resp["reencodings"] = sf.Reencodings
		resp["sink_default"] = sf.SinkActionFor(false, false)
		resp["sink_strict"] = sf.SinkActionFor(true, false)
		resp["sink_managed"] = sf.SinkActionFor(false, true)
		resp["extra_path_globs"] = sf.LabelSets.ExtraPathGlobs
		resp["extra_secret_patterns"] = sf.LabelSets.ExtraSecretPatterns
		resp["destination_allowlist"] = sf.DestinationAllowlist
		resp["max_labeled_paths"] = sf.Memory.MaxLabeledPaths
		resp["max_value_digests"] = sf.Memory.MaxValueDigests
	}
	secretFlowSessions.mu.Lock()
	resp["tracked_sessions"] = len(secretFlowSessions.m)
	secretFlowSessions.mu.Unlock()
	resp["recent_hits"] = secretFlowSessions.recentHits(maxFlowHitRing)
	a.writeJSON(w, http.StatusOK, resp)
}
