// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// state.call_effects (decision_model.call_effects, off by default) gives the
// decision model the typed effects of the current call (what it reads,
// writes, deletes, runs and sends, from internal/effects) next to its
// text. It is computed only for a call that is sent to the model, inside a
// 50 ms budget, and it is versioned so a model or a replay cache can tell
// the shapes apart.

// decisionCallEffectsVersion is the shape version of state.call_effects.
const decisionCallEffectsVersion = 1

const (
	// maxDecisionCallEffects bounds the effects sent; more is truncated.
	maxDecisionCallEffects = 16
	// maxDecisionEffectTarget bounds one target string, in bytes.
	maxDecisionEffectTarget = 256
	// decisionEffectsBudget bounds the extraction; a late one is truncated.
	decisionEffectsBudget = 50 * time.Millisecond
	// decisionEffectsExtractCap is the extractor's own output bound.
	decisionEffectsExtractCap = 64
)

// decisionCallEffects is state.call_effects.
type decisionCallEffects struct {
	V       int                  `json:"v"`
	Effects []decisionCallEffect `json:"effects"`
	// Unknown lists the structure-level reasons the projection is not fully
	// known (unmodeled_program, dynamic_expansion, ...), in the extractor's
	// precedence order.
	Unknown []string `json:"unknown,omitempty"`
	// Truncated: a cap was hit (effects, extractor limit or time). What was
	// seen before the cap is still listed (ONE BOUND RULE).
	Truncated bool     `json:"truncated,omitempty"`
	Caps      []string `json:"caps,omitempty"`
}

// decisionCallEffect is one effect as the model reads it.
type decisionCallEffect struct {
	Kind       string `json:"kind"`
	TargetType string `json:"target_type,omitempty"`
	Target     string `json:"target,omitempty"`
	// Unknown: the target or the role on it is not known.
	Unknown     bool     `json:"unknown,omitempty"`
	Conditional bool     `json:"conditional,omitempty"`
	DataFrom    []string `json:"data_from,omitempty"`
}

// computeDecisionCallEffects extracts and projects the effects of one call
// within decisionEffectsBudget. It never fails: an extractor panic or a
// late answer is a truncated projection with no effects.
func computeDecisionCallEffects(toolName, args string) *decisionCallEffects {
	raw := json.RawMessage(args)
	if !json.Valid(raw) {
		raw, _ = json.Marshal(args)
	}
	opts := effects.Options{Flavor: effects.FlavorPOSIX, MaxEffects: decisionEffectsExtractCap}
	switch runtime.GOOS {
	case "windows":
		opts.Flavor, opts.CaseInsensitive = effects.FlavorWindows, true
	case "darwin":
		opts.CaseInsensitive = true
	}
	done := make(chan *effects.Result, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- nil
			}
		}()
		r := effects.Extract(effects.Normalize("", toolName, raw), opts)
		done <- &r
	}()
	timer := time.NewTimer(decisionEffectsBudget)
	defer timer.Stop()
	select {
	case r := <-done:
		if r == nil {
			return &decisionCallEffects{V: decisionCallEffectsVersion, Effects: []decisionCallEffect{}, Truncated: true, Caps: []string{"parse"}}
		}
		return projectDecisionCallEffects(*r)
	case <-timer.C:
		return &decisionCallEffects{V: decisionCallEffectsVersion, Effects: []decisionCallEffect{}, Truncated: true, Caps: []string{"time"}}
	}
}

func projectDecisionCallEffects(r effects.Result) *decisionCallEffects {
	out := &decisionCallEffects{V: decisionCallEffectsVersion, Effects: []decisionCallEffect{}}
	caps := map[string]bool{}
	seen := map[string]bool{}
	for _, u := range r.Unknowns {
		code := string(u.Code)
		switch u.Code {
		case effects.ReasonLimit:
			caps["effects"] = true
		case effects.ReasonNestingLimit:
			caps["depth"] = true
		}
		if !seen[code] {
			seen[code] = true
			out.Unknown = append(out.Unknown, code)
		}
	}
	if len(r.Effects) >= decisionEffectsExtractCap {
		caps["effects"] = true
	}
	for i, e := range r.Effects {
		if len(out.Effects) == maxDecisionCallEffects {
			caps["effects"] = true
			break
		}
		ce := decisionCallEffect{
			Kind:        string(e.Kind),
			TargetType:  string(e.Target.Type),
			Target:      decisionEffectTarget(e.Target),
			Unknown:     e.TargetState != effects.TargetStateKnown || e.RoleState == effects.RoleStateUnknown,
			Conditional: e.Cond,
		}
		if ce.TargetType == string(effects.TargetNone) {
			ce.TargetType = ""
		}
		if e.Data != nil {
			for _, s := range e.Data.Sources {
				switch {
				case s.Effect > 0 && s.Effect <= len(r.Effects) && s.Effect != i+1:
					ce.DataFrom = append(ce.DataFrom, fmt.Sprintf("effect %d", s.Effect))
				case s.Path != "":
					ce.DataFrom = append(ce.DataFrom, boundDecisionEffectString(s.Path))
				case s.Kind != "":
					ce.DataFrom = append(ce.DataFrom, string(s.Kind))
				}
				if len(ce.DataFrom) == 4 {
					break
				}
			}
		}
		out.Effects = append(out.Effects, ce)
	}
	for _, c := range []string{"depth", "effects"} {
		if caps[c] {
			out.Truncated = true
			out.Caps = append(out.Caps, c)
		}
	}
	return out
}

func decisionEffectTarget(t effects.Target) string {
	for _, v := range []string{t.Path, t.URL, t.Host, t.Glob, t.Spelling} {
		if v != "" {
			return boundDecisionEffectString(v)
		}
	}
	return ""
}

func boundDecisionEffectString(s string) string {
	if len(s) <= maxDecisionEffectTarget {
		return s
	}
	cut := maxDecisionEffectTarget
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

// withCallEffects adds state.call_effects when the model is configured for
// it and the call is about to be sent (the breaker is closed and there is
// time). A skipped call costs no extraction.
func (d *decisionModel) withCallEffects(ctx context.Context, state decisionModelState, toolName, args string) decisionModelState {
	if d == nil || !d.callEffects || state.CallEffects != nil || d.wouldSkip(ctx) {
		return state
	}
	state.CallEffects = computeDecisionCallEffects(toolName, args)
	return state
}

// wouldSkip reports, without counting a skip, whether decide would not call
// the model now.
func (d *decisionModel) wouldSkip(ctx context.Context) bool {
	d.breakerMu.Lock()
	open := time.Now().Before(d.openUntil)
	d.breakerMu.Unlock()
	return open || d.budget(ctx) < decisionMinBudget
}
