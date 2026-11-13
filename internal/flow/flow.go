// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package flow is the Secret flow tracking step (S7, 1.0.10). It folds the
// effects of each tool call into a small per-session state and answers one
// question: did a labeled secret reach an external sink.
//
// It is a Go rebuild of the information-flow idea in OpenAPPA
// (archestra-ai/OpenAPPA, MIT) and its paper, "APPA: Recoverable
// Information-Flow Control for Real-World LLM Agents" (arXiv 2607.24625,
// NeurIPS 2026 Workshop on Agents in the Wild), which stands on the
// information-flow-control tradition: Denning's lattice model of secure
// information flow (1976) and the decentralized model of Myers and Liskov
// (SOSP 1997). See docs-site/content/docs/guardrail/secret-flow-tracking.mdx,
// section "Credits", for what we took and what we changed.
//
// What we took: a session label that only ever tightens, labels that travel
// with the files a session writes, and a check at network sinks.
// What we changed: the step is O(1) per call (it folds state, it does not
// replay the trajectory); it labels credentials only by default; it carries
// keyed hashes of the secret VALUES seen in tool results so a copied or
// re-encoded secret is still caught; and the default action is a visible
// alert, never a block.
//
// The step is deterministic and self-contained: it imports only
// internal/effects, reads no filesystem, consults no runtime.GOOS, and makes
// no network or LLM calls. The gateway holds one State per session (bounded,
// evicted) and feeds it the effects of each call; value digests are added
// from PostToolUse tool results through AddResultValues.
package flow

import "github.com/defenseclaw/defenseclaw/internal/effects"

// Disposition is the finding disposition this step exposes. Stream S8 maps it
// to a native "ask" where a connector supports one; until then default is a
// visible alert and strict/managed block.
const Disposition = "flow_secret_egress"

// RuleIDEgress is the rule id a flow finding carries.
const RuleIDEgress = "flow.secret_egress"

// Action is what the step would do for one call under the active mode.
type Action string

const (
	ActionAllow Action = "allow"
	ActionAlert Action = "alert"
	ActionBlock Action = "block"
)

// HitKind names why a sink fired, for the explain view and the measurement.
type HitKind string

const (
	// HitLabeledFile: the sent file carries a secret label this session put on
	// it (a credential read, or a copy/move/link of a labeled file).
	HitLabeledFile HitKind = "labeled_file"
	// HitValueMatch: the sent bytes contain a keyed-hash match of a secret
	// value this session saw in a tool result (possibly re-encoded).
	HitValueMatch HitKind = "value_match"
	// HitSessionContext: the session is labeled and the call reaches an
	// external sink, with no data-lane proof. Never fires in default.
	HitSessionContext HitKind = "session_context"
)

// Hit is one sink finding.
type Hit struct {
	Kind HitKind
	// Program is the sink program (curl, git, an MCP tool name), value-free.
	Program string
	// Host is the external destination host, when known.
	Host string
	// Sets are the label sets that labeled the data (e.g. "credentials").
	Sets []string
	// Source, redacted, describes where the label came from: a basename or a
	// set name, never a full path or a secret value. Used by `explain`.
	Source string
	// EffectIndex is the 1-based index of the sink effect in the call.
	EffectIndex int
}

// Result is the step's answer for one call.
type Result struct {
	// Label is the session label after this call (monotone).
	Label Label
	// Hits are the sinks that fired on this call.
	Hits []Hit
	// Action is the action the active mode would take for the strongest hit.
	Action Action
	// LabeledPaths is how many session paths carry a label after this call
	// (for the status/explain view and the memory-bound test).
	LabeledPaths int
	// LabeledThisCall lists the basenames (redacted) this call newly labeled,
	// for explain.
	LabeledThisCall []string
}

// Step folds one call's effects into the state and returns the verdict. It
// mutates the state (session label, labeled paths) and is O(number of effects)
// in the call, independent of session length.
func (s *State) Step(res effects.Result, cfg Config) Result {
	if s == nil {
		return Result{Action: ActionAllow}
	}
	out := Result{Action: ActionAllow}

	// Pass 1: credential-source reads tighten the session label and mark the
	// read target keys, so a later write/upload of the same key is labeled.
	readLabel := map[int]Label{} // 1-based effect index -> label of what it read
	for i := range res.Effects {
		e := &res.Effects[i]
		if e.Kind != effects.KindRead {
			continue
		}
		if lbl, sets, ok := cfg.labelForTarget(e.Target); ok {
			s.tighten(lbl)
			readLabel[i+1] = lbl
			if k := e.Target.Key(); k != "" {
				s.labelPath(k, lbl, sets, basename(e.Target))
				out.LabeledThisCall = append(out.LabeledThisCall, basename(e.Target))
			}
		}
	}

	// Pass 2: carry labels onto files this call writes/links from a labeled
	// source, and collect sink effects.
	for i := range res.Effects {
		e := &res.Effects[i]
		switch e.Kind {
		case effects.KindWrite, effects.KindAppend, effects.KindLink:
			if lbl, sets, src, ok := s.writeLabel(e, res.Effects, readLabel, cfg); ok {
				if k := e.Target.Key(); k != "" {
					s.labelPath(k, lbl, sets, src)
					out.LabeledThisCall = append(out.LabeledThisCall, basename(e.Target))
				}
				// A link's physical target is the real file; label it too so a
				// later read of the link name is caught.
				if e.Kind == effects.KindLink && e.Target.Physical != "" {
					s.labelPath(physicalKey(e.Target), lbl, sets, src)
				}
			}
		}
	}

	// Pass 3: sinks.
	for i := range res.Effects {
		e := &res.Effects[i]
		if !isSink(e, cfg) {
			continue
		}
		// The effect model does not yet put the destination host on the upload
		// effect (it is on the sibling fetch of the same command); resolve it
		// here. TODO: drop once s7-effects carries the host on the send effect.
		host := sinkHost(e, res.Effects)
		if cfg.isAllowlistedHost(host) {
			continue
		}
		if h, ok := s.sinkHit(e, host, res.Effects, readLabel, cfg); ok {
			h.EffectIndex = i + 1
			out.Hits = append(out.Hits, h)
		}
	}

	out.Label = s.Label
	out.LabeledPaths = s.paths.len()
	out.Action = cfg.action(out.Hits)
	return out
}

// sinkHost returns the destination host of a sink effect. An upload effect
// (curl -T/-F/-d, wget --post-file) currently carries no host of its own; the
// host is on the sibling network_fetch of the same command (same Origin
// command and span). This resolves it so the allowlist and loopback checks
// work. TODO: remove the sibling search once s7-effects puts the host on the
// send effect directly.
func sinkHost(e *effects.Effect, all []effects.Effect) string {
	if e.Target.Host != "" {
		return e.Target.Host
	}
	for i := range all {
		o := &all[i]
		if o == e || o.Target.Host == "" {
			continue
		}
		if o.Origin.Command == e.Origin.Command && o.Origin.Span == e.Origin.Span {
			return o.Target.Host
		}
	}
	return ""
}

// isSink reports whether an effect is an external network sink the step checks.
func isSink(e *effects.Effect, cfg Config) bool {
	switch e.Kind {
	case effects.KindNetworkSend:
		return true
	case effects.KindNetworkFetch:
		// A fetch is a sink only when it carries data (a query/body the model
		// built), handled by the value/label check; a plain GET is not.
		return e.Data != nil || hasQuery(e.Target)
	case effects.KindWrite, effects.KindAppend, effects.KindLink:
		// A write/copy to another host (scp/rsync host:path, an ssh remote
		// operand) sends the data off the machine, so it is an external sink.
		return e.Target.Type == effects.TargetRemote
	}
	return false
}
