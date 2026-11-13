// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package gateway

import (
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// flowSeen remembers, per session id, how many shadow hits (and which last one) the harness has already reported.
var flowSeen sync.Map

type flowSeenState struct {
	n    int
	last string
}

func flowHitKey(h FlowHitRecord) string {
	return h.Time + "|" + h.Kind + "|" + h.Program + "|" + h.Host + "|" + h.Source + "|" + h.Action
}

// FlowHitsSince reports the secret-flow shadow hits a session gained since the last call, as short "kind:action" labels, read from the
// session's explain view (the redacted ring the product keeps for `defenseclaw guardrail secret-flow explain`). Shadow never changes an
// answer, so this column is where the lane's would-be findings are visible.
func (e *S7Engine) FlowHitsSince(sessionID string) []string {
	v := secretFlowSessions.view(sessionID)
	if !v.Found || len(v.Hits) == 0 {
		return nil
	}
	prev, _ := flowSeen.Load(sessionID)
	st, _ := prev.(flowSeenState)
	last := flowHitKey(v.Hits[len(v.Hits)-1])
	start := 0
	switch {
	case len(v.Hits) < maxFlowHitRing:
		start = st.n // the ring only appends until it is full
	case last != st.last:
		start = len(v.Hits) - 1 // full ring: the newest hit is the one we can prove is new
	default:
		start = len(v.Hits)
	}
	if start > len(v.Hits) {
		start = len(v.Hits)
	}
	var out []string
	for _, h := range v.Hits[start:] {
		out = append(out, h.Kind+":"+h.Action)
	}
	flowSeen.Store(sessionID, flowSeenState{n: len(v.Hits), last: last})
	return out
}

// S7ApplyFlow applies the harness -secret-flow choice. The effect lane and secret flow ship in shadow, so "" and "shadow" both mean shadow
// here; "off" turns the lane off. The harness has no real user home to follow links through, so the effect lane resolves paths lexically
// (the same harness limit the effects and flow lanes document).
func S7ApplyFlow(cfg *config.Config, mode string) {
	switch mode {
	case "off":
		cfg.Guardrail.EffectsRules = "off"
		cfg.Guardrail.SecretFlow.Mode = "off"
	default:
		cfg.Guardrail.EffectsRules = "shadow"
		cfg.Guardrail.SecretFlow.Mode = "shadow"
	}
	effectResolverOverride = func(path string) (string, bool) { return path, true }
}
