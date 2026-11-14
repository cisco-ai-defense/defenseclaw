// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

// sensitiveFloor is the floor source of req: the guardrail severity at or
// above routing.sensitive.severity_at_least, else a routing.sensitive
// signal; "" when neither fires.
func (e *Engine) sensitiveFloor(req Request, signals map[string]bool) string {
	s := e.sensitive
	if s.SeverityAtLeast != "" && req.Severity != "" && rankOf(req.Severity) >= rankOf(s.SeverityAtLeast) {
		return SensitiveSourceGuardrail
	}
	for _, name := range s.Signals {
		if signals[name] {
			return SensitiveSourceSignal
		}
	}
	return ""
}

// SensitiveFloor is the floor source of a request the router cannot
// re-route (a signed Bedrock body, an API family it does not rewrite); ""
// when routing.sensitive is off or the floor does not fire.
func (e *Engine) SensitiveFloor(req Request) string {
	if e == nil || e.sensitive == nil || len(e.sensitive.Aliases) == 0 {
		return ""
	}
	return e.sensitiveFloor(req, e.matcher.Match(req.Text))
}
