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

// SensitiveConfigured reports whether routing.sensitive can narrow a
// request (aliases set).
func (e *Engine) SensitiveConfigured() bool {
	return e != nil && e.sensitive != nil && len(e.sensitive.Aliases) > 0
}

// SensitiveFloor is the floor source of a request the router cannot
// re-route (a signed Bedrock body, an API family it does not rewrite, a
// body too large to read): the floor, or an earlier sensitive turn of the
// conversation; "" when routing.sensitive is off or neither fires.
func (e *Engine) SensitiveFloor(req Request) string {
	if !e.SensitiveConfigured() {
		return ""
	}
	src := e.sensitiveFloor(req, e.matcher.Match(req.Text))
	if src == "" && e.sensitiveSticky(req) {
		src = SensitiveSourceSticky
	}
	if src != "" {
		e.markSensitiveSticky(req)
	}
	return src
}

// sensitiveStickyKey keys the sensitive mark of a conversation: the caller,
// connector and the agent session id. A request with no session id has no
// mark (each turn is judged alone). Every narrowed turn renews the mark, so
// it ends 30 minutes after the last turn of the conversation that was
// narrowed.
func sensitiveStickyKey(req Request) (stickyKey, bool) {
	if req.ConversationID == "" {
		return stickyKey{}, false
	}
	return stickyKey{subject: req.Caller.Key, connector: req.Connector, conversation: req.ConversationID, requested: "\x00sensitive"}, true
}

func (e *Engine) markSensitiveSticky(req Request) {
	if k, ok := sensitiveStickyKey(req); ok && e.marks != nil {
		e.marks.put(k, ClassifyResult{Category: "sensitive", Confidence: 1})
	}
}

func (e *Engine) sensitiveSticky(req Request) bool {
	k, ok := sensitiveStickyKey(req)
	if !ok || e.marks == nil {
		return false
	}
	_, hit := e.marks.get(k)
	return hit
}
