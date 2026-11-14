// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// sensitiveRun is the state of one request sensitive narrowing: the floor
// source (set when the guardrail severity, a keyword signal or an earlier
// positive of the conversation already says sensitive) or the pending
// decision-model check, started before the classifier so the two overlap.
type sensitiveRun struct {
	floor   string
	ch      chan sensitiveCheckResult
	timeout time.Duration
	started time.Time
	cancel  context.CancelFunc
}

type sensitiveCheckResult struct {
	sensitive bool
	err       error
}

// beginSensitive evaluates the floor and, when it did not fire, starts the
// check. The floor never weakens: the check only adds positives.
func (e *Engine) beginSensitive(ctx context.Context, req Request, signals map[string]bool) *sensitiveRun {
	s := e.sensitive
	if s == nil || len(s.Aliases) == 0 {
		return nil
	}
	run := &sensitiveRun{floor: e.sensitiveFloor(req, signals)}
	if run.floor == "" && e.sensitiveSticky(req) {
		run.floor = SensitiveSourceSticky
	}
	if run.floor != "" {
		// Every narrowed turn renews the mark of the conversation.
		e.markSensitiveSticky(req)
		return run
	}
	if e.checker == nil || strings.TrimSpace(req.SensitiveText) == "" {
		return run
	}
	run.timeout = time.Duration(s.EffectiveCheckTimeoutMs()) * time.Millisecond
	run.started = time.Now()
	run.ch = make(chan sensitiveCheckResult, 1)
	// Decide cancels the check when it returns before reading it (a
	// managed admin deny): the text is not sent for a refused request.
	cctx, stop := context.WithCancel(ctx)
	run.cancel = stop
	in := SensitiveInput{Text: req.SensitiveText, Truncated: req.SensitiveTruncated, Definition: s.Definition, Connector: req.Connector}
	go func(ch chan<- sensitiveCheckResult, c SensitiveChecker, timeout time.Duration) {
		defer func() {
			if recover() != nil {
				ch <- sensitiveCheckResult{err: &ClassifierError{Code: FailureConfig, Err: errors.New("sensitivity checker panicked")}}
			}
		}()
		tctx, cancel := context.WithTimeout(cctx, timeout)
		defer cancel()
		ok, err := c.Check(tctx, in)
		ch <- sensitiveCheckResult{sensitive: ok, err: err}
	}(run.ch, e.checker, run.timeout)
	return run
}

// applySensitive narrows pol and records the outcome on d.
func (e *Engine) applySensitive(pol *Policy, d *Decision, run *sensitiveRun, req Request) {
	if run == nil {
		return
	}
	s := e.sensitive
	src, reason := run.floor, ""
	if src != "" {
		reason = "positive"
	}
	if run.ch != nil {
		d.Sensitive.Checked = true
		var r sensitiveCheckResult
		timer := time.NewTimer(run.timeout + 250*time.Millisecond)
		select {
		case r = <-run.ch:
			timer.Stop()
		case <-timer.C:
			r.err = &ClassifierError{Code: FailureTimeout, Err: errors.New("sensitivity check timed out")}
		}
		d.Sensitive.CheckLatency = time.Since(run.started)
		name := e.checker.Name()
		hasLocal := len(intersectAliases(pol.AllowedAliases, s.Aliases)) > 0
		switch {
		case r.err != nil:
			code := FailureConfig
			var ce *ClassifierError
			if errors.As(r.err, &ce) && ce.Code != "" {
				code = ce.Code
			}
			d.Sensitive.CheckFailure = code
			reason = "unavailable:" + code
			if s.EffectiveOnUnavailable() == config.RoutingSensitiveUnavailableLocal && hasLocal {
				// Soft: local is tried first, never a block (design 3).
				src, d.Sensitive.Soft = name, true
			} else if hasLocal {
				reason += ":ignored"
			} else {
				reason += ":no_local_route"
			}
		case r.sensitive:
			src, reason = name, "positive"
			e.markSensitiveSticky(req)
		case req.SensitiveTruncated:
			// ONE BOUND RULE: a truncated input is judged at least at the
			// unknown tier of the pack: strict routes local, default and
			// permissive record it and keep the route.
			reason = "truncated"
			d.Warnings = append(d.Warnings, "sensitive_check_truncated")
			if req.StrictTier && hasLocal {
				src, d.Sensitive.Soft = name, true
			}
		default:
			reason = "clear"
		}
	}
	d.Sensitive.Source, d.Sensitive.Reason = src, reason
	if src != "" && !d.Sensitive.Soft {
		pol.AllowedAliases = intersectAliases(pol.AllowedAliases, s.Aliases)
		d.FilteredBy = "sensitive"
	}
}

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
// it ends SensitiveMarkTTL after the last narrowed turn of the
// conversation; marks are in memory and a gateway restart clears them.
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
