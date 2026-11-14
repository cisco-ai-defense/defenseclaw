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
	key     stickyKey
}

type sensitiveCheckResult struct {
	sensitive bool
	err       error
}

func (e *Engine) sensitiveStickyKey(req Request) stickyKey {
	return stickyKey{subject: req.Caller.Key, connector: req.Connector, conversation: req.ConversationID, requested: "sensitive-check"}
}

// beginSensitive evaluates the floor and, when it did not fire, starts the
// check. The floor never weakens: the check only adds positives.
func (e *Engine) beginSensitive(ctx context.Context, req Request, signals map[string]bool) *sensitiveRun {
	s := e.sensitive
	if s == nil || len(s.Aliases) == 0 {
		return nil
	}
	run := &sensitiveRun{}
	if s.SeverityAtLeast != "" && req.Severity != "" && rankOf(req.Severity) >= rankOf(s.SeverityAtLeast) {
		run.floor = SensitiveSourceGuardrail
	}
	for _, name := range s.Signals {
		if run.floor == "" && signals[name] {
			run.floor = SensitiveSourceSignal
		}
	}
	if run.floor != "" || e.checker == nil || strings.TrimSpace(req.SensitiveText) == "" {
		return run
	}
	run.key = e.sensitiveStickyKey(req)
	if _, ok := e.sticky.get(run.key); ok {
		run.floor = SensitiveSourceSticky
		return run
	}
	run.timeout = time.Duration(s.EffectiveCheckTimeoutMs()) * time.Millisecond
	run.started = time.Now()
	run.ch = make(chan sensitiveCheckResult, 1)
	in := SensitiveInput{Text: req.SensitiveText, Truncated: req.SensitiveTruncated, Definition: s.Definition, Connector: req.Connector}
	go func(ch chan<- sensitiveCheckResult, c SensitiveChecker, timeout time.Duration) {
		defer func() {
			if recover() != nil {
				ch <- sensitiveCheckResult{err: &ClassifierError{Code: FailureConfig, Err: errors.New("sensitivity checker panicked")}}
			}
		}()
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ok, err := c.Check(cctx, in)
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
				src = name
			} else if hasLocal {
				reason += ":ignored"
			} else {
				reason += ":no_local_route"
			}
		case r.sensitive:
			src, reason = name, "positive"
			e.sticky.put(run.key, ClassifyResult{Category: "sensitive", Confidence: 1})
		case req.SensitiveTruncated:
			// ONE BOUND RULE: a truncated input is judged at least at the
			// unknown tier of the pack: strict routes local, default and
			// permissive record it and keep the route.
			reason = "truncated"
			d.Warnings = append(d.Warnings, "sensitive_check_truncated")
			if req.StrictTier && hasLocal {
				src = name
			}
		default:
			reason = "clear"
		}
	}
	d.Sensitive.Source, d.Sensitive.Reason = src, reason
	if src != "" {
		pol.AllowedAliases = intersectAliases(pol.AllowedAliases, s.Aliases)
		d.FilteredBy = "sensitive"
	}
}
