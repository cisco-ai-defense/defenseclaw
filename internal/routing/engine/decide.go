// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"slices"
	"time"
)

var severityRank = map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

func rankOf(s string) int { return severityRank[upper(s)] }

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 0x61 && c <= 0x7a {
			b[i] = c - 0x20
		}
	}
	return string(b)
}

// Decide picks the backend of one request. It never fails: every problem
// is an OutcomeFallback (send the original request) or, on a managed host
// only, an OutcomeDenied.
func (e *Engine) Decide(ctx context.Context, req Request) (d Decision) {
	started := time.Now()
	defer func() { d.Latency = time.Since(started) }()
	if e == nil {
		return Decision{Outcome: OutcomePassthrough, FailureCode: FailureNone}
	}
	pol := e.policyFor(req)
	signals := e.matcher.Match(req.Text)
	categories := make([]string, 0, len(pol.Categories))
	for c := range pol.Categories {
		categories = append(categories, c)
	}
	slices.Sort(categories)
	in := ClassifyInput{
		Text: req.Text, APIFamily: req.APIFamily, Connector: req.Connector, RequestedModel: req.RequestedModel,
		HasTools: req.HasTools, ToolTurn: req.ToolTurn, HasImages: req.HasImages, LongContext: req.LongContext, Signals: signals,
		Categories: categories,
	}

	// 1. Candidate from the user override, sticky entry or the classifier.
	var candidates []string
	var res ClassifyResult
	failure := FailureNone
	classifierFailed := false
	override := pol.AllowUserOverride && req.RequestedModel != "" && e.aliasAllowed(pol, req.RequestedModel)
	needCategory := e.admin != nil && e.admin.Active() && e.admin.NeedsCategory()
	if override {
		d.Source = SourceUserOverride
		candidates = []string{req.RequestedModel}
	}
	if !override || needCategory {
		key := stickyKey{subject: req.Caller.Key, connector: req.Connector, conversation: req.ConversationID, requested: req.RequestedModel, policy: pol.Digest()}
		if r, ok := e.sticky.get(key); ok {
			res = r
			if !override {
				d.Source = SourceSticky
			}
		} else {
			var err error
			res, failure, err = e.classify(ctx, in)
			classifierFailed = err != nil
			if err == nil && (len(res.Aliases) > 0 || res.Category != "") {
				e.sticky.put(key, res)
			}
			if !override {
				d.Source = e.classifierName()
			}
		}
		if !override {
			candidates = append(candidates, res.Aliases...)
		}
	}
	d.Category, d.RuleID, d.Confidence = res.Category, res.RuleID, res.Confidence

	// 2. Admin rules and budgets (S11) narrow the policy.
	var verdict AdminVerdict
	if e.admin != nil && e.admin.Active() {
		verdict = e.admin.Evaluate(ctx, pol, req, res.Category, classifierFailed)
		pol = verdict.Policy
		d.Warnings, d.RuleIDs, d.ChargeKeys = verdict.Warnings, verdict.RuleIDs, verdict.ChargeKeys
		if verdict.Deny != nil && e.managed {
			d.Outcome, d.Deny, d.FailureCode = OutcomeDenied, verdict.Deny, FailureFiltered
			return d
		}
	}
	if !override && len(res.Aliases) == 0 && res.Category != "" {
		if alias, ok := pol.Categories[res.Category]; ok {
			candidates = append(candidates, alias)
		}
	}

	// 3. Sensitive narrowing: guardrail severity or a sensitive signal.
	if s := e.sensitive; s != nil && len(s.Aliases) > 0 {
		hit := s.SeverityAtLeast != "" && req.Severity != "" && rankOf(req.Severity) >= rankOf(s.SeverityAtLeast)
		for _, name := range s.Signals {
			hit = hit || signals[name]
		}
		if hit {
			pol.AllowedAliases = intersectAliases(pol.AllowedAliases, s.Aliases)
			d.FilteredBy = "sensitive"
		}
	}
	d.PolicyDigest = pol.Digest()

	// 4. First eligible alias: Force, candidates, defaults.
	order := append(append(slices.Clone(verdict.Force), candidates...), pol.DefaultAlias, e.unconditional)
	if len(candidates) > 0 {
		d.Candidate = candidates[0]
	}
	for i, alias := range order {
		if alias == "" {
			continue
		}
		b, why := e.eligible(pol, alias, req)
		if why != "" {
			if d.FilteredBy == "" {
				d.FilteredBy = why
			}
			continue
		}
		switch {
		case i < len(verdict.Force):
			d.Source = SourceForce
		case i >= len(verdict.Force)+len(candidates):
			d.Source = SourceDefault
		}
		d.Outcome, d.Backend, d.FailureCode = OutcomeApplied, &b, FailureNone
		d.verdict = verdict
		return d
	}

	// 5. Nothing survives: D3 fallback, or a managed deny when the original
	// request is outside the policy.
	d.verdict = verdict
	if e.managed && (verdict.Bind || e.providerDenied(pol, req.RequestedProvider)) {
		d.Outcome, d.FailureCode = OutcomeDenied, FailureFiltered
		d.Deny = &DenyReason{Code: "routing_admin_denied", Message: "routing.admin does not allow this model for you, and no allowed model can serve this request"}
		return d
	}
	d.Outcome = OutcomeFallback
	switch {
	case failure != FailureNone:
		d.FailureCode = failure
	case len(order) > 0 && d.FilteredBy != "":
		d.FailureCode = FailureFiltered
	default:
		d.FailureCode = FailureNoCandidate
	}
	return d
}

// Gate checks a forwarded exit (the routed backend or the original request)
// against the admin verdict of the decision.
func (e *Engine) Gate(d Decision, target GateTarget) *DenyReason {
	if e == nil || e.admin == nil || !e.admin.Active() {
		return nil
	}
	return e.admin.Gate(d.verdict, target, e.managed)
}

func (e *Engine) classifierName() string {
	if e.classifier == nil {
		return SourceRules
	}
	return e.classifier.Name()
}

// classify runs the configured classifier with the confidence and error
// policy; it returns the failure code of a dropped answer.
func (e *Engine) classify(ctx context.Context, in ClassifyInput) (ClassifyResult, string, error) {
	c := e.classifier
	if c == nil {
		return e.onClassifierError(ctx, in, FailureConfig, errors.New("classifier unavailable"))
	}
	res, err := c.Classify(ctx, in)
	if err != nil {
		code := FailureConfig
		var ce *ClassifierError
		if errors.As(err, &ce) {
			code = ce.Code
		}
		return e.onClassifierError(ctx, in, code, err)
	}
	if e.minConfidence > 0 && res.Confidence >= 0 && res.Confidence < e.minConfidence && c != Classifier(e.rules) {
		return e.onClassifierError(ctx, in, FailureLowConfidence, errors.New("confidence below routing.min_confidence"))
	}
	return res, FailureNone, nil
}

func (e *Engine) onClassifierError(ctx context.Context, in ClassifyInput, code string, err error) (ClassifyResult, string, error) {
	if e.onError == "rules" && e.classifier != Classifier(e.rules) {
		res, _ := e.rules.Classify(ctx, in)
		return res, code, nil
	}
	return ClassifyResult{Confidence: -1}, code, err
}

func intersectAliases(allowed, only []string) []string {
	if allowed == nil {
		return slices.Clone(only)
	}
	out := []string{}
	for _, a := range allowed {
		if slices.Contains(only, a) {
			out = append(out, a)
		}
	}
	return out
}
