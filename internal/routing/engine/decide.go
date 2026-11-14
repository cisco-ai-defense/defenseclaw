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

	// 1. Classifier (or its sticky answer), unless the request names an
	// allowed alias and no admin rule needs the category.
	overrideRequested := pol.AllowUserOverride && req.RequestedModel != "" && e.aliasAllowed(pol, req.RequestedModel)
	needCategory := e.admin != nil && e.admin.Active() && e.admin.NeedsCategory()
	var res ClassifyResult
	classifierSource, failure, classifierFailed := "", FailureNone, false
	if !overrideRequested || needCategory {
		res, classifierSource, failure, classifierFailed = e.classifyWithSticky(ctx, req, in, pol)
		if failure != FailureNone && !classifierFailed {
			d.Warnings = append(d.Warnings, "classifier_fallback:"+failure)
		}
	}
	d.Category, d.RuleID, d.Confidence = res.Category, res.RuleID, res.Confidence

	// 2. Admin rules and budgets (S11) narrow the policy.
	var verdict AdminVerdict
	if e.admin != nil && e.admin.Active() {
		verdict = e.admin.Evaluate(ctx, pol.clone(), req, res.Category, classifierFailed)
		pol = verdict.Policy
		d.Warnings = append(d.Warnings, verdict.Warnings...)
		d.RuleIDs, d.ChargeKeys = verdict.RuleIDs, verdict.ChargeKeys
		if verdict.Deny != nil && e.managed {
			d.Outcome, d.Deny, d.FailureCode, d.verdict = OutcomeDenied, verdict.Deny, FailureFiltered, verdict
			return d
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

	// 4. First eligible alias: Force, user override, classifier, defaults.
	// A failed classifier keeps the 1.0.9 meaning: the request goes out
	// unchanged, so the defaults are not tried.
	type cand struct{ alias, source string }
	var order []cand
	for _, a := range verdict.Force {
		order = append(order, cand{a, SourceForce})
	}
	if pol.AllowUserOverride && req.RequestedModel != "" && e.aliasAllowed(pol, req.RequestedModel) {
		order = append(order, cand{req.RequestedModel, SourceUserOverride})
	}
	for _, a := range res.Aliases {
		order = append(order, cand{a, classifierSource})
	}
	if len(res.Aliases) == 0 && res.Category != "" {
		if a, ok := pol.Categories[res.Category]; ok {
			order = append(order, cand{a, classifierSource})
		}
	}
	for _, c := range order {
		if c.source != SourceForce {
			d.Candidate = c.alias
			break
		}
	}
	if !classifierFailed {
		order = append(order, cand{pol.DefaultAlias, SourceDefault}, cand{e.unconditional, SourceDefault})
	}
	for _, c := range order {
		if c.alias == "" {
			continue
		}
		b, why := e.eligible(pol, c.alias, req)
		if why != "" {
			if d.FilteredBy == "" {
				d.FilteredBy = why
			}
			continue
		}
		d.Outcome, d.Backend, d.FailureCode, d.Source, d.verdict = OutcomeApplied, &b, FailureNone, c.source, verdict
		return d
	}

	// 5. Nothing survives: D3 fallback to the original request. The admin
	// Gate judges that original at the forwarded exit (S11 DESIGN 10.2: a
	// binding rule refuses it there, with its own reason), so only the S1
	// floor (routing.admin.denied_providers) denies here, managed only.
	d.verdict = verdict
	if e.managed && e.providerDenied(pol, req.RequestedProvider) {
		d.Outcome, d.FailureCode = OutcomeDenied, FailureFiltered
		d.Deny = &DenyReason{Code: "routing_admin_denied", Message: "routing.admin does not allow this model for you, and no allowed model can serve this request"}
		return d
	}
	d.Outcome, d.Source = OutcomeFallback, classifierSource
	switch {
	case failure != FailureNone:
		d.FailureCode = failure
	case d.FilteredBy != "":
		d.FailureCode = FailureFiltered
	default:
		d.FailureCode = FailureNoCandidate
	}
	return d
}

// classifyWithSticky returns the classifier answer, its source, the failure
// code of a dropped or replaced answer, and whether the request has no
// classifier answer at all.
func (e *Engine) classifyWithSticky(ctx context.Context, req Request, in ClassifyInput, pol Policy) (ClassifyResult, string, string, bool) {
	key := stickyKey{subject: req.Caller.Key, connector: req.Connector, conversation: req.ConversationID, requested: req.RequestedModel, policy: pol.Digest()}
	if r, ok := e.sticky.get(key); ok {
		return r, SourceSticky, FailureNone, false
	}
	res, failure, err := e.classify(ctx, in)
	if err != nil {
		return res, e.classifierName(), failure, true
	}
	if failure != FailureNone {
		// The rules classifier answered for a failed classifier.
		return res, SourceRules, failure, false
	}
	if len(res.Aliases) > 0 || res.Category != "" {
		e.sticky.put(key, res)
	}
	return res, e.classifierName(), FailureNone, false
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
