// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
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
// is an OutcomeFallback (send the original request) or an OutcomeDenied (a
// managed admin rule, or a sensitive request no local model can serve).
func (e *Engine) Decide(ctx context.Context, req Request) (d Decision) {
	started := time.Now()
	defer func() { d.Latency = time.Since(started) }()
	if e == nil {
		return Decision{Outcome: OutcomePassthrough, FailureCode: FailureNone}
	}
	pol := e.policyFor(req)
	// The classifier reads routing.context (older turns, tool names); the
	// routing.sensitive floor and check keep reading the newest turn only,
	// as documented (merge of s1b/route-context and s1c/pii-local).
	text, signals, contextWarning := e.classifierText(req)
	if contextWarning != "" {
		d.Warnings = append(d.Warnings, contextWarning)
	}
	newest := signals
	if text != req.Text {
		newest = e.matcher.Match(req.Text)
	}
	sens := e.beginSensitive(ctx, req, newest)
	if sens != nil && sens.cancel != nil {
		defer sens.cancel()
	}
	categories := make([]string, 0, len(pol.Categories))
	for c := range pol.Categories {
		categories = append(categories, c)
	}
	slices.Sort(categories)
	in := ClassifyInput{
		Text: text, APIFamily: req.APIFamily, Connector: req.Connector, RequestedModel: req.RequestedModel,
		HasTools: req.HasTools, ToolTurn: req.ToolTurn, HasImages: req.HasImages, LongContext: req.LongContext, Signals: signals,
		ToolLoop:   req.ToolLoop && e.context.ToolNames,
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
		if verdict.Deny != nil && (e.managed || verdict.Enforce) {
			if e.SensitiveConfigured() && e.sensitiveFloor(req, newest) != "" {
				// The refused turn may stay in the agent history: keep the
				// conversation narrowed (GAP-0576 review r3).
				e.markSensitiveSticky(req)
			}
			d.Outcome, d.Deny, d.FailureCode, d.verdict = OutcomeDenied, verdict.Deny, FailureFiltered, verdict
			return d
		}
	}

	// 3. Sensitive narrowing: the guardrail or signal floor, else the
	// decision-model check (sensitive.go).
	e.applySensitive(&pol, &d, sens, req)
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
	narrowed := d.SensitiveNarrowed()
	req.Narrowed = narrowed
	if d.Sensitive.Soft {
		// Prefer the local models (after admin Force); the usual order
		// follows, so a request no local model can take is never refused.
		soft := make([]cand, 0, len(e.sensitive.Aliases))
		for _, a := range e.sensitive.Aliases {
			soft = append(soft, cand{a, SourceSensitive})
		}
		n := len(verdict.Force)
		order = append(order[:n:n], append(soft, order[n:]...)...)
	}
	if narrowed {
		// A sensitive request tries the local models even when the
		// classifier and the defaults name only cloud aliases, and even
		// when the classifier failed (GAP-0576).
		for _, a := range e.sensitive.Aliases {
			order = append(order, cand{a, SourceSensitive})
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
		if verdict.Bind && pol.DefaultAlias != "" {
			// A routing.admin rule that lists the allowed aliases binds the
			// request to them (the original request is refused when it is
			// outside the list). Its default is only a preference: when the
			// default cannot serve this request (another API, a missing
			// capability or credential) the next allowed alias that can is
			// used, in the list's order, instead of refusing a request an
			// allowed model could answer (rel-1-0-10:GAP-1104). A request
			// whose model the rule does not allow is still refused with the
			// rule named, and a rule with no default tries nothing new.
			if _, why := e.eligible(pol, pol.DefaultAlias, req); why == "api" || why == "capability" || why == "credential" {
				for _, a := range pol.AllowedAliases {
					order = append(order, cand{a, SourceDefault})
				}
			}
		}
	}
	localWhy := ""
	for _, c := range order {
		if c.alias == "" {
			continue
		}
		b, why := e.eligible(pol, c.alias, req)
		if why != "" {
			if d.FilteredBy == "" {
				d.FilteredBy = why
			}
			switch why {
			case "credential":
				if !slices.Contains(d.NoCredential, c.alias) {
					d.NoCredential = append(d.NoCredential, c.alias)
				}
			case "capability", "api", "endpoint":
				d.OtherUnfit = true
			}
			if narrowed && localWhy == "" && slices.Contains(e.sensitive.Aliases, c.alias) {
				localWhy = "local model " + c.alias + " cannot serve it (" + why + ")"
			}
			continue
		}
		d.Outcome, d.Backend, d.FailureCode, d.Source, d.verdict = OutcomeApplied, &b, FailureNone, c.source, verdict
		return d
	}

	// 5. Nothing survives: D3 fallback to the original request. The admin
	// Gate judges that original at the forwarded exit (S11 DESIGN 10.2: a
	// binding rule refuses it there, with its own reason), so only the S1
	// floor (routing.admin.denied_providers) denies here, on a managed host
	// and for an enforced (actor) verdict.
	d.verdict = verdict
	if narrowed {
		// Fail closed: a sensitive request never falls back to the
		// original (cloud) request, on OSS and managed hosts alike.
		if localWhy == "" {
			localWhy = "no routing.sensitive.aliases model is allowed for this caller"
		}
		d.Outcome, d.FailureCode, d.Source = OutcomeDenied, FailureFiltered, SourceSensitive
		d.Deny = SensitiveLocalDeny(d.Sensitive.Source, localWhy)
		return d
	}
	if (e.managed || verdict.Enforce) && e.providerDenied(pol, req.RequestedProvider) {
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
// against the decision: a sensitive decision allows only the
// routing.sensitive.aliases models (every host; the original request is
// never one), then the admin verdict judges the exit.
func (e *Engine) Gate(d Decision, target GateTarget) *DenyReason {
	if e == nil {
		return nil
	}
	if d.SensitiveNarrowed() && (e.sensitive == nil || target.Alias == "" || !slices.Contains(e.sensitive.Aliases, target.Alias)) {
		exit := "the original model request"
		if target.Alias != "" {
			exit = "model " + target.Alias
		}
		return SensitiveLocalDeny(d.Sensitive.Source, exit+" is not a local model")
	}
	if e.admin == nil || !e.admin.Active() {
		return nil
	}
	deny := e.admin.Gate(d.verdict, target, e.managed || d.verdict.Enforce)
	if deny != nil && deny.Code == "routing_admin_denied" && target.Alias == "" && len(d.NoCredential) > 0 {
		// The administrator allows a model, but no credential is stored
		// for it, so the request fell back to its own (disallowed) model:
		// say what is missing, not that the model is disallowed.
		return &DenyReason{Code: deny.Code, Message: NoCredentialMessage(d.NoCredential, d.verdict.RuleIDs, d.OtherUnfit)}
	}
	return deny
}

// NoCredentialMessage is the refusal text of a request whose allowed
// models have no gateway credential. ruleIDs are the rules proven to match
// the caller (AdminVerdict.RuleIDs; the plain refusal names
// AdminVerdict.BindRuleIDs); otherUnfit says another
// allowed model did not fit the request for a reason that is not a
// credential.
func NoCredentialMessage(aliases, ruleIDs []string, otherUnfit bool) string {
	msg := "The model your administrator allows for you (" + strings.Join(aliases, ", ") + ") has no gateway credential on this machine, so it cannot be used"
	if len(ruleIDs) > 0 {
		msg += " (rule " + strings.Join(ruleIDs, ", ") + ")"
	}
	msg += ". Ask your administrator to store the credential for it."
	if otherUnfit {
		msg += " Other models allowed for you do not fit this request."
	}
	return msg
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
