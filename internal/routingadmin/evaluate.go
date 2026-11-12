// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package routingadmin evaluates routing.admin.rules and routing.admin.budgets
// for one model request: which aliases the caller may use, which default the
// rules give, whether a budget forces a downgrade, and whether a standalone
// managed device refuses the request. It is pure: the gateway supplies the
// verified caller, the classifier result and the spend ledger, and the
// routing engine (internal/routing) picks the model from the verdict.
//
// On OSS a deny never blocks: it becomes a warning code. Only a standalone
// managed device (Policy.Managed) refuses, and there unknown facts fail
// closed.
package routingadmin

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// MatchState is the outcome of an identity selector against the caller.
type MatchState uint8

const (
	// No: the facts prove the selector does not name the caller.
	No MatchState = iota
	// Maybe: the facts cannot prove it either way (unverified caller,
	// failed directory lookup, unknown or unconfirmed groups).
	Maybe
	// Yes: the facts prove the selector names the caller.
	Yes
)

// Caller is the verified identity of the request. X-User-Id and other
// request headers never fill it.
type Caller struct {
	// Verified is true for a kernel peer or a per-user credential on a
	// managed device, and for the gateway owner on OSS.
	Verified bool
	// Key is the stable caller id with its kind ("uid:1001",
	// "sid:S-1-5-21-..."), the same id the usage store keeps. Empty when
	// unverified.
	Key string
	// Match reports whether groups, users or agents selectors name the
	// caller, with the matcher guardrail.profile_assignments uses. It is
	// only called with those three keys set. Nil answers Maybe for a
	// verified caller and No otherwise.
	Match func(config.ProfileMatch) MatchState
	// Unconfirmed names the fact a Maybe comes from (for example groups),
	// for the identity_unconfirmed reason code.
	Unconfirmed string
}

// Request is what Evaluate needs about one forwarded model call.
type Request struct {
	Caller    Caller
	Connector string // normalized connector name, from the listener or its credential
	Category  string // classifier category, "" when none
	// ClassifierFailed is true when the classifier errored, timed out or
	// its breaker was open (not for "no match" or low confidence).
	ClassifierFailed bool
	// Severity is the pre-call guardrail severity ("" when the listener runs
	// no guardrail, as route-only does).
	Severity string
}

// Deny is a refusal on a managed device.
type Deny struct {
	// Code is a closed reason code: rule_deny:<id>, identity_unconfirmed:<fact>,
	// budget_exceeded:<id>, budget_unavailable:<id>,
	// budget_downgrade_unavailable:<id>, routing_admin_denied.
	Code string
	// Message is the user-facing text.
	Message string
}

// Verdict is the rules and budgets outcome. The routing engine intersects
// Allowed with its own allowed set, picks Force (first compatible alias)
// before anything else, uses Defaults in order, and runs Gate at every exit.
type Verdict struct {
	// Allowed is the intersection of the allow lists of the matching rules;
	// nil adds no limit, an empty non-nil slice allows no alias.
	Allowed []string
	// Bind is true when a matching rule set allow: a request that is not
	// routed must also use an allowed model (Gate).
	Bind bool
	// Defaults are the matching rules' defaults in list order.
	Defaults []string
	// Force is the downgrade alias list of an exceeded budget; ForceBudget
	// names the budget.
	Force       []string
	ForceBudget string
	// Deny is set only on a managed device.
	Deny     *Deny
	Warnings []string
	RuleIDs  []string
	// ChargeKeys are the budget keys this call counts against.
	ChargeKeys []string
}

// Policy is the compiled routing.admin rules and budgets of one config
// generation. Nil means none are configured.
type Policy struct {
	Managed bool
	rules   []config.RoutingAdminRule
	budgets []config.RoutingBudget
}

// Compile returns the policy for rules and budgets, or nil when there are
// none (the engine then skips Evaluate). managed is cfg.StandaloneEnterprise().
// The input has passed config validation.
func Compile(rules []config.RoutingAdminRule, budgets []config.RoutingBudget, managed bool) *Policy {
	if len(rules) == 0 && len(budgets) == 0 {
		return nil
	}
	p := &Policy{Managed: managed}
	p.rules = append(p.rules, rules...)
	p.budgets = append(p.budgets, budgets...)
	return p
}

// BudgetIDs lists the budget ids, for the ledger seed.
func (p *Policy) BudgetIDs() []string {
	if p == nil {
		return nil
	}
	ids := make([]string, 0, len(p.budgets))
	for _, b := range p.budgets {
		ids = append(ids, b.ID)
	}
	return ids
}

// Evaluate applies the rules, then the budgets, to req. Every exceeded warn
// budget adds a warning; of the exceeded downgrade and (managed) deny
// budgets the strongest applies, deny over downgrade, list order breaking
// ties. ledger may be nil
// when no budget is configured.
func (p *Policy) Evaluate(req Request, ledger *Ledger, now time.Time) Verdict {
	var v Verdict
	if p == nil {
		return v
	}
	for _, rule := range p.rules {
		state, fact := p.ruleState(rule, req, &v)
		if state == No {
			continue
		}
		if state == Maybe {
			if !p.Managed {
				v.warn("identity_unconfirmed")
				continue
			}
			if rule.IsDeny() {
				if v.Deny == nil {
					v.Deny = &Deny{Code: "identity_unconfirmed:" + fact, Message: unconfirmedMessage(rule.ID)}
				}
				v.RuleIDs = append(v.RuleIDs, rule.ID)
				continue
			}
		}
		v.RuleIDs = append(v.RuleIDs, rule.ID)
		if rule.IsDeny() {
			if !p.Managed {
				v.warn("rule_deny_not_enforced:" + rule.ID)
			} else if v.Deny == nil {
				v.Deny = &Deny{Code: "rule_deny:" + rule.ID, Message: denyMessage(rule)}
			}
			continue
		}
		if len(rule.Allow) > 0 {
			v.Bind = true
			v.Allowed = intersect(v.Allowed, rule.Allow)
		}
		if rule.Default != "" {
			v.Defaults = append(v.Defaults, rule.Default)
		}
	}
	if v.Deny != nil {
		return v
	}
	p.applyBudgets(req, ledger, now, &v)
	return v
}

// ruleState matches rule against req: AND across keys, Maybe when an
// identity fact is unknown.
func (p *Policy) ruleState(rule config.RoutingAdminRule, req Request, v *Verdict) (MatchState, string) {
	m := rule.Match
	state, fact := Yes, ""
	if len(m.Connectors) > 0 && !connectorMatches(m.Connectors, req.Connector) {
		return No, ""
	}
	if len(m.Categories) > 0 {
		switch {
		case req.ClassifierFailed && p.Managed:
			// Fail closed: every category rule narrows when the category
			// is unknown (validation keeps the intersection non-empty).
		case req.ClassifierFailed:
			v.warn("category_unknown")
			return No, ""
		case !containsFold(m.Categories, req.Category):
			return No, ""
		}
	}
	if min := m.SeverityAtLeast; strings.TrimSpace(min) != "" {
		if req.Severity == "" || severityRank(req.Severity) < severityRank(min) {
			return No, ""
		}
	}
	if m.NamesIdentity() {
		switch s, f := identityState(req.Caller, config.ProfileMatch{Groups: m.Groups, Users: m.Users, Agents: m.Agents}); s {
		case No:
			return No, ""
		case Maybe:
			state, fact = Maybe, f
		}
	}
	return state, fact
}

func identityState(c Caller, m config.ProfileMatch) (MatchState, string) {
	if !c.Verified {
		return Maybe, "unverified"
	}
	if c.Match == nil {
		return Maybe, "identity"
	}
	s := c.Match(m)
	fact := c.Unconfirmed
	if fact == "" {
		fact = "identity"
	}
	return s, fact
}

func (p *Policy) applyBudgets(req Request, ledger *Ledger, now time.Time, v *Verdict) {
	strongest, strongestBudget := 0, config.RoutingBudget{}
	for _, b := range p.budgets {
		key, state, fact := chargeKey(b, req)
		switch state {
		case No:
			continue
		case Maybe:
			if !p.Managed {
				v.warn("identity_unconfirmed")
				continue
			}
			if key == "" {
				// A per-user budget cannot be attributed to an unknown
				// caller: refuse rather than spend without a limit.
				if action, _ := b.OnExceedAction(); action == config.RoutingBudgetOnExceedDeny {
					v.Deny = &Deny{Code: "identity_unconfirmed:" + fact, Message: unconfirmedMessage(b.ID)}
					return
				}
				v.warn("budget_spend_unknown:" + b.ID)
				continue
			}
		}
		v.ChargeKeys = append(v.ChargeKeys, key)
		action, _ := b.OnExceedAction()
		spend, seeded := ledger.Spend(key, b.Period, now)
		if !seeded {
			if p.Managed && action == config.RoutingBudgetOnExceedDeny {
				v.Deny = &Deny{Code: "budget_unavailable:" + b.ID, Message: "Model use is paused: DefenseClaw is still loading the spend of budget " + b.ID + ". Try again shortly or contact your administrator."}
				return
			}
			v.warn("budget_spend_unknown:" + b.ID)
			continue
		}
		if spend < b.LimitUSD {
			continue
		}
		switch {
		case action == config.RoutingBudgetOnExceedWarn:
			v.warn("budget_warn:" + b.ID)
			continue
		case action == config.RoutingBudgetOnExceedDeny && !p.Managed:
			// OSS reports a deny budget and keeps routing: a downgrade
			// budget that is also over its limit still applies.
			v.warn("budget_deny_not_enforced:" + b.ID)
			continue
		}
		if rank := actionRank(action); rank > strongest {
			strongest, strongestBudget = rank, b
		}
	}
	if strongest == 0 {
		return
	}
	b := strongestBudget
	action, aliases := b.OnExceedAction()
	switch action {
	case config.RoutingBudgetOnExceedDeny:
		v.Deny = &Deny{Code: "budget_exceeded:" + b.ID, Message: "Your model budget " + b.ID + " is used up for this " + b.Period + ". It resets at " + NextReset(b.Period, now).Format(time.RFC3339) + "."}
	case config.RoutingBudgetOnExceedDowngrade:
		force := aliases
		if v.Allowed != nil {
			force = intersect(append([]string(nil), aliases...), v.Allowed)
		}
		if len(force) == 0 {
			if p.Managed {
				v.Deny = &Deny{Code: "budget_downgrade_unavailable:" + b.ID, Message: "Your model budget " + b.ID + " is used up and none of its fallback models is allowed for this request."}
				return
			}
			v.warn("budget_downgrade_unavailable:" + b.ID)
			return
		}
		v.Force, v.ForceBudget = force, b.ID
		v.warn("budget_downgrade:" + b.ID)
	}
}

// chargeKey returns the budget's key for req, or "" with Maybe when the
// subject cannot be attributed.
func chargeKey(b config.RoutingBudget, req Request) (string, MatchState, string) {
	switch b.Scope {
	case config.RoutingBudgetScopeConnector:
		if b.Subject != config.RoutingBudgetSubjectAll && config.NormalizeConnectorName(b.Subject) != req.Connector {
			return "", No, ""
		}
		if req.Connector == "" {
			return "", No, ""
		}
		return "connector:" + b.ID + ":" + req.Connector, Yes, ""
	case config.RoutingBudgetScopeUser:
		if b.Subject == config.RoutingBudgetSubjectAll {
			if !req.Caller.Verified || req.Caller.Key == "" {
				return "", Maybe, "unverified"
			}
			return "user:" + b.ID + ":*:" + shortHash(req.Caller.Key), Yes, ""
		}
		state, fact := identityState(req.Caller, config.ProfileMatch{Users: []string{b.Subject}})
		if state == No {
			return "", No, ""
		}
		return "user:" + b.ID + ":" + shortHash(b.Subject), state, fact
	case config.RoutingBudgetScopeGroup:
		state, fact := identityState(req.Caller, config.ProfileMatch{Groups: []string{b.Subject}})
		if state == No {
			return "", No, ""
		}
		return "group:" + b.ID + ":" + shortHash(b.Subject), state, fact
	}
	return "", No, ""
}

// Target is a provider and model a request goes to.
type Target struct{ Provider, Model string }

// Gate is the admin check every forwarded call passes, routed or not
// (fallback to the original, signed bodies, count_tokens, retry on the
// original upstream). original is where the call goes when no alias is
// used; catalog maps routing.models aliases to their target. It returns a
// refusal on a managed device, and on OSS at most a warning code.
func Gate(v Verdict, original Target, catalog map[string]Target, managed bool) (*Deny, string) {
	if v.Deny != nil {
		return v.Deny, ""
	}
	if !v.Bind {
		return nil, ""
	}
	for _, alias := range v.Allowed {
		if t, ok := catalog[alias]; ok && sameTarget(t, original) {
			return nil, ""
		}
	}
	if !managed {
		return nil, "rule_allow_not_enforced:" + strings.Join(v.RuleIDs, ",")
	}
	return &Deny{Code: "routing_admin_denied", Message: "Your administrator does not allow this model for this request (rule " + strings.Join(v.RuleIDs, ", ") + ")."}, ""
}

func sameTarget(a, b Target) bool {
	return strings.EqualFold(strings.TrimSpace(a.Provider), strings.TrimSpace(b.Provider)) && a.Model == b.Model
}

func (v *Verdict) warn(code string) {
	for _, w := range v.Warnings {
		if w == code {
			return
		}
	}
	v.Warnings = append(v.Warnings, code)
}

func denyMessage(rule config.RoutingAdminRule) string {
	if m := strings.TrimSpace(rule.Message); m != "" {
		return m
	}
	return "Your administrator does not allow this request (rule " + rule.ID + ")."
}

func unconfirmedMessage(id string) string {
	return "DefenseClaw cannot confirm who you are for the administrator's routing policy (" + id + "); try again, or contact your administrator."
}

func actionRank(action string) int {
	switch action {
	case config.RoutingBudgetOnExceedWarn:
		return 1
	case config.RoutingBudgetOnExceedDowngrade:
		return 2
	case config.RoutingBudgetOnExceedDeny:
		return 3
	}
	return 0
}

func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return 0
}

func connectorMatches(list []string, connector string) bool {
	if connector == "" {
		return false
	}
	for _, c := range list {
		if config.NormalizeConnectorName(c) == connector {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	if v == "" {
		return false
	}
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// intersect keeps the entries of a found in b, in a's order; a nil a means
// "no limit yet" and returns a copy of b.
func intersect(a, b []string) []string {
	if a == nil {
		return append(make([]string, 0, len(b)), b...)
	}
	out := a[:0]
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
