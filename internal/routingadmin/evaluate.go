// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package routingadmin evaluates routing.admin.rules and routing.admin.budgets
// for one model request: which aliases the caller may use, which default the
// rules give, whether a budget forces a downgrade, and whether a standalone
// managed device refuses the request. It is pure: the gateway supplies the
// verified caller, the classifier result and the spend ledger, and the
// routing engine (internal/routing/engine) picks the model from the verdict.
//
// On OSS a deny never blocks: it becomes a warning code. Only a standalone
// managed device (Policy.Managed) refuses, and there unknown facts fail
// closed.
//
// Reason codes (closed set): rule_deny:<id>, identity_unconfirmed:<fact>,
// budget_exceeded:<id>, budget_unavailable:<id>,
// budget_downgrade_unavailable:<id>, routing_admin_denied (denies);
// identity_unconfirmed, category_unknown, rule_deny_not_enforced:<id>,
// rule_allow_not_enforced:<ids>, budget_warn:<id>, budget_downgrade:<id>,
// budget_deny_not_enforced:<id>, budget_downgrade_unavailable:<id>,
// budget_downgrade_not_enforced:<id>, budget_spend_unknown:<id>,
// budget_cost_unknown:<id> (warnings; budget_cost_unknown:<id> is also a
// managed deny).
//
// Charge keys: user:<id>:*:<caller key> (each user of a * budget),
// user:<id>:=<sha12 of the subject> (a named user), group:<id>:<sha12 of the
// subject>, connector:<id>:<connector>. The caller key is the verified id
// with its kind (uid:1001, sid:S-1-5-...); subjects are hashed so no group
// or account name is stored.
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
	// managed device, and for the gateway owner on OSS. An unverified
	// caller is Maybe for every identity selector.
	Verified bool
	// Key is the stable caller id with its kind ("uid:1001",
	// "sid:S-1-5-21-..."), the id the usage store keeps. Empty when
	// unverified.
	Key string
	// Match reports whether groups, users or agents selectors name a
	// verified caller, with the matcher guardrail.profile_assignments uses.
	// It is only called with those keys set. Nil answers Maybe.
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
	Code    string // closed reason code (package doc)
	Message string // user-facing text
}

// Verdict is the rules and budgets outcome. The routing engine intersects
// Allowed with its own allowed set, picks the first compatible Force alias
// before anything else, uses Defaults in order, and runs Gate at every exit.
type Verdict struct {
	// Allowed is the intersection of the allow lists of the matching rules;
	// nil adds no limit, an empty non-nil slice allows no alias.
	Allowed []string
	// Bind is true when a matching rule set allow: a request that is not
	// routed must also use an allowed model (Gate). BindRuleIDs name them.
	Bind        bool
	BindRuleIDs []string
	// Defaults are the matching rules' defaults in list order.
	Defaults []string
	// Force is the downgrade alias list of an exceeded budget; ForceBudget
	// names the budget. On a managed device Gate holds every exit to it.
	Force       []string
	ForceBudget string
	// Deny is set only on a managed device.
	Deny     *Deny
	Warnings []string
	RuleIDs  []string
	// ChargeKeys are the budget keys this call counts against.
	ChargeKeys []string
}

type compiledRule struct {
	config.RoutingAdminRule
	connectors []string
	identity   config.ProfileMatch
	hasID      bool
	severity   int
}

type compiledBudget struct {
	config.RoutingBudget
	action    string
	downgrade []string
	subject   string // normalized connector, or the hashed user/group subject
}

// Policy is the compiled routing.admin rules and budgets of one config
// generation. Nil means none are configured. It shares nothing with the
// config it was compiled from.
type Policy struct {
	Managed bool
	rules   []compiledRule
	budgets []compiledBudget
}

// Compile returns the policy for rules and budgets, or nil when there are
// none (the engine then skips Evaluate). managed is cfg.StandaloneEnterprise().
// The input has passed config validation.
func Compile(rules []config.RoutingAdminRule, budgets []config.RoutingBudget, managed bool) *Policy {
	return CompileWith(rules, budgets, managed, nil)
}

// CompileWith is Compile with the subject hash of named-user and group
// budget keys (nil: an unkeyed SHA-256 prefix, device only; a fleet uses a
// keyed hash of the tenant secret so the store cannot read subjects).
func CompileWith(rules []config.RoutingAdminRule, budgets []config.RoutingBudget, managed bool, hash func(string) string) *Policy {
	if len(rules) == 0 && len(budgets) == 0 {
		return nil
	}
	if hash == nil {
		hash = shortHash
	}
	p := &Policy{Managed: managed}
	for _, r := range rules {
		r.Allow = clone(r.Allow)
		m := r.Match
		r.Match = config.RoutingAdminMatch{Groups: clone(m.Groups), Users: clone(m.Users), Connectors: clone(m.Connectors),
			Agents: clone(m.Agents), Categories: clone(m.Categories), SeverityAtLeast: m.SeverityAtLeast}
		c := compiledRule{RoutingAdminRule: r, hasID: r.Match.NamesIdentity(), severity: severityRank(r.Match.SeverityAtLeast)}
		for _, name := range r.Match.Connectors {
			c.connectors = append(c.connectors, config.NormalizeConnectorName(name))
		}
		c.identity = config.ProfileMatch{Groups: r.Match.Groups, Users: r.Match.Users, Agents: r.Match.Agents}
		p.rules = append(p.rules, c)
	}
	for _, b := range budgets {
		c := compiledBudget{RoutingBudget: b}
		c.action, c.downgrade = b.OnExceedAction()
		switch {
		case b.Scope == config.RoutingBudgetScopeConnector && b.Subject != config.RoutingBudgetSubjectAll:
			c.subject = config.NormalizeConnectorName(b.Subject)
		case b.Subject != config.RoutingBudgetSubjectAll:
			c.subject = hash(b.Subject)
		}
		p.budgets = append(p.budgets, c)
	}
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

// Evaluate applies the rules, then the budgets, to req. Every matching rule
// applies: a deny wins (a definite deny's message over an unconfirmed one),
// allow lists intersect, defaults keep list order. Every exceeded warn
// budget adds a warning; of the exceeded downgrade and (managed) deny
// budgets the strongest applies, deny over downgrade, list order breaking
// ties. ledger may be nil when no budget is configured.
func (p *Policy) Evaluate(req Request, ledger *Ledger, now time.Time) Verdict {
	var v Verdict
	if p == nil {
		return v
	}
	definiteDeny := false
	for i := range p.rules {
		rule := &p.rules[i]
		state, fact := p.ruleState(rule, req, &v)
		switch {
		case state == No:
			continue
		case state == Maybe && !p.Managed:
			v.warn("identity_unconfirmed")
			continue
		case state == Maybe && rule.IsDeny():
			if v.Deny == nil {
				v.Deny = &Deny{Code: "identity_unconfirmed:" + fact, Message: unconfirmedMessage(rule.ID)}
			}
			v.RuleIDs = append(v.RuleIDs, rule.ID)
			continue
		}
		v.RuleIDs = append(v.RuleIDs, rule.ID)
		if rule.IsDeny() {
			if !p.Managed {
				v.warn("rule_deny_not_enforced:" + rule.ID)
			} else if !definiteDeny {
				v.Deny, definiteDeny = &Deny{Code: "rule_deny:" + rule.ID, Message: denyMessage(rule.RoutingAdminRule)}, true
			}
			continue
		}
		if len(rule.Allow) > 0 {
			v.Bind = true
			v.BindRuleIDs = append(v.BindRuleIDs, rule.ID)
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
func (p *Policy) ruleState(rule *compiledRule, req Request, v *Verdict) (MatchState, string) {
	if len(rule.connectors) > 0 && (req.Connector == "" || !contains(rule.connectors, req.Connector)) {
		return No, ""
	}
	if len(rule.Match.Categories) > 0 {
		switch {
		case req.ClassifierFailed && p.Managed:
			// Fail closed: every category rule narrows when the category
			// is unknown (config validation keeps their allow lists
			// sharing an alias).
		case req.ClassifierFailed:
			v.warn("category_unknown")
			return No, ""
		case !containsFold(rule.Match.Categories, req.Category):
			return No, ""
		}
	}
	if rule.severity > 0 && (req.Severity == "" || severityRank(req.Severity) < rule.severity) {
		return No, ""
	}
	if rule.hasID {
		return identityState(req.Caller, rule.identity)
	}
	return Yes, ""
}

func identityState(c Caller, m config.ProfileMatch) (MatchState, string) {
	if !c.Verified {
		return Maybe, "unverified"
	}
	if c.Match == nil {
		return Maybe, "identity"
	}
	s := c.Match(m)
	if s == Yes {
		return Yes, ""
	}
	fact := c.Unconfirmed
	if fact == "" {
		fact = "identity"
	}
	return s, fact
}

func (p *Policy) applyBudgets(req Request, ledger *Ledger, now time.Time, v *Verdict) {
	var strongest *compiledBudget
	for i := range p.budgets {
		b := &p.budgets[i]
		key, state, fact := chargeKey(b, req)
		if state == No {
			continue
		}
		if state == Maybe && !p.Managed {
			v.warn("identity_unconfirmed")
			continue
		}
		if state == Maybe && key == "" {
			// A * user budget for a caller without a verified id cannot be
			// counted: refuse a deny budget rather than spend without one.
			if b.action == config.RoutingBudgetOnExceedDeny {
				v.Deny = &Deny{Code: "identity_unconfirmed:" + fact, Message: unconfirmedMessage(b.ID)}
				return
			}
			v.warn("budget_spend_unknown:" + b.ID)
			continue
		}
		// A Maybe caller of a named budget is never charged to it (that
		// would spend another subject's budget); it is held to the
		// subject's limit only when that limit is reached.
		if state == Yes {
			v.ChargeKeys = append(v.ChargeKeys, key)
		}
		spend, seeded := ledger.Spend(key, b.Period, now)
		if !seeded {
			if p.Managed && b.action == config.RoutingBudgetOnExceedDeny {
				v.Deny = &Deny{Code: "budget_unavailable:" + b.ID, Message: "Model use is paused: DefenseClaw is still loading the spend of budget " + b.ID + ". Try again shortly or contact your administrator."}
				return
			}
			v.warn("budget_spend_unknown:" + b.ID)
			continue
		}
		if ledger.Unknown(key, b.Period, now) {
			// A call of unknown cost: the spend is not known (never 0).
			// Managed treats the budget as over its limit (deny refuses,
			// downgrade forces); OSS warns.
			if !p.Managed {
				v.warn("budget_cost_unknown:" + b.ID)
				continue
			}
			if b.action == config.RoutingBudgetOnExceedDeny {
				v.Deny = &Deny{Code: "budget_cost_unknown:" + b.ID, Message: "The cost of a model call for budget " + b.ID + " could not be computed, so the budget cannot tell how much is left; ask your administrator to price the model (observability.pricing)."}
				return
			}
			if b.action == config.RoutingBudgetOnExceedWarn {
				v.warn("budget_cost_unknown:" + b.ID)
				continue
			}
		} else if spend < b.LimitUSD {
			continue
		}
		switch {
		case b.action == config.RoutingBudgetOnExceedWarn:
			v.warn("budget_warn:" + b.ID)
			continue
		case b.action == config.RoutingBudgetOnExceedDeny && !p.Managed:
			// OSS reports a deny budget and keeps routing: a downgrade
			// budget that is also over its limit still applies.
			v.warn("budget_deny_not_enforced:" + b.ID)
			continue
		case b.action == config.RoutingBudgetOnExceedDeny && state == Maybe:
			v.Deny = &Deny{Code: "identity_unconfirmed:" + fact, Message: unconfirmedMessage(b.ID)}
			return
		}
		if strongest == nil || actionRank(b.action) > actionRank(strongest.action) {
			strongest = b
		}
	}
	if strongest == nil {
		return
	}
	b := strongest
	switch b.action {
	case config.RoutingBudgetOnExceedDeny:
		v.Deny = &Deny{Code: "budget_exceeded:" + b.ID, Message: "Your model budget " + b.ID + " is used up for this " + b.Period + ". It resets at " + NextReset(b.Period, now).Format(time.RFC3339) + "."}
	case config.RoutingBudgetOnExceedDowngrade:
		force := clone(b.downgrade)
		if v.Allowed != nil {
			force = intersect(force, v.Allowed)
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

// chargeKey returns the budget's key for req and whether the subject names
// the caller. A * user budget for an unverified caller has no key (Maybe).
func chargeKey(b *compiledBudget, req Request) (string, MatchState, string) {
	switch b.Scope {
	case config.RoutingBudgetScopeConnector:
		if req.Connector == "" || (b.subject != "" && b.subject != req.Connector) {
			return "", No, ""
		}
		return "connector:" + b.ID + ":" + req.Connector, Yes, ""
	case config.RoutingBudgetScopeUser:
		if b.Subject == config.RoutingBudgetSubjectAll {
			if !req.Caller.Verified || req.Caller.Key == "" {
				return "", Maybe, "unverified"
			}
			return "user:" + b.ID + ":*:" + req.Caller.Key, Yes, ""
		}
		state, fact := identityState(req.Caller, config.ProfileMatch{Users: []string{b.Subject}})
		return "user:" + b.ID + ":=" + b.subject, state, fact
	case config.RoutingBudgetScopeGroup:
		state, fact := identityState(req.Caller, config.ProfileMatch{Groups: []string{b.Subject}})
		return "group:" + b.ID + ":" + b.subject, state, fact
	}
	return "", No, ""
}

// Target is a provider and model a request goes to. The engine passes the
// canonical model id (a decoded Bedrock id, not a percent-encoded ARN).
type Target struct{ Provider, Model string }

// Gate is the admin check every forwarded call passes, routed or not
// (fallback to the original, signed bodies, count_tokens, retry on the
// original upstream). target is where the call goes; catalog maps
// routing.models aliases to their target. It returns a refusal on a managed
// device, and on OSS at most a warning code.
func Gate(v Verdict, target Target, catalog map[string]Target, managed bool) (*Deny, string) {
	if v.Deny != nil {
		return v.Deny, ""
	}
	if len(v.Force) > 0 && !targetIn(v.Force, target, catalog) {
		if !managed {
			return nil, "budget_downgrade_not_enforced:" + v.ForceBudget
		}
		return &Deny{Code: "budget_downgrade_unavailable:" + v.ForceBudget, Message: "Your model budget " + v.ForceBudget + " is used up; this request can only use its fallback models."}, ""
	}
	if !v.Bind || targetIn(v.Allowed, target, catalog) {
		return nil, ""
	}
	if !managed {
		return nil, "rule_allow_not_enforced:" + strings.Join(v.BindRuleIDs, ",")
	}
	return &Deny{Code: "routing_admin_denied", Message: "Your administrator does not allow this model for this request (rule " + strings.Join(v.BindRuleIDs, ", ") + ")."}, ""
}

func targetIn(aliases []string, target Target, catalog map[string]Target) bool {
	for _, alias := range aliases {
		if t, ok := catalog[alias]; ok && strings.EqualFold(strings.TrimSpace(t.Provider), strings.TrimSpace(target.Provider)) && t.Model == target.Model {
			return true
		}
	}
	return false
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

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
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

// intersect keeps the entries of a found in b, in a's order, reusing a;
// a nil a means "no limit yet" and returns a copy of b.
func intersect(a, b []string) []string {
	if a == nil {
		return append(make([]string, 0, len(b)), b...)
	}
	out := a[:0]
	for _, x := range a {
		if contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
