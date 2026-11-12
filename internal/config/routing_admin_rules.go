// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// routing.admin.rules, routing.admin.budgets and routing.admin.visibility
// (1.0.10). The organization floor keys of routing.admin (allowed_aliases,
// denied_providers, default_alias, categories, allow_user_override,
// locked) live in routing_policy.go; these three are the per-subject rules,
// the spend budgets and who may read usage. All of them only tighten what
// the floor allows, and a deny or a budget deny takes effect only on a
// standalone managed device: on OSS they are reported, never enforced.

// Values of routing.admin.rules[].action.
const (
	RoutingRuleActionConstrain = "constrain"
	RoutingRuleActionDeny      = "deny"
)

// Values of routing.admin.budgets[].scope.
const (
	RoutingBudgetScopeUser      = "user"
	RoutingBudgetScopeGroup     = "group"
	RoutingBudgetScopeConnector = "connector"
)

// Values of routing.admin.budgets[].period. Windows are UTC calendar
// windows; a week starts Monday 00:00 UTC.
const (
	RoutingBudgetPeriodDay   = "day"
	RoutingBudgetPeriodWeek  = "week"
	RoutingBudgetPeriodMonth = "month"
)

// Values of routing.admin.budgets[].on_exceed. A downgrade is written
// downgrade:<alias>[,<alias>...]; the first alias the request can use wins.
const (
	RoutingBudgetOnExceedWarn      = "warn"
	RoutingBudgetOnExceedDeny      = "deny"
	RoutingBudgetOnExceedDowngrade = "downgrade"
)

// Values of routing.admin.visibility.users_see. Administrators always see
// every subject's usage.
const (
	RoutingUsersSeeOwn  = "own"
	RoutingUsersSeeNone = "none"
)

// RoutingBudgetSubjectAll, as a user or connector budget subject, gives
// every user (or connector) its own limit.
const RoutingBudgetSubjectAll = "*"

// Bounds of the rules and budgets lists.
const (
	RoutingAdminMaxRules        = 256
	RoutingAdminMaxBudgets      = 64
	RoutingAdminMessageMaxBytes = 512
	RoutingBudgetMaxLimitUSD    = 1e7
)

var routingAdminIDPattern = lazyregexp.New(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// RoutingAdminRule is one entry of routing.admin.rules. Every rule whose
// Match selects the request applies: a deny wins, allow lists intersect,
// and the first matching rule whose Default survives gives the default.
type RoutingAdminRule struct {
	// ID names the rule in records, explain and the bundle receipt.
	ID string `mapstructure:"id" yaml:"id"`
	// Match selects the requests the rule applies to.
	Match RoutingAdminMatch `mapstructure:"match" yaml:"match"`
	// Action is constrain (also "") or deny.
	Action string `mapstructure:"action" yaml:"action,omitempty"`
	// Allow limits routing to these routing.models aliases; it also binds a
	// request that is not routed: its own model must be one of them.
	Allow []string `mapstructure:"allow" yaml:"allow,omitempty"`
	// Default is the alias used when nothing else the caller may use was
	// chosen. It must be in Allow when Allow is set.
	Default string `mapstructure:"default" yaml:"default,omitempty"`
	// Message is the refusal text of a deny rule (at most 512 printable
	// bytes).
	Message string `mapstructure:"message" yaml:"message,omitempty"`
}

// RoutingAdminMatch selects requests. Set keys combine with AND, the
// values of one key with OR, and at least one key must be set. Groups,
// Users and Agents compare against a verified caller only, with the matcher
// guardrail.profile_assignments uses.
type RoutingAdminMatch struct {
	Groups     []string `mapstructure:"groups"     yaml:"groups,omitempty"`
	Users      []string `mapstructure:"users"      yaml:"users,omitempty"`
	Connectors []string `mapstructure:"connectors" yaml:"connectors,omitempty"`
	Agents     []string `mapstructure:"agents"     yaml:"agents,omitempty"`
	// Categories are classifier categories (routing.categories keys).
	Categories []string `mapstructure:"categories" yaml:"categories,omitempty"`
	// SeverityAtLeast is LOW, MEDIUM, HIGH or CRITICAL: the request's
	// pre-call guardrail severity must be at least this. The route-only
	// listener runs no guardrail, so such a rule never applies there.
	SeverityAtLeast string `mapstructure:"severity_at_least" yaml:"severity_at_least,omitempty"`
}

// Identity returns the identity and connector selectors as a
// ProfileMatch, for the gateway's assignment matcher.
func (m RoutingAdminMatch) Identity() ProfileMatch {
	return ProfileMatch{Groups: m.Groups, Users: m.Users, Connectors: m.Connectors, Agents: m.Agents}
}

// Empty reports whether no selector key is set.
func (m RoutingAdminMatch) Empty() bool {
	return m.Identity().Empty() && len(m.Categories) == 0 && strings.TrimSpace(m.SeverityAtLeast) == ""
}

// NamesIdentity reports whether the match needs a verified caller.
func (m RoutingAdminMatch) NamesIdentity() bool {
	return len(m.Groups) > 0 || len(m.Users) > 0 || len(m.Agents) > 0
}

// IsDeny reports whether the rule refuses the requests it matches.
func (r RoutingAdminRule) IsDeny() bool {
	return strings.TrimSpace(r.Action) == RoutingRuleActionDeny
}

// RoutingBudget is one entry of routing.admin.budgets. Spend is counted per
// device from the computed cost of agent calls (the price table in
// observability.pricing); reported cost is never counted.
type RoutingBudget struct {
	ID string `mapstructure:"id" yaml:"id"`
	// Scope is user, group or connector.
	Scope string `mapstructure:"scope" yaml:"scope"`
	// Subject is, for user, a users entry or * (each user its own limit);
	// for group, a groups entry (one pooled limit); for connector, a
	// connector name or * (each connector its own limit).
	Subject string `mapstructure:"subject" yaml:"subject"`
	// Period is day, week or month (UTC calendar windows).
	Period string `mapstructure:"period" yaml:"period"`
	// LimitUSD is the spend at which OnExceed applies.
	LimitUSD float64 `mapstructure:"limit_usd" yaml:"limit_usd"`
	// OnExceed is warn, deny or downgrade:<alias>[,<alias>...].
	OnExceed string `mapstructure:"on_exceed" yaml:"on_exceed"`
}

// OnExceedAction returns warn, deny or downgrade and, for downgrade, the
// aliases in order.
func (b RoutingBudget) OnExceedAction() (string, []string) {
	value := strings.TrimSpace(b.OnExceed)
	if rest, ok := strings.CutPrefix(value, RoutingBudgetOnExceedDowngrade+":"); ok {
		var aliases []string
		for _, alias := range strings.Split(rest, ",") {
			aliases = append(aliases, strings.TrimSpace(alias))
		}
		return RoutingBudgetOnExceedDowngrade, aliases
	}
	return value, nil
}

// RoutingVisibility is routing.admin.visibility.
type RoutingVisibility struct {
	// UsersSee is own (also "": a user reads only their own usage) or none
	// (only administrators read usage).
	UsersSee string `mapstructure:"users_see" yaml:"users_see,omitempty"`
}

// EffectiveUsersSee returns UsersSee with its default.
func (v *RoutingVisibility) EffectiveUsersSee() string {
	if v == nil || strings.TrimSpace(v.UsersSee) == "" {
		return RoutingUsersSeeOwn
	}
	return strings.TrimSpace(v.UsersSee)
}

// ValidateRoutingAdminRules checks routing.admin.rules, budgets and
// visibility against the routing.models aliases. The error names the key.
func ValidateRoutingAdminRules(rules []RoutingAdminRule, budgets []RoutingBudget, visibility *RoutingVisibility, aliases map[string]struct{}) error {
	if len(rules) > RoutingAdminMaxRules {
		return settingErrorAt("routing.admin.rules", fmt.Errorf("routing.admin.rules must not have more than %d entries", RoutingAdminMaxRules))
	}
	seen := map[string]struct{}{}
	for i, rule := range rules {
		at := fmt.Sprintf("routing.admin.rules[%d]", i)
		if err := validateRoutingAdminRule(at, rule, aliases); err != nil {
			return err
		}
		if _, dup := seen[rule.ID]; dup {
			return settingErrorAt(at+".id", fmt.Errorf("%s.id %q is used by an earlier rule; rule ids must be unique", at, rule.ID))
		}
		seen[rule.ID] = struct{}{}
	}
	if len(budgets) > RoutingAdminMaxBudgets {
		return settingErrorAt("routing.admin.budgets", fmt.Errorf("routing.admin.budgets must not have more than %d entries", RoutingAdminMaxBudgets))
	}
	seen = map[string]struct{}{}
	for i, budget := range budgets {
		at := fmt.Sprintf("routing.admin.budgets[%d]", i)
		if err := validateRoutingBudget(at, budget, aliases); err != nil {
			return err
		}
		if _, dup := seen[budget.ID]; dup {
			return settingErrorAt(at+".id", fmt.Errorf("%s.id %q is used by an earlier budget; budget ids must be unique", at, budget.ID))
		}
		seen[budget.ID] = struct{}{}
	}
	if visibility != nil {
		switch strings.TrimSpace(visibility.UsersSee) {
		case "", RoutingUsersSeeOwn, RoutingUsersSeeNone:
		default:
			return settingErrorAt("routing.admin.visibility.users_see",
				fmt.Errorf("routing.admin.visibility.users_see %q must be own or none", visibility.UsersSee))
		}
	}
	return nil
}

func validateRoutingAdminRule(at string, rule RoutingAdminRule, aliases map[string]struct{}) error {
	if !routingAdminIDPattern.MatchString(rule.ID) {
		return settingErrorAt(at+".id", fmt.Errorf("%s.id %q must be lowercase letters, digits, - or _, at most 64, starting with a letter or digit", at, rule.ID))
	}
	if err := validateRoutingAdminMatch(at+".match", rule.Match); err != nil {
		return err
	}
	if err := validateRoutingAdminMessage(at+".message", rule.Message); err != nil {
		return err
	}
	switch strings.TrimSpace(rule.Action) {
	case RoutingRuleActionDeny:
		if rule.Allow != nil || rule.Default != "" {
			return settingErrorAt(at, fmt.Errorf("%s is a deny rule; remove allow and default (a deny rule refuses the requests it matches)", at))
		}
		return nil
	case "", RoutingRuleActionConstrain:
	default:
		return settingErrorAt(at+".action", fmt.Errorf("%s.action %q must be constrain or deny", at, rule.Action))
	}
	if rule.Message != "" {
		return settingErrorAt(at+".message", fmt.Errorf("%s.message is only used by a deny rule; remove it or set action: deny", at))
	}
	if rule.Allow != nil && len(rule.Allow) == 0 {
		return settingErrorAt(at+".allow", fmt.Errorf("%s.allow is empty; leave it out for no limit, or use action: deny to refuse", at))
	}
	if len(rule.Allow) == 0 && rule.Default == "" {
		return settingErrorAt(at, fmt.Errorf("%s changes nothing; set allow or default, or action: deny", at))
	}
	allowed := map[string]struct{}{}
	for j, alias := range rule.Allow {
		if _, ok := aliases[alias]; !ok {
			return settingErrorAt(fmt.Sprintf("%s.allow[%d]", at, j), fmt.Errorf("%s.allow[%d] %q is not an alias in routing.models", at, j, alias))
		}
		allowed[alias] = struct{}{}
	}
	if rule.Default != "" {
		if _, ok := aliases[rule.Default]; !ok {
			return settingErrorAt(at+".default", fmt.Errorf("%s.default %q is not an alias in routing.models", at, rule.Default))
		}
		if _, ok := allowed[rule.Default]; len(allowed) > 0 && !ok {
			return settingErrorAt(at+".default", fmt.Errorf("%s.default %q is not in its allow list", at, rule.Default))
		}
	}
	return nil
}

func validateRoutingAdminMatch(at string, m RoutingAdminMatch) error {
	if m.Empty() {
		return settingErrorAt(at, fmt.Errorf("%s needs at least one of groups, users, connectors, agents, categories or severity_at_least", at))
	}
	for _, selector := range []struct {
		key    string
		values []string
	}{{"groups", m.Groups}, {"users", m.Users}, {"connectors", m.Connectors}} {
		for _, value := range selector.values {
			if strings.TrimSpace(value) == "" {
				return settingErrorAt(at+"."+selector.key, fmt.Errorf("%s.%s: an entry is empty; name a %s or remove the entry", at, selector.key, strings.TrimSuffix(selector.key, "s")))
			}
		}
	}
	for _, agent := range m.Agents {
		if !agentIdentityPattern.MatchString(agent) {
			return settingErrorAt(at+".agents", fmt.Errorf("%s.agents: %q is not an agent identity (want agt- followed by 16 hex digits)", at, agent))
		}
	}
	for _, category := range m.Categories {
		if !routingAdminCategoryPattern.MatchString(category) {
			return settingErrorAt(at+".categories", fmt.Errorf("%s.categories: %q must be lowercase letters, digits, _, . or -, at most 64", at, category))
		}
	}
	if s := m.SeverityAtLeast; strings.TrimSpace(s) != "" && canonicalGuardrailLevel(s) == "" {
		return settingErrorAt(at+".severity_at_least", fmt.Errorf("%s.severity_at_least %q must be LOW, MEDIUM, HIGH or CRITICAL", at, s))
	}
	return nil
}

// routingAdminCategoryPattern is the category name form routing.categories
// uses.
var routingAdminCategoryPattern = lazyregexp.New(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func validateRoutingAdminMessage(at, message string) error {
	if len(message) > RoutingAdminMessageMaxBytes {
		return settingErrorAt(at, fmt.Errorf("%s must not exceed %d bytes", at, RoutingAdminMessageMaxBytes))
	}
	for _, r := range message {
		if !unicode.IsPrint(r) {
			return settingErrorAt(at, fmt.Errorf("%s must be printable text on one line", at))
		}
	}
	return nil
}

func validateRoutingBudget(at string, b RoutingBudget, aliases map[string]struct{}) error {
	if !routingAdminIDPattern.MatchString(b.ID) {
		return settingErrorAt(at+".id", fmt.Errorf("%s.id %q must be lowercase letters, digits, - or _, at most 64, starting with a letter or digit", at, b.ID))
	}
	subject := strings.TrimSpace(b.Subject)
	if subject == "" || subject != b.Subject {
		return settingErrorAt(at+".subject", fmt.Errorf("%s.subject must be set, without surrounding spaces", at))
	}
	switch b.Scope {
	case RoutingBudgetScopeUser:
	case RoutingBudgetScopeGroup:
		if subject == RoutingBudgetSubjectAll {
			return settingErrorAt(at+".subject", fmt.Errorf("%s.subject: a group budget names one group; use scope user with subject * for a limit per user", at))
		}
	case RoutingBudgetScopeConnector:
		if subject != RoutingBudgetSubjectAll && NormalizeConnectorName(subject) != subject {
			return settingErrorAt(at+".subject", fmt.Errorf("%s.subject %q must be a connector name such as codex or claudecode, or *", at, subject))
		}
	default:
		return settingErrorAt(at+".scope", fmt.Errorf("%s.scope %q must be user, group or connector", at, b.Scope))
	}
	switch b.Period {
	case RoutingBudgetPeriodDay, RoutingBudgetPeriodWeek, RoutingBudgetPeriodMonth:
	default:
		return settingErrorAt(at+".period", fmt.Errorf("%s.period %q must be day, week or month", at, b.Period))
	}
	if math.IsNaN(b.LimitUSD) || math.IsInf(b.LimitUSD, 0) || b.LimitUSD <= 0 || b.LimitUSD > RoutingBudgetMaxLimitUSD {
		return settingErrorAt(at+".limit_usd", fmt.Errorf("%s.limit_usd must be more than 0 and at most %.0f", at, RoutingBudgetMaxLimitUSD))
	}
	action, downgrade := b.OnExceedAction()
	switch action {
	case RoutingBudgetOnExceedWarn, RoutingBudgetOnExceedDeny:
	case RoutingBudgetOnExceedDowngrade:
		seen := map[string]struct{}{}
		for _, alias := range downgrade {
			if _, ok := aliases[alias]; !ok {
				return settingErrorAt(at+".on_exceed", fmt.Errorf("%s.on_exceed: %q is not an alias in routing.models", at, alias))
			}
			if _, dup := seen[alias]; dup {
				return settingErrorAt(at+".on_exceed", fmt.Errorf("%s.on_exceed names %q twice", at, alias))
			}
			seen[alias] = struct{}{}
		}
	default:
		return settingErrorAt(at+".on_exceed", errors.New(at+".on_exceed must be warn, deny or downgrade:<alias> (more aliases separated by commas)"))
	}
	return nil
}
