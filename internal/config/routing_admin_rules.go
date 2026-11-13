// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	RoutingAdminMessageMaxChars = 512
	RoutingBudgetMaxLimitUSD    = 1e7
)

var (
	routingAdminIDPattern = lazyregexp.New(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	// routingBudgetConnectorPattern is the schema's connectorName form.
	routingBudgetConnectorPattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

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
	// characters on one line).
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
	return m.Identity().Empty() && len(m.Categories) == 0 && m.SeverityAtLeast == ""
}

// NamesIdentity reports whether the match needs a verified caller.
func (m RoutingAdminMatch) NamesIdentity() bool {
	return len(m.Groups) > 0 || len(m.Users) > 0 || len(m.Agents) > 0
}

// IsDeny reports whether the rule refuses the requests it matches.
func (r RoutingAdminRule) IsDeny() bool {
	return r.Action == RoutingRuleActionDeny
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
	if rest, ok := strings.CutPrefix(b.OnExceed, RoutingBudgetOnExceedDowngrade+":"); ok {
		return RoutingBudgetOnExceedDowngrade, strings.Split(rest, ",")
	}
	return b.OnExceed, nil
}

// RoutingVisibility is routing.admin.visibility.
type RoutingVisibility struct {
	// UsersSee is own (also "": a user reads only their own usage) or none
	// (only administrators read usage).
	UsersSee string `mapstructure:"users_see" yaml:"users_see,omitempty"`
}

// EffectiveUsersSee returns UsersSee with its default.
func (v *RoutingVisibility) EffectiveUsersSee() string {
	if v == nil || v.UsersSee == "" {
		return RoutingUsersSeeOwn
	}
	return v.UsersSee
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
		switch visibility.UsersSee {
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
	switch rule.Action {
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
	}{{"groups", m.Groups}, {"users", m.Users}, {"connectors", m.Connectors}, {"agents", m.Agents}, {"categories", m.Categories}} {
		if selector.values != nil && len(selector.values) == 0 {
			return settingErrorAt(at+"."+selector.key, fmt.Errorf("%s.%s is empty; leave the key out or name at least one", at, selector.key))
		}
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
	if s := m.SeverityAtLeast; s != "" && (s != strings.TrimSpace(s) || canonicalGuardrailLevel(s) == "") {
		return settingErrorAt(at+".severity_at_least", fmt.Errorf("%s.severity_at_least %q must be LOW, MEDIUM, HIGH or CRITICAL", at, s))
	}
	return nil
}

// routingAdminCategoryPattern is the category name form routing.categories
// uses.
var routingAdminCategoryPattern = lazyregexp.New(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func validateRoutingAdminMessage(at, message string) error {
	if utf8.RuneCountInString(message) > RoutingAdminMessageMaxChars {
		return settingErrorAt(at, fmt.Errorf("%s must not exceed %d characters", at, RoutingAdminMessageMaxChars))
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
		if subject != RoutingBudgetSubjectAll && !routingBudgetConnectorPattern.MatchString(subject) {
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

// validateRoutingAdminRules checks routing.admin.rules, budgets and
// visibility of a loaded config, and on a standalone managed device the
// rules that keep a fail-closed admin policy usable.
func (c *Config) validateRoutingAdminRules() error {
	a := c.Routing.Admin
	if a == nil {
		return nil
	}
	aliases := make(map[string]struct{}, len(c.Routing.Models))
	for _, m := range c.Routing.Models {
		aliases[m.Name] = struct{}{}
	}
	if err := ValidateRoutingAdminRules(a.Rules, a.Budgets, a.Visibility, aliases); err != nil {
		return err
	}
	if len(a.Budgets) > 0 {
		if err := c.validateBudgetFeed(); err != nil {
			return err
		}
	}
	if a.BudgetStore != nil {
		if a.BudgetStore.Server != nil && strings.TrimSpace(a.BudgetStore.URL) == "" {
			// A store host's config: only budget-store serve reads it.
			if err := ValidateRoutingBudgetStore(a.BudgetStore, false); err != nil {
				return err
			}
		} else {
			if !c.StandaloneEnterprise() {
				return settingErrorAt("routing.admin.budget_store", errors.New("routing.admin.budget_store needs a standalone managed device: the store secret is a protected credential"))
			}
			if err := ValidateRoutingBudgetStore(a.BudgetStore, true); err != nil {
				return err
			}
		}
	}
	if !c.StandaloneEnterprise() || (len(a.Rules) == 0 && len(a.Budgets) == 0) {
		return nil
	}
	if !c.Routing.Enabled {
		return settingErrorAt("routing.enabled", errors.New("routing.admin rules or budgets are set but routing.enabled is false: a managed device would apply none of them; set routing.enabled: true or remove them"))
	}
	return validateRoutingAdminFailClosed(a.Rules, a.AllowedAliases)
}

// validateRoutingAdminFailClosed refuses category rules that would deny
// every call on a managed device while the classifier is down: there every
// category rule applies at once, so their allow lists (and the floor's
// allowed_aliases) must share an alias.
func validateRoutingAdminFailClosed(rules []RoutingAdminRule, floor []string) error {
	var allowed []string
	var ids []string
	limited := floor != nil
	if limited {
		allowed = append(allowed, floor...)
	}
	for _, rule := range rules {
		if len(rule.Match.Categories) == 0 || rule.IsDeny() || len(rule.Allow) == 0 {
			continue
		}
		ids = append(ids, rule.ID)
		if !limited {
			allowed, limited = append([]string(nil), rule.Allow...), true
			continue
		}
		kept := allowed[:0]
		for _, alias := range allowed {
			for _, want := range rule.Allow {
				if alias == want {
					kept = append(kept, alias)
					break
				}
			}
		}
		allowed = kept
	}
	if len(ids) > 0 && len(allowed) == 0 {
		return settingErrorAt("routing.admin.rules", fmt.Errorf(
			"routing.admin.rules %s: when the classifier is down a managed device applies every category rule at once, and their allow lists (with routing.admin.allowed_aliases) share no alias, so every call would be refused; add one alias to all of them",
			strings.Join(ids, ", ")))
	}
	return nil
}

// RoutingBudgetStoreConfig is routing.admin.budget_store: the opt-in fleet
// budget store (defenseclaw-gateway budget-store serve) that sums budget
// spend across managed devices. Absent = budgets count on each device.
// Devices send only charge keys (a budget id with an account join key, a
// keyed hash of a users or groups entry, or a connector name), UTC days and
// dollar amounts.
type RoutingBudgetStoreConfig struct {
	// URL is https://host[:port] of the store.
	URL string `mapstructure:"url" yaml:"url,omitempty"`
	// Credential names the protected credential that holds this device's
	// own credential (budget-store device issue, installed by MDM; default
	// routing-budget-store-device). No device holds a tenant-wide secret.
	Credential string `mapstructure:"credential" yaml:"credential,omitempty"`
	// CAFile is a PEM file of the only CA the device trusts for the store
	// (a private certificate); empty = the system roots.
	CAFile string `mapstructure:"ca_file" yaml:"ca_file,omitempty"`
	// SyncInterval is how often a device sends its spend and reads the
	// fleet's (a Go duration, 10s to 10m; default 30s).
	SyncInterval string `mapstructure:"sync_interval" yaml:"sync_interval,omitempty"`
	// TimeoutMs bounds one request (100 to 10000; default 2000).
	TimeoutMs int `mapstructure:"timeout_ms" yaml:"timeout_ms,omitempty"`
	// Server is read only by budget-store serve on the store host.
	Server *RoutingBudgetStoreServerConfig `mapstructure:"server" yaml:"server,omitempty"`
}

// RoutingBudgetStoreServerConfig is routing.admin.budget_store.server.
type RoutingBudgetStoreServerConfig struct {
	// Listen is host:port of the HTTPS listener.
	Listen string `mapstructure:"listen" yaml:"listen,omitempty"`
	// TLSCertFile and TLSKeyFile are the PEM certificate and key (required:
	// the store serves HTTPS only).
	TLSCertFile string `mapstructure:"tls_cert_file" yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string `mapstructure:"tls_key_file"  yaml:"tls_key_file,omitempty"`
	// DBPath is the store's SQLite file (devices and spend).
	DBPath string `mapstructure:"db_path" yaml:"db_path,omitempty"`
	// RateLimitPerMinute caps requests per device (default 600; 20 times
	// that per client address before authentication).
	RateLimitPerMinute int `mapstructure:"rate_limit_per_minute" yaml:"rate_limit_per_minute,omitempty"`
	// DeviceDailyCapUSD is the default spend one device may add per UTC day
	// (default 500; device issue --cap-usd sets one device's).
	DeviceDailyCapUSD float64 `mapstructure:"device_daily_cap_usd" yaml:"device_daily_cap_usd,omitempty"`
}

// Defaults of routing.admin.budget_store.
const (
	RoutingBudgetStoreDefaultCredential = "routing-budget-store-device"
	RoutingBudgetStoreDefaultSync       = 30 * time.Second
	RoutingBudgetStoreDefaultTimeoutMs  = 2000
	RoutingBudgetStoreDefaultRate       = 600
)

// EffectiveCredential returns Credential with its default.
func (b *RoutingBudgetStoreConfig) EffectiveCredential() string {
	if b == nil || strings.TrimSpace(b.Credential) == "" {
		return RoutingBudgetStoreDefaultCredential
	}
	return strings.TrimSpace(b.Credential)
}

// EffectiveSyncInterval returns SyncInterval with its default.
func (b *RoutingBudgetStoreConfig) EffectiveSyncInterval() time.Duration {
	if b == nil {
		return RoutingBudgetStoreDefaultSync
	}
	if d, err := time.ParseDuration(strings.TrimSpace(b.SyncInterval)); err == nil && d > 0 {
		return d
	}
	return RoutingBudgetStoreDefaultSync
}

// EffectiveTimeout returns TimeoutMs with its default.
func (b *RoutingBudgetStoreConfig) EffectiveTimeout() time.Duration {
	if b == nil || b.TimeoutMs <= 0 {
		return RoutingBudgetStoreDefaultTimeoutMs * time.Millisecond
	}
	return time.Duration(b.TimeoutMs) * time.Millisecond
}

// ValidateRoutingBudgetStore checks routing.admin.budget_store. device is
// true when a device would use it (a gateway config); the store host's
// serve command validates the server section with device false.
func ValidateRoutingBudgetStore(b *RoutingBudgetStoreConfig, device bool) error {
	if b == nil {
		return nil
	}
	at := "routing.admin.budget_store"
	if device || strings.TrimSpace(b.URL) != "" {
		u, err := url.Parse(strings.TrimSpace(b.URL))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return settingErrorAt(at+".url", fmt.Errorf("%s.url must be https://host[:port] (HTTPS only, no path, query or credentials)", at))
		}
	}
	if c := strings.TrimSpace(b.Credential); c != "" && !ValidEnterpriseCredentialName(c) {
		return settingErrorAt(at+".credential", fmt.Errorf("%s.credential %q is not a valid credential name", at, b.Credential))
	}
	if s := strings.TrimSpace(b.SyncInterval); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 10*time.Second || d > 10*time.Minute {
			return settingErrorAt(at+".sync_interval", fmt.Errorf("%s.sync_interval must be a duration from 10s to 10m", at))
		}
	}
	if b.TimeoutMs != 0 && (b.TimeoutMs < 100 || b.TimeoutMs > 10000) {
		return settingErrorAt(at+".timeout_ms", fmt.Errorf("%s.timeout_ms must be 100 to 10000", at))
	}
	if b.CAFile != "" && !filepath.IsAbs(b.CAFile) {
		return settingErrorAt(at+".ca_file", fmt.Errorf("%s.ca_file must be an absolute path", at))
	}
	if s := b.Server; s != nil {
		if device {
			return settingErrorAt(at+".server", fmt.Errorf("%s.server is read by budget-store serve on the store host; remove it from a device config", at))
		}
		if _, _, err := net.SplitHostPort(strings.TrimSpace(s.Listen)); err != nil {
			return settingErrorAt(at+".server.listen", fmt.Errorf("%s.server.listen must be host:port", at))
		}
		for key, path := range map[string]string{"tls_cert_file": s.TLSCertFile, "tls_key_file": s.TLSKeyFile, "db_path": s.DBPath} {
			if !filepath.IsAbs(strings.TrimSpace(path)) {
				return settingErrorAt(at+".server."+key, fmt.Errorf("%s.server.%s must be an absolute path (the store serves HTTPS only)", at, key))
			}
		}
		if s.RateLimitPerMinute < 0 || s.RateLimitPerMinute > 100000 {
			return settingErrorAt(at+".server.rate_limit_per_minute", fmt.Errorf("%s.server.rate_limit_per_minute must be 0 to 100000", at))
		}
		if math.IsNaN(s.DeviceDailyCapUSD) || s.DeviceDailyCapUSD < 0 || s.DeviceDailyCapUSD > RoutingBudgetMaxLimitUSD {
			return settingErrorAt(at+".server.device_daily_cap_usd", fmt.Errorf("%s.server.device_daily_cap_usd must be 0 to %.0f", at, RoutingBudgetMaxLimitUSD))
		}
	}
	return nil
}

// BudgetFeedReady reports whether agent calls are recorded with a computed
// cost, the only spend budgets count (observability.tokenomics on, cost
// computed, role agent recorded).
func (c *Config) BudgetFeedReady() bool {
	t := c.Observability.Tokenomics
	return t.Enabled && t.ComputesCost() && t.RoleEnabled("agent")
}

// validateBudgetFeed refuses budgets that nothing would charge: on a
// standalone managed device budgets need the usage feed and a price for
// every model (observability.pricing.unknown_model fallback), else a deny
// budget would never trip. OSS reports the same gaps through doctor.
func (c *Config) validateBudgetFeed() error {
	if !c.StandaloneEnterprise() {
		return nil
	}
	if !c.BudgetFeedReady() {
		return settingErrorAt("routing.admin.budgets", errors.New(
			"routing.admin.budgets count the computed cost of agent calls: set observability.tokenomics.enabled true, keep cost.compute on and roles including agent"))
	}
	if strings.TrimSpace(c.Observability.Pricing.UnknownModel) != "fallback" {
		return settingErrorAt("observability.pricing.unknown_model", errors.New(
			"routing.admin.budgets on a managed device need a price for every model: set observability.pricing.unknown_model fallback with observability.pricing.fallback rates"))
	}
	return nil
}
