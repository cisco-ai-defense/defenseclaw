// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// The egress ask keys of SandboxAdminConfig (GAP-0171, PLAN §5.3): which
// hosts and paths of an actor's allowed egress need a person's approval
// first, and which paths are refused. The egress callout applies them to
// requests its EgressPolicy already lets through: they never open a host.
// Agent Substrate keys: openshell.admin refuses them. Profiles only add to
// substrate.admin's (more asks and more refusals are tighter), so an url
// rule's action is deny or ask, never allow.

// SandboxURLRule is one url_rules entry: requests to Hosts, with one of
// Methods (none = every method), under PathPrefix (none = every path) are
// refused (deny) or need an approval (ask).
type SandboxURLRule struct {
	Name       string   `mapstructure:"name" yaml:"name,omitempty" json:"name,omitempty"`
	Hosts      []string `mapstructure:"hosts" yaml:"hosts" json:"hosts"`
	Methods    []string `mapstructure:"methods" yaml:"methods,omitempty" json:"methods,omitempty"`
	PathPrefix string   `mapstructure:"path_prefix" yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	Action     string   `mapstructure:"action" yaml:"action" json:"action"`
}

// URL rule actions.
const (
	SandboxURLRuleDeny = "deny"
	SandboxURLRuleAsk  = "ask"
)

// Limits of the egress ask keys.
const (
	sandboxMaxAskHosts      = 256
	sandboxMaxURLRules      = 64
	sandboxMaxURLRuleHosts  = 64
	sandboxMaxURLPathPrefix = 512
)

var (
	// sandboxHostPattern is a lower-case DNS name, or "*." and one, as in
	// an EgressPolicy rule.
	sandboxHostPattern = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	sandboxHTTPMethod  = regexp.MustCompile(`^[A-Z]{3,10}$`)
	sandboxURLRuleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

func sandboxHostPatternOK(h string) bool {
	return len(h) <= 253 && sandboxHostPattern.MatchString(h)
}

// sandboxPathPrefixOK is a path the callout can canonicalize as written:
// it starts with "/", is printable ASCII and has no percent sign,
// semicolon, backslash or dot segment, so the rule matches what it says
// (the callout refuses ambiguous prefixes at load, GAP-0046).
func sandboxPathPrefixOK(p string) bool {
	if p == "" {
		return true
	}
	if !strings.HasPrefix(p, "/") || len(p) > sandboxMaxURLPathPrefix || strings.ContainsAny(p, `%;\`) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// validateAskKeys checks ask_hosts and url_rules of one floor section.
func (a *SandboxAdminConfig) validateAskKeys(prefix string) error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if a.AskHosts != nil && len(a.AskHosts) == 0 {
		bad("%s.ask_hosts: an empty list is refused; leave the key out for no ask", prefix)
	}
	if len(a.AskHosts) > sandboxMaxAskHosts {
		bad("%s.ask_hosts: at most %d entries", prefix, sandboxMaxAskHosts)
	}
	for i, h := range a.AskHosts {
		if !sandboxHostPatternOK(h) {
			bad(`%s.ask_hosts[%d]: %q must be a lower-case host name or "*.<host>"`, prefix, i, h)
		}
	}
	if a.URLRules != nil && len(a.URLRules) == 0 {
		bad("%s.url_rules: an empty list is refused; leave the key out for no rule", prefix)
	}
	if len(a.URLRules) > sandboxMaxURLRules {
		bad("%s.url_rules: at most %d entries", prefix, sandboxMaxURLRules)
	}
	seenNames := map[string]int{}
	for i, r := range a.URLRules {
		p := fmt.Sprintf("%s.url_rules[%d]", prefix, i)
		// An approval is keyed by the rule's name (the callout asks for
		// "url_rules:<name>"), so two rules with one name would share one
		// approval: an approval of the first would answer the second
		// (GAP-0177).
		if r.Name != "" {
			if first, dup := seenNames[r.Name]; dup {
				bad("%s.name %q is already the name of url_rules[%d]; names must be unique", p, r.Name, first)
			}
			seenNames[r.Name] = i
		}
		if r.Name != "" && !sandboxURLRuleName.MatchString(r.Name) {
			bad(`%s.name %q must be letters, digits, ".", "_" and "-" (at most 64)`, p, r.Name)
		}
		// Any letter case, as the other floor enums.
		if act := strings.ToLower(r.Action); act != SandboxURLRuleDeny && act != SandboxURLRuleAsk {
			bad("%s.action %q must be one of deny, ask", p, r.Action)
		}
		if len(r.Hosts) == 0 || len(r.Hosts) > sandboxMaxURLRuleHosts {
			bad("%s.hosts: name one to %d hosts", p, sandboxMaxURLRuleHosts)
		}
		for j, h := range r.Hosts {
			if !sandboxHostPatternOK(h) {
				bad(`%s.hosts[%d]: %q must be a lower-case host name or "*.<host>"`, p, j, h)
			}
		}
		for j, m := range r.Methods {
			if !sandboxHTTPMethod.MatchString(m) {
				bad("%s.methods[%d]: %q must be an HTTP method in capitals such as POST", p, j, m)
			}
		}
		if !sandboxPathPrefixOK(r.PathPrefix) {
			bad(`%s.path_prefix %q must start with "/" and have no percent sign, semicolon, backslash or dot segment`, p, r.PathPrefix)
		}
	}
	return errors.Join(errs...)
}

// tightenAskKeys adds overlay's ask_hosts and url_rules to out's: an
// approval or a refusal more is tighter. substrate.admin's rules come
// first, so a profile can't put a rule before them.
func tightenAskKeys(out *SandboxAdminConfig, o SandboxAdminConfig) {
	for _, h := range o.AskHosts {
		if !slices.Contains(out.AskHosts, h) {
			out.AskHosts = append(out.AskHosts, h)
		}
	}
	for _, r := range o.URLRules {
		if !slices.ContainsFunc(out.URLRules, r.equal) {
			out.URLRules = append(out.URLRules, cloneURLRule(r))
		}
	}
}

// duplicateURLRuleName is the first name that two different rules share, or
// "". A rule repeated word for word (a profile that repeats a rule of
// substrate.admin) is one rule, not a duplicate.
func duplicateURLRuleName(rules []SandboxURLRule) string {
	seen := map[string]SandboxURLRule{}
	for _, r := range rules {
		if r.Name == "" {
			continue
		}
		if first, ok := seen[r.Name]; ok && !first.equal(r) {
			return r.Name
		}
		seen[r.Name] = r
	}
	return ""
}

func (r SandboxURLRule) equal(o SandboxURLRule) bool {
	return r.Name == o.Name && r.Action == o.Action && r.PathPrefix == o.PathPrefix &&
		slices.Equal(r.Hosts, o.Hosts) && slices.Equal(r.Methods, o.Methods)
}

func cloneURLRule(r SandboxURLRule) SandboxURLRule {
	r.Hosts, r.Methods = slices.Clone(r.Hosts), slices.Clone(r.Methods)
	return r
}

func cloneURLRules(rs []SandboxURLRule) []SandboxURLRule {
	if rs == nil {
		return nil
	}
	out := make([]SandboxURLRule, len(rs))
	for i, r := range rs {
		out[i] = cloneURLRule(r)
	}
	return out
}
