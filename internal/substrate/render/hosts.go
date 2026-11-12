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

package render

import (
	"regexp"
	"slices"
	"strings"
)

// Ecosystem allow packs (E22): the package indexes and mirrors a coding
// agent needs to install dependencies. Each is rendered as inspected https,
// so the callout sees every request.
var ecosystemPacks = map[string][]string{
	"pypi":   {"pypi.org", "files.pythonhosted.org"},
	"npm":    {"registry.npmjs.org", "registry.yarnpkg.com"},
	"crates": {"crates.io", "index.crates.io", "static.crates.io"},
	"go":     {"proxy.golang.org", "sum.golang.org"},
}

// EcosystemPacks are the pack names, sorted.
func EcosystemPacks() []string {
	out := make([]string, 0, len(ecosystemPacks))
	for k := range ecosystemPacks {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// PackHosts returns a pack's hosts, or nil for an unknown pack.
func PackHosts(name string) []string { return slices.Clone(ecosystemPacks[name]) }

// hostClass is a set of host names: a suffix family (the name and every
// name under it) or a regular expression. parent matches the parent of
// every name re matches, so a one-label wildcard "*.<parent>" can be
// checked for overlap.
type hostClass struct {
	suffix string
	// subOnly leaves suffix itself out (a "*.<suffix>" block entry).
	subOnly bool
	re      *regexp.Regexp
	parent  *regexp.Regexp
}

// providerHosts are model provider APIs and consumer chat sites. D2: model
// traffic goes only through the DefenseClaw proxy, so no actor rule may
// reach them. Settings.ProviderHosts adds the hosts of configured providers.
var providerHosts = []hostClass{
	{suffix: "anthropic.com"},
	{suffix: "claude.ai"},
	{suffix: "claude.com"},
	{suffix: "openai.com"},
	{suffix: "chatgpt.com"},
	{suffix: "openai.azure.com"},
	{suffix: "cognitiveservices.azure.com"},
	{suffix: "services.ai.azure.com"},
	{suffix: "generativelanguage.googleapis.com"},
	{suffix: "aiplatform.googleapis.com"},
	{re: regexp.MustCompile(`^[a-z0-9-]+-aiplatform\.googleapis\.com$`), parent: regexp.MustCompile(`^googleapis\.com$`)},
	{re: regexp.MustCompile(`^bedrock(-runtime|-agent|-agent-runtime)?(-fips)?\.[a-z0-9-]+\.amazonaws\.com$`),
		parent: regexp.MustCompile(`^[a-z0-9-]+\.amazonaws\.com$`)},
	{suffix: "mistral.ai"},
	{suffix: "cohere.ai"},
	{suffix: "cohere.com"},
	{suffix: "groq.com"},
	{suffix: "openrouter.ai"},
	{suffix: "x.ai"},
	{suffix: "perplexity.ai"},
	{suffix: "together.xyz"},
	{suffix: "deepseek.com"},
	{suffix: "fireworks.ai"},
	{suffix: "replicate.com"},
}

// pattern is a Substrate hostname pattern: an exact name, "*.<name>"
// (exactly one more label) or "*" (every name).
type pattern struct {
	name     string
	wildcard bool
	any      bool
}

func (p pattern) String() string {
	switch {
	case p.any:
		return "*"
	case p.wildcard:
		return "*." + p.name
	}
	return p.name
}

// parsePattern normalizes and parses a Substrate hostname pattern: lower
// case, one trailing dot dropped, a DNS-1123 subdomain whose last label is
// not all digits (so no IP addresses), optionally "*." in front, or "*".
func parsePattern(raw string) (pattern, bool) {
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if s == "*" {
		return pattern{any: true}, true
	}
	name, wildcard := strings.CutPrefix(s, "*.")
	if !isHostname(name) {
		return pattern{}, false
	}
	return pattern{name: name, wildcard: wildcard}, true
}

// isHostname mirrors upstream egresspolicy.isHostname: a DNS-1123
// subdomain whose top label is not all digits.
func isHostname(name string) bool {
	if !isDNS1123Subdomain(name) {
		return false
	}
	top := name[strings.LastIndexByte(name, '.')+1:]
	return strings.Trim(top, "0123456789") != ""
}

func parent(name string) string {
	_, rest, ok := strings.Cut(name, ".")
	if !ok {
		return ""
	}
	return rest
}

// overlaps reports whether p matches any name in c.
func (c hostClass) overlaps(p pattern) bool {
	switch {
	case p.any:
		return true
	case !p.wildcard:
		if c.re != nil {
			return c.re.MatchString(p.name)
		}
		return (!c.subOnly && p.name == c.suffix) || strings.HasSuffix(p.name, "."+c.suffix)
	case c.re != nil:
		return c.parent.MatchString(p.name)
	}
	// "*.<name>" matches one label under name.
	return p.name == c.suffix || strings.HasSuffix(p.name, "."+c.suffix) || (!c.subOnly && parent(c.suffix) == p.name)
}

// blockClasses reads blocklist entries the way OpenShell does
// (config.OpenShellAdminBlockPatterns): a host name blocks itself and every
// name under it, "*.<name>" every name under it at any depth. IP and CIDR
// entries never match a host name rule and are skipped; "*" blocks all.
func blockClasses(hosts []string) []hostClass {
	var out []hostClass
	for _, h := range hosts {
		s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if s == "*" {
			out = append(out, hostClass{re: regexp.MustCompile(`.`), parent: regexp.MustCompile(`.`)})
			continue
		}
		if p, ok := parsePattern(s); ok {
			out = append(out, hostClass{suffix: p.name, subOnly: p.wildcard})
		}
	}
	return out
}

// covered reports whether every name p matches is admitted by an
// allow-only list in OpenShell syntax: a host name admits itself only,
// "*.<name>" every name under it at any depth.
func covered(allowOnly []string, p pattern) bool {
	if p.any {
		return false
	}
	for _, raw := range allowOnly {
		a, ok := parsePattern(raw)
		if !ok || a.any {
			continue
		}
		switch {
		case !a.wildcard:
			if !p.wildcard && p.name == a.name {
				return true
			}
		case p.wildcard:
			if p.name == a.name || strings.HasSuffix(p.name, "."+a.name) {
				return true
			}
		default:
			if strings.HasSuffix(p.name, "."+a.name) {
				return true
			}
		}
	}
	return false
}

func anyOverlap(classes []hostClass, p pattern) (string, bool) {
	for _, c := range classes {
		if c.overlaps(p) {
			if c.re != nil {
				return c.re.String(), true
			}
			return c.suffix, true
		}
	}
	return "", false
}
