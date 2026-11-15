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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
)

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

// pattern is egressspec.Pattern; parsePattern its parser.
type pattern = egressspec.Pattern

func parsePattern(raw string) (pattern, bool) { return egressspec.ParsePattern(raw) }

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
	case p.Any:
		return true
	case !p.Wildcard:
		if c.re != nil {
			return c.re.MatchString(p.Name)
		}
		return (!c.subOnly && p.Name == c.suffix) || strings.HasSuffix(p.Name, "."+c.suffix)
	case c.re != nil:
		return c.parent.MatchString(p.Name)
	}
	// "*.<name>" matches one label under name.
	return p.Name == c.suffix || strings.HasSuffix(p.Name, "."+c.suffix) || (!c.subOnly && parent(c.suffix) == p.Name)
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
			out = append(out, hostClass{suffix: p.Name, subOnly: p.Wildcard})
		}
	}
	return out
}

// covered reports whether every name p matches is admitted by an
// allow-only list in OpenShell syntax: a host name admits itself only,
// "*.<name>" every name under it at any depth.
func covered(allowOnly []string, p pattern) bool {
	if p.Any {
		return false
	}
	for _, raw := range allowOnly {
		a, ok := parsePattern(raw)
		if !ok || a.Any {
			continue
		}
		switch {
		case !a.Wildcard:
			if !p.Wildcard && p.Name == a.Name {
				return true
			}
		case p.Wildcard:
			if p.Name == a.Name || strings.HasSuffix(p.Name, "."+a.Name) {
				return true
			}
		default:
			if strings.HasSuffix(p.Name, "."+a.Name) {
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
