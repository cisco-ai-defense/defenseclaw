// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// AllowRules are the destinations an admin allows for supply-chain content:
// remote MCP servers, and the registries and marketplaces that skills and
// plugins come from. They feed three places: the build-time MCP host rule
// (ConfigRules), the run-time scan, and A3's EgressPolicy render
// (render.Settings.MCPHosts and RegistryHosts), so an actor can reach exactly
// the hosts its attested content was checked against.
type AllowRules struct {
	MCPHosts           []string `json:"mcp_hosts,omitempty" yaml:"mcp_hosts,omitempty"`
	SkillRegistries    []string `json:"skill_registries,omitempty" yaml:"skill_registries,omitempty"`
	PluginMarketplaces []string `json:"plugin_marketplaces,omitempty" yaml:"plugin_marketplaces,omitempty"`
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeHost validates one host pattern: a DNS name, or "*." and a DNS
// name. A scheme, port, path, a bare wildcard or an address that is private,
// loopback, link-local or unspecified is refused.
func NormalizeHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(h), ".")))
	if h == "" {
		return "", fmt.Errorf("empty host")
	}
	if strings.ContainsAny(h, "/:@ \t?#") {
		return "", fmt.Errorf("%q: give a host name only, with no scheme, port, path or user", h)
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("%q: private, loopback and link-local addresses cannot be allowed", h)
		}
		return h, nil
	}
	name := strings.TrimPrefix(h, "*.")
	if strings.Contains(name, "*") {
		return "", fmt.Errorf("%q: a wildcard is only allowed as a leading \"*.\"", h)
	}
	if len(name) > 253 || !strings.Contains(name, ".") && name != "localhost" {
		return "", fmt.Errorf("%q: not a fully qualified host name", h)
	}
	for _, l := range strings.Split(name, ".") {
		if !hostLabel.MatchString(l) {
			return "", fmt.Errorf("%q: bad host name label %q", h, l)
		}
	}
	return h, nil
}

func normalizeList(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	var errs []string
	for _, h := range in {
		n, err := NormalizeHost(h)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

// Normalize returns the rules with every host validated, de-duplicated and
// sorted. Any invalid host is an error and is left out of the result.
func (r AllowRules) Normalize() (AllowRules, error) {
	var out AllowRules
	var errs []string
	var err error
	if out.MCPHosts, err = normalizeList(r.MCPHosts); err != nil {
		errs = append(errs, "mcp_hosts: "+err.Error())
	}
	if out.SkillRegistries, err = normalizeList(r.SkillRegistries); err != nil {
		errs = append(errs, "skill_registries: "+err.Error())
	}
	if out.PluginMarketplaces, err = normalizeList(r.PluginMarketplaces); err != nil {
		errs = append(errs, "plugin_marketplaces: "+err.Error())
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

// RegistryHosts is the union of skill registries and plugin marketplaces,
// for render.Settings.RegistryHosts.
func (r AllowRules) RegistryHosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{r.SkillRegistries, r.PluginMarketplaces} {
		for _, h := range l {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sort.Strings(out)
	return out
}

// AllowsMCPHost reports whether a remote MCP host is allowed. With no MCP
// hosts listed nothing is allowed here (the list is the allow list); the
// build rule treats an empty list as "not configured" and skips the check.
func (r AllowRules) AllowsMCPHost(host string) bool {
	return hostAllowed(strings.ToLower(host), r.MCPHosts)
}
