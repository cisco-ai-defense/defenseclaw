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

package egress

import (
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
)

// FirewallBlockPatterns converts the deny rules of the host egress firewall
// configuration into DeciderOptions.Block patterns, so a destination the
// operator denies for the host is denied for sandboxes too. The sandbox
// policy (packs.Resolve) adds them to its block list from
// firewall.config_file.
//
// Only deny rules carry over. The host firewall's default_action and
// allowlist are not a sandbox egress allowlist and are ignored: they scope
// what the DefenseClaw host itself may reach (the default configuration
// denies everything but DefenseClaw's model, registry and inspection
// endpoints), which would leave a sandbox almost nothing. Sandbox egress is
// narrowed by the network profile instead (allowlist mode with the curated
// allowlist feed) and by openshell.egress.allow.
//
// Only outbound TCP-capable deny rules with a destination apply. A rule
// scoped to a port or port range applies when it covers one of ports (the
// proxy's destination ports) and then blocks the destination outright,
// because the proxy decides per destination; a range that cannot be parsed
// is treated as covering them. Destinations that are not valid patterns
// (firewall.Validate reports those) are skipped, and duplicates dropped.
func FirewallBlockPatterns(cfg *firewall.FirewallConfig, ports []int) []string {
	if cfg == nil {
		return nil
	}
	if len(ports) == 0 {
		ports = DefaultPorts()
	}
	seen := map[string]bool{}
	var out []string
	for _, rule := range cfg.Rules {
		if !strings.EqualFold(rule.Action, "deny") || strings.TrimSpace(rule.Destination) == "" {
			continue
		}
		if dir := strings.ToLower(strings.TrimSpace(rule.Direction)); dir != "" && dir != "outbound" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
		case "", "tcp", "any", "all":
		default:
			continue
		}
		if !firewallRuleCoversPorts(rule, ports) {
			continue
		}
		p, err := parsePattern(rule.Destination)
		if err != nil || seen[p.raw] {
			continue
		}
		seen[p.raw] = true
		out = append(out, p.raw)
	}
	return out
}

func firewallRuleCoversPorts(rule firewall.Rule, ports []int) bool {
	lo, hi := 0, 0
	switch {
	case rule.Port > 0:
		lo, hi = rule.Port, rule.Port
	case strings.TrimSpace(rule.PortRange) != "":
		var ok bool
		if lo, hi, ok = parsePortRange(rule.PortRange); !ok {
			return true
		}
	default:
		return true
	}
	for _, port := range ports {
		if port >= lo && port <= hi {
			return true
		}
	}
	return false
}

// parsePortRange accepts "N", "N-M" and "N:M".
func parsePortRange(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	a, b, found := strings.Cut(s, "-")
	if !found {
		a, b, found = strings.Cut(s, ":")
	}
	if !found {
		b = a
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}
