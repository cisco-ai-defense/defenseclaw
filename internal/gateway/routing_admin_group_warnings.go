// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// RoutingAdminGroupWarningCode ends each RoutingAdminGroupWarnings warning.
const RoutingAdminGroupWarningCode = "routing_admin_group_unmatched"

// routingAdminGroupSelector is one routing.admin rule or group budget that
// names groups, for the group check.
type routingAdminGroupSelector struct {
	label  string
	groups []string
}

func routingAdminGroupSelectors(cfg *config.Config) []routingAdminGroupSelector {
	if cfg == nil || cfg.Routing.Admin == nil {
		return nil
	}
	var out []routingAdminGroupSelector
	for _, r := range cfg.Routing.Admin.Rules {
		if len(r.Match.Groups) > 0 {
			out = append(out, routingAdminGroupSelector{label: "routing.admin rule " + r.ID, groups: r.Match.Groups})
		}
	}
	for _, b := range cfg.Routing.Admin.Budgets {
		if b.Scope == config.RoutingBudgetScopeGroup && strings.TrimSpace(b.Subject) != "" {
			out = append(out, routingAdminGroupSelector{label: "routing.admin budget " + b.ID, groups: []string{b.Subject}})
		}
	}
	return out
}

var routingAdminAssignmentLabel = regexp.MustCompile(`\bassignment (\d+): `)

// RoutingAdminGroupWarnings names the routing.admin rules and group budgets
// of a standalone managed config whose group matches no group this host
// knows by that name or by its paired NetBIOS or DNS spelling, with the
// checks guardrail profile assignment groups get (unknownAssignmentGroups):
// such a deny budget or rule never acts on this host, and a group budget
// never pools this host's spend (rel-1-0-10:GAP-1124). config validate and
// doctor list them. spoolDir is the guardian's identity spool, whose records
// pair the NetBIOS and DNS names of the domains of this device's accounts.
// The groups of a per-user install match nobody (CallerFromEngine), which
// routing rules list already says, so it gets none.
func RoutingAdminGroupWarnings(ctx context.Context, cfg *config.Config, spoolDir string) []string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	selectors := routingAdminGroupSelectors(cfg)
	if len(selectors) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, profileGroupCheckBudget)
	defer cancel()
	assignments := make([]config.ProfileAssignment, len(selectors))
	for i, s := range selectors {
		assignments[i] = config.ProfileAssignment{Match: config.ProfileMatch{Groups: s.groups}}
	}
	pairs := verifiedGroupDomains(spoolDir)
	exists := foldedGroupExists(profileGroupExists, pairs)
	return routingAdminGroupWarningsFrom(selectors, unknownAssignmentGroups(ctx, assignments, exists, foldedGroupQualify(profileGroupQualifiedName, pairs), bareGroupsDirectorySilent))
}

// routingAdminGroupWarningsFrom names the selectors in the assignment
// warnings of their groups.
func routingAdminGroupWarningsFrom(selectors []routingAdminGroupSelector, warnings []string) []string {
	out := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		warning = routingAdminAssignmentLabel.ReplaceAllStringFunc(warning, func(m string) string {
			n, err := strconv.Atoi(routingAdminAssignmentLabel.FindStringSubmatch(m)[1])
			if err != nil || n < 1 || n > len(selectors) {
				return m
			}
			return selectors[n-1].label + ": "
		})
		warning = strings.ReplaceAll(warning, "so the assignment selects nobody", "so it selects nobody")
		warning = strings.ReplaceAll(warning, "later assignment groups", "later groups")
		out = append(out, fmt.Sprintf("%s (%s)", warning, RoutingAdminGroupWarningCode))
	}
	return out
}
