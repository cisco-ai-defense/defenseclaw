// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// routingAdminCapabilities adds the routing.admin rules and budgets of a
// config with routing on. The ids are cumulative, so weakening one under the
// same id is a loss too: a rule is routing.admin.rule.<id> plus .deny for a
// deny rule; a budget is routing.admin.budget.<id> plus .downgrade for a
// downgrade or deny budget and .deny for a deny budget. A higher limit is
// not a loss (the bundle diff shows it).
func routingAdminCapabilities(root *yaml.Node, on map[string]bool) {
	if !truthy(nodeAt(root, "routing", "enabled")) {
		return
	}
	if rules := nodeAt(root, "routing", "admin", "rules"); rules != nil && rules.Kind == yaml.SequenceNode {
		for _, rule := range rules.Content {
			id := scalarAt(rule, "id")
			if id == "" {
				continue
			}
			on["routing.admin.rule."+id] = true
			if scalarAt(rule, "action") == "deny" {
				on["routing.admin.rule."+id+".deny"] = true
			}
		}
	}
	if budgets := nodeAt(root, "routing", "admin", "budgets"); budgets != nil && budgets.Kind == yaml.SequenceNode {
		for _, budget := range budgets.Content {
			id := scalarAt(budget, "id")
			if id == "" {
				continue
			}
			on["routing.admin.budget."+id] = true
			switch onExceed := scalarAt(budget, "on_exceed"); {
			case onExceed == "deny":
				on["routing.admin.budget."+id+".downgrade"] = true
				on["routing.admin.budget."+id+".deny"] = true
			case strings.HasPrefix(onExceed, "downgrade:"):
				on["routing.admin.budget."+id+".downgrade"] = true
			}
		}
	}
}

func scalarAt(node *yaml.Node, key string) string {
	if n := nodeAt(node, key); n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}
