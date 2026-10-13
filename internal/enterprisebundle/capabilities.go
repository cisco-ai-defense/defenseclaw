// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DisabledByBundle compares the config the device enforces with the rendered
// bundle config. IDs describe protection surfaces, not YAML source locations.
// Both inputs have already passed managed-config validation at apply time.
func DisabledByBundle(current, rendered []byte) ([]string, error) {
	if len(current) == 0 {
		return nil, nil
	}
	before, err := capabilitySet(current)
	if err != nil {
		return nil, fmt.Errorf("read enforced capabilities: %w", err)
	}
	after, err := capabilitySet(rendered)
	if err != nil {
		return nil, fmt.Errorf("read bundle capabilities: %w", err)
	}
	var disabled []string
	for id, enabled := range before {
		if !enabled {
			continue
		}
		if next, named := after[id]; named && next {
			continue
		}
		// An omitted per-connector override inherits an enabled global
		// guardrail; only an explicit false or global off disables it.
		if strings.HasPrefix(id, "guardrail.") && !strings.HasPrefix(id, "guardrail.connector.") {
			if _, named := after[id]; !named && after["guardrail"] {
				continue
			}
		}
		if strings.HasPrefix(id, "machine_policy.") && id != "machine_policy.default" {
			if _, named := after[id]; !named && after["machine_policy.default"] {
				continue
			}
		}
		if !after[id] {
			disabled = append(disabled, id)
		}
	}
	sort.Strings(disabled)
	return disabled, nil
}

// AbsentSectionWarnings alerts the signer to omitted major protection
// sections. A signer has no knowledge of the receiving device's state.
func AbsentSectionWarnings(raw []byte) ([]Warning, error) {
	root, err := parseConfigNode(raw)
	if err != nil {
		return nil, err
	}
	var warnings []Warning
	if nodeAt(root, "enterprise", "openshell") == nil && nodeAt(root, "openshell") == nil {
		warnings = append(warnings, Warning{Code: "sandbox_section_absent", Message: "config.yaml has no sandbox or enterprise.openshell section; applying this full config can switch sandbox protection off"})
	}
	sections := []struct{ path, code string }{
		{"guardrail", "guardrail_section_absent"},
		{"observability", "observability_section_absent"},
		{"asset_policy", "asset_policy_section_absent"},
		{"enterprise.machine_policy", "machine_policy_section_absent"},
	}
	for _, section := range sections {
		if nodeAt(root, strings.Split(section.path, ".")...) == nil {
			warnings = append(warnings, Warning{Code: section.code, Message: "config.yaml has no " + section.path + " section; applying this full config can switch that capability off"})
		}
	}
	return warnings, nil
}

func capabilitySet(raw []byte) (map[string]bool, error) {
	root, err := parseConfigNode(raw)
	if err != nil {
		return nil, err
	}
	on := map[string]bool{}
	field := func(path ...string) *yaml.Node { return nodeAt(root, path...) }
	if truthy(field("openshell", "enabled")) {
		on["sandbox"] = true
	}
	if section := field("enterprise", "openshell"); section != nil && section.Kind == yaml.MappingNode && len(section.Content) > 0 {
		on["enterprise.openshell"] = true
		for i := 0; i+1 < len(section.Content); i += 2 {
			on["enterprise.openshell."+section.Content[i].Value] = true
		}
	}
	if truthy(field("guardrail", "enabled")) {
		on["guardrail"] = true
		if selected := field("guardrail", "connector"); selected != nil && selected.Value != "" {
			on["guardrail.connector."+selected.Value] = true
		}
	}
	if connectors := field("guardrail", "connectors"); connectors != nil && connectors.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(connectors.Content); i += 2 {
			enabled := nodeAt(connectors.Content[i+1], "enabled")
			on["guardrail."+connectors.Content[i].Value] = on["guardrail"] && (enabled == nil || truthy(enabled))
		}
	}
	if truthy(field("asset_policy", "enabled")) {
		on["asset_policy"] = true
	}
	if destinations := field("observability", "destinations"); destinations != nil && destinations.Kind == yaml.SequenceNode {
		for _, destination := range destinations.Content {
			if name := nodeAt(destination, "name"); name != nil && name.Value != "" {
				on["observability."+name.Value] = true
			}
		}
	}
	on["machine_policy.default"] = !isOff(field("enterprise", "machine_policy", "default", "ownership"))
	if policy := field("enterprise", "machine_policy"); policy != nil && policy.Kind == yaml.MappingNode {
		if connectors := nodeAt(policy, "connectors"); connectors != nil && connectors.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(connectors.Content); i += 2 {
				ownership := nodeAt(connectors.Content[i+1], "ownership")
				enabled := on["machine_policy.default"]
				if ownership != nil {
					enabled = !isOff(ownership)
				}
				on["machine_policy."+connectors.Content[i].Value] = enabled
			}
		}
	}
	return on, nil
}

func nodeAt(node *yaml.Node, path ...string) *yaml.Node {
	for node != nil && node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	for _, part := range path {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == part {
				next = node.Content[i+1]
				break
			}
		}
		node = next
	}
	return node
}

func truthy(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!bool" && node.Value == "true"
}

func isOff(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Value == "off"
}
