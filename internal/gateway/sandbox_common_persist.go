// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"gopkg.in/yaml.v3"
)

// sandboxDecisionPatch is called with the current source under the config
// writer lock. Always decisions append to the effective list and preserve
// explicit overlapping source leaves without granting private-address access.
func sandboxDecisionPatch(path string, raw []byte, key, host string) ([]configwrite.Change, error) {
	if key != "openshell.egress.unblocked" && key != "openshell.egress.block" {
		return nil, fmt.Errorf("sandbox decisions cannot be saved to %s", key)
	}
	doc, err := config.ParseV8YAML(path, raw)
	if err != nil {
		return nil, err
	}
	root := doc.Document.Content[0]
	lookup := func(path string) *yaml.Node {
		node := root
		for _, part := range strings.Split(path, ".") {
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
	mode := lookup("deployment_mode")
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) || mode != nil && managed.IsManagedEnterprise(mode.Value) {
		return nil, configwrite.ErrManaged
	}
	legacy := lookup(key)
	listNode, target := legacy, key
	if common := lookup("sandbox"); common != nil {
		if common.Kind != yaml.MappingNode {
			return nil, errors.New("sandbox: expected a configuration mapping")
		}
		target = "sandbox." + strings.TrimPrefix(key, "openshell.")
		if declared := lookup(target); declared != nil {
			listNode = declared
		}
	}
	var list []string
	if listNode != nil {
		if err := listNode.Decode(&list); err != nil {
			return nil, err
		}
	}
	for _, have := range list {
		if strings.EqualFold(strings.TrimSpace(have), host) {
			return nil, nil
		}
	}
	next := append(list, host)
	changes := []configwrite.Change{{Path: target, Value: next}}
	if target != key && legacy != nil {
		changes = append(changes, configwrite.Change{Path: key, Value: next})
	}
	return changes, nil
}
