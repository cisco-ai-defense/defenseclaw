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

package workspace

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// registryRules are review rules taken from the connector registry
// (GAP-0522): every hook config and MCP config a DefenseClaw connector
// reads from a project folder, at any depth, since an agent started in a
// subfolder reads that subfolder's. A connector that adds such a path is
// covered with no change here. They are built once.
var registryRules = sync.OnceValue(func() []riskRule {
	root := filepath.Join(string(filepath.Separator)+"dc-review-ws", "project")
	hooks, mcp := map[string]bool{}, map[string]bool{}
	add := func(set map[string]bool, p string) {
		if p == "" {
			return
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return // user or system scope, not the project folder
		}
		set["**/"+filepath.ToSlash(rel)] = true
	}
	reg := connector.NewDefaultRegistry()
	for _, name := range reg.Names() {
		c, ok := reg.Get(name)
		if !ok {
			continue
		}
		cp, ok := c.(connector.ConnectorCapabilityProvider)
		if !ok {
			continue
		}
		caps := cp.Capabilities(connector.SetupOpts{WorkspaceDir: root})
		add(hooks, caps.Hooks.ConfigPath)
		for _, p := range append(append([]string{}, caps.MCP.ConfigPaths...), caps.MCP.ReadPaths...) {
			add(mcp, p)
		}
	}
	list := func(set map[string]bool) []string {
		out := make([]string, 0, len(set))
		for p := range set {
			out = append(out, p)
		}
		sort.Strings(out)
		return out
	}
	var out []riskRule
	if l := list(hooks); len(l) > 0 {
		out = append(out, riskRule{patterns: l, kind: RiskAgentConfig, severity: SeverityHigh,
			detail: "an agent started in this folder runs the hooks and commands it registers"})
	}
	if l := list(mcp); len(l) > 0 {
		out = append(out, riskRule{patterns: l, kind: RiskMCPServer, severity: SeverityHigh,
			detail: "an agent started in this folder launches these MCP servers as commands"})
	}
	return out
})
