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

package kit

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// GAP-0522 drift guard: every MCP config and hook config a DefenseClaw
// connector reads from a project folder (its capabilities with that folder
// as the workspace, the source mcpConfigPaths uses) is flagged as able to
// run code by the copy-mode and pull review, at the root and in a
// subfolder. A connector that adds a project config path without a review
// rule fails here.
func TestGAP0522EveryConnectorProjectConfigIsFlagged(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	for _, sub := range []string{"", "pkg"} {
		ws := filepath.Join(root, sub)
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
			caps := cp.Capabilities(connector.SetupOpts{WorkspaceDir: ws})
			paths := append(append([]string{caps.Hooks.ConfigPath}, caps.MCP.ConfigPaths...), caps.MCP.ReadPaths...)
			for _, p := range paths {
				rel, err := filepath.Rel(root, p)
				if p == "" || err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
					continue // not in the project folder (user or system scope)
				}
				if !osw.RunsCode(filepath.ToSlash(rel)) {
					t.Errorf("%s reads %s from the project folder, and pull does not flag it", name, filepath.ToSlash(rel))
				}
			}
		}
	}
}
