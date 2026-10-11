// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"encoding/json"
	"path/filepath"
	"sort"
)

// Claude's state also holds project history and credentials. Discovery reads
// at most 256 MiB, never follows a link, and retains only server and project
// names; commands, environment variables, headers and URLs never become
// inventory evidence.
const maxClaudeDiscoveryStateBytes = 256 << 20

func readClaudeDiscoveryState(path string) (servers, projects []string, err error) {
	raw, err := readBoundedRegularFileNoFollow(path, maxClaudeDiscoveryStateBytes)
	if err != nil {
		return nil, nil, err
	}
	var state struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, nil, err
	}
	for name := range state.MCPServers {
		servers = append(servers, name)
	}
	for project, scope := range state.Projects {
		if filepath.IsAbs(project) {
			projects = append(projects, filepath.Clean(project))
		}
		for name := range scope.MCPServers {
			servers = append(servers, name)
		}
	}
	sort.Strings(servers)
	sort.Strings(projects)
	return servers, projects, nil
}
