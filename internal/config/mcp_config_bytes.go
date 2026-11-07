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

package config

import (
	"encoding/json"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"gopkg.in/yaml.v3"
)

// Byte forms of the AI-discovery MCP config readers. The path readers above
// read a file and call these; the Cowork VM sensor helper reads the file
// itself (no-follow, owner-checked, capped) and parses the bytes with the
// same code, so a brokered read names exactly the servers a direct read
// would (cowork-1-0-8 GAP-0008).

// ParseMCPFromDotMCPJSON parses an .mcp.json document.
func ParseMCPFromDotMCPJSON(data []byte) ([]MCPServerEntry, error) {
	return parseDotMCPJSON(data)
}

// ParseMCPFromJSONCPaths parses the servers found at each key chain of paths
// in a JSON or JSONC document (union).
func ParseMCPFromJSONCPaths(data []byte, paths ...[]string) ([]MCPServerEntry, error) {
	var doc map[string]any
	if err := json.Unmarshal(jsonc.Strip(data), &doc); err != nil {
		return nil, err
	}
	return readMCPFromAnyPaths(doc, paths...)
}

// ParseMCPFromAmpSettings parses an Amp settings document (amp.mcpServers).
func ParseMCPFromAmpSettings(data []byte) ([]MCPServerEntry, error) {
	return ParseMCPFromJSONCPaths(data, []string{"amp.mcpServers"})
}

// ParseMCPFromYAMLPaths parses the servers found at each key chain of paths
// in a YAML document (union).
func ParseMCPFromYAMLPaths(data []byte, paths ...[]string) ([]MCPServerEntry, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return readMCPFromAnyPaths(doc, paths...)
}

// ParseMCPFromClaudeJSONBothScopes parses ~/.claude.json: user-scope and
// local-scope servers.
func ParseMCPFromClaudeJSONBothScopes(data []byte) ([]MCPServerEntry, error) {
	user, projects, err := parseClaudeJSONScopes(data)
	if err != nil {
		return nil, err
	}
	return append(user, projects...), nil
}

// ParseMCPFromOpenCodeConfig parses one OpenCode config document.
func ParseMCPFromOpenCodeConfig(source string, data []byte) ([]MCPServerEntry, error) {
	doc, err := parseOpenCodeJSONC(data)
	if err != nil {
		return nil, err
	}
	layer := openCodeConfigLayer{Source: source, Scope: "global", Data: doc}
	return readMCPServersOpenCodeResolution(openCodeConfigResolution{Layers: []openCodeConfigLayer{layer}}), nil
}

// ParseMCPFromCodexConfigTOML parses the [mcp_servers] table of a Codex
// config.toml.
func ParseMCPFromCodexConfigTOML(data []byte) ([]MCPServerEntry, error) {
	var doc struct {
		MCPServers map[string]struct {
			Command   string            `toml:"command"`
			Args      []string          `toml:"args"`
			Env       map[string]string `toml:"env"`
			URL       string            `toml:"url"`
			Transport string            `toml:"transport"`
		} `toml:"mcp_servers"`
	}
	if err := gatewayconnector.ParseCodexTOML(data, &doc); err != nil {
		return nil, err
	}
	var rawDoc struct {
		MCPServers map[string]map[string]any `toml:"mcp_servers"`
	}
	if err := gatewayconnector.ParseCodexTOML(data, &rawDoc); err != nil {
		return nil, err
	}
	out := make([]MCPServerEntry, 0, len(doc.MCPServers))
	for name, cfg := range doc.MCPServers {
		out = append(out, MCPServerEntry{
			Name:              name,
			Command:           cfg.Command,
			Args:              cfg.Args,
			Env:               cfg.Env,
			URL:               cfg.URL,
			Transport:         cfg.Transport,
			codexBuiltinShape: isCodexBuiltinMCPShape(name, rawDoc.MCPServers[name]),
		})
	}
	return out, nil
}
