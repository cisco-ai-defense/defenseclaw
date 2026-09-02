// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// DiscoveryResult is one bounded discovery pass over an agent's effective MCP
// configuration.
//
// Status must be reported alongside Servers so that a pass which could not
// read every layer is never mistaken for an authoritative empty list.
type DiscoveryResult struct {
	Servers      []MCPServer
	Status       MCPDiscoveryStatus
	DiscoveredAt time.Time

	// SkippedDisabled counts configured servers omitted because the agent has
	// them disabled. The Astrix mcp_server shape has no disabled field, so
	// emitting them would overstate the active surface.
	SkippedDisabled int
}

// mcpLayer is one config file consulted during discovery, in precedence order.
type mcpLayer struct {
	path string
	read func(string) ([]config.MCPServerEntry, error)
}

// DiscoverMCPServers reads the MCP servers configured for one connector, for
// the calling user and the given workspace.
//
// It must run in the hook process: the layer paths depend on the real user's
// home directory and the agent's workspace. The deadline bounds the whole
// pass; layers not reached before it expires make the result partial rather
// than silently shrinking the list.
func DiscoverMCPServers(platform Platform, workspaceDir string, deadline time.Time) DiscoveryResult {
	now := time.Now().UTC()
	result := DiscoveryResult{Status: MCPDiscoveryComplete, DiscoveredAt: now}

	layers := mcpLayersFor(platform, workspaceDir)
	if len(layers) == 0 {
		result.Status = MCPDiscoveryError
		return result
	}

	seen := make(map[string]struct{}, 8)
	var parsed, failed, unreached int

	for _, layer := range layers {
		if layer.path == "" {
			continue
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			unreached++
			continue
		}
		if _, err := os.Stat(layer.path); err != nil {
			// An absent layer is authoritative: the user simply has no config
			// at that location.
			continue
		}
		entries, err := layer.read(layer.path)
		if err != nil {
			failed++
			continue
		}
		parsed++
		for _, entry := range entries {
			name := strings.TrimSpace(entry.Name)
			if name == "" {
				continue
			}
			if _, dup := seen[name]; dup {
				// First layer wins, matching the connector precedence the
				// product already applies.
				continue
			}
			seen[name] = struct{}{}
			if entry.Disabled {
				result.SkippedDisabled++
				continue
			}
			result.Servers = append(result.Servers, projectMCPEntry(entry))
		}
	}

	switch {
	case failed == 0 && unreached == 0:
		result.Status = MCPDiscoveryComplete
	case parsed > 0:
		result.Status = MCPDiscoveryPartial
	default:
		result.Status = MCPDiscoveryError
	}

	sort.Slice(result.Servers, func(i, j int) bool {
		return result.Servers[i].ServerName < result.Servers[j].ServerName
	})
	return result
}

// mcpLayersFor returns the config layers for a connector in precedence order,
// mirroring the resolution the product already implements.
func mcpLayersFor(platform Platform, workspaceDir string) []mcpLayer {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	workspace := strings.TrimSpace(workspaceDir)

	switch platform {
	case PlatformClaudeCode:
		var layers []mcpLayer
		if workspace != "" {
			layers = append(layers, mcpLayer{
				path: filepath.Join(workspace, ".mcp.json"),
				read: config.ReadMCPFromDotMCPJSON,
			})
		}
		claudeDir := envDir("CLAUDE_CONFIG_DIR", home, ".claude")
		statePath := filepath.Join(home, ".claude.json")
		if dir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); dir != "" {
			statePath = filepath.Join(dir, ".claude.json")
		}
		layers = append(layers,
			// BothScopes covers the user-level map and every project scope
			// recorded in the state file.
			mcpLayer{path: statePath, read: config.ReadMCPFromClaudeJSONBothScopes},
			mcpLayer{path: filepath.Join(claudeDir, "settings.json"), read: config.ReadMCPFromClaudeSettings},
		)
		return layers

	case PlatformCodex:
		var layers []mcpLayer
		if workspace != "" {
			layers = append(layers, mcpLayer{
				path: filepath.Join(workspace, ".codex", "config.toml"),
				read: config.ReadMCPFromCodexConfigTOML,
			})
		}
		codexHome := envDir("CODEX_HOME", home, ".codex")
		layers = append(layers, mcpLayer{
			path: filepath.Join(codexHome, "config.toml"),
			read: config.ReadMCPFromCodexUserConfigTOML,
		})
		return layers

	case PlatformCursor:
		var layers []mcpLayer
		if home != "" {
			// Cursor resolves the user scope ahead of the workspace scope, so
			// a user entry wins a name collision.
			layers = append(layers, mcpLayer{
				path: filepath.Join(home, ".cursor", "mcp.json"),
				read: config.ReadMCPFromDotMCPJSON,
			})
		}
		if workspace != "" {
			layers = append(layers, mcpLayer{
				path: filepath.Join(workspace, ".cursor", "mcp.json"),
				read: config.ReadMCPFromDotMCPJSON,
			})
		}
		return layers

	default:
		return nil
	}
}

// envDir resolves a connector home override, falling back to a directory under
// the user's home.
func envDir(variable, home, defaultDir string) string {
	if configured := strings.TrimSpace(os.Getenv(variable)); configured != "" {
		if abs, err := filepath.Abs(configured); err == nil {
			return filepath.Clean(abs)
		}
		return filepath.Clean(configured)
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, defaultDir)
}

// projectMCPEntry reduces a parsed config entry to the allow-listed shape.
//
// Env, Args, Headers, OAuth blobs, CWD, and full URLs are read here but never
// carried forward: only the classification they imply is kept.
func projectMCPEntry(entry config.MCPServerEntry) MCPServer {
	out := MCPServer{ServerName: strings.TrimSpace(entry.Name)}

	if strings.TrimSpace(entry.URL) != "" {
		out.ServerType = ServerTypeRemote
		if sanitized, ok := SanitizeRemoteURL(entry.URL); ok {
			out.URL = sanitized
		}
		declared := strings.TrimSpace(entry.AuthProviderType)
		if declared == "" && len(entry.OAuth) > 0 {
			declared = "oauth"
		}
		out.AuthMethod = ClassifyAuthMethod(
			declared,
			headerNames(entry.Headers),
			authorizationScheme(entry.Headers),
			false,
		)
		if out.AuthMethod == AuthMethodUnknown {
			// The sanitized URL dropped user-info and any query string; recover
			// the classification they implied so a credential carried in the
			// URL is named rather than left unidentified.
			if hint := AuthHintFromURL(entry.URL); hint != "" && hint != AuthMethodUnknown {
				out.AuthMethod = hint
			}
		}
		return out
	}

	out.ServerType = ServerTypeLocal
	out.Runner = InferRunner(entry.Command)
	out.Package, out.PackageVersion = InferPackage(out.Runner, entry.Command, entry.Args)
	return out
}

// headerNames returns only the configured header names, sorted for stable
// output. Values are never returned.
func headerNames(headers map[string]string) []string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// authorizationScheme returns just the scheme token of an Authorization
// header, for example "Bearer". The credential that follows it is never read
// past the first whitespace-delimited field and is never returned.
func authorizationScheme(headers map[string]string) string {
	for name, value := range headers {
		if !strings.EqualFold(strings.TrimSpace(name), "authorization") {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return ""
		}
		return fields[0]
	}
	return ""
}
