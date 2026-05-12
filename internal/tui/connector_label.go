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

package tui

import (
	"os"
	"path/filepath"
	"strings"
)

// FriendlyConnectorName turns a wire-name connector identifier into the
// human-facing label used across the TUI ("openclaw" → "OpenClaw",
// "zeptoclaw" → "ZeptoClaw", "claudecode" → "Claude Code", "codex" →
// "Codex"). Unknown values are returned with the first rune upper-cased
// so plugin connectors still render reasonably.
func FriendlyConnectorName(name string) string {
	switch strings.TrimSpace(name) {
	case "":
		return "OpenClaw"
	case "openclaw":
		return "OpenClaw"
	case "zeptoclaw":
		return "ZeptoClaw"
	case "claudecode":
		return "Claude Code"
	case "codex":
		return "Codex"
	case "hermes":
		return "Hermes"
	case "cursor":
		return "Cursor"
	case "windsurf":
		return "Windsurf"
	case "geminicli":
		return "Gemini CLI"
	case "copilot":
		return "GitHub Copilot CLI"
	default:
		// Capitalise the first rune for an unknown plugin connector
		// so we still show "Foo" rather than "foo" — but never
		// invent words.
		s := strings.TrimSpace(name)
		if s == "" {
			return name
		}
		return strings.ToUpper(s[:1]) + s[1:]
	}
}

// ConnectorSourceLabel returns the per-category source-of-truth file
// or directory list for the given connector, used as a "Source: …"
// banner under TUI panels (Skills, MCPs, Plugins). Paths use ~ for the
// user's home so the banner stays compact and recognisable.
//
// category is one of: "skills", "mcps", "plugins", "config".
//
// The returned string is intentionally lossy: it reflects what
// connector_paths.py / internal/config/claw.go would *attempt* to read
// for this connector; the actual data may be a strict subset (e.g.
// non-existent files are skipped). The goal is to tell the operator
// "your data is coming from these locations", not to enumerate live
// inventory — that belongs in the panels themselves.
func ConnectorSourceLabel(connector, category string) string {
	connector = strings.TrimSpace(connector)
	if connector == "" {
		connector = "openclaw"
	}

	switch category {
	case "skills":
		return strings.Join(skillSources(connector), ", ")
	case "mcps":
		return strings.Join(mcpSources(connector), ", ")
	case "plugins":
		return strings.Join(pluginSources(connector), ", ")
	case "config":
		return strings.Join(configSources(connector), ", ")
	default:
		return ""
	}
}

func tildePath(p string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

func cwdRel(name string) string {
	return "./" + name
}

func skillSources(connector string) []string {
	home, _ := os.UserHomeDir()
	switch connector {
	case "claudecode":
		return []string{
			tildePath(filepath.Join(home, ".claude", "skills")),
			cwdRel(".claude/skills"),
		}
	case "codex":
		return []string{
			tildePath(filepath.Join(home, ".codex", "skills")),
			cwdRel(".codex/skills"),
		}
	case "zeptoclaw":
		return []string{
			tildePath(filepath.Join(home, ".zeptoclaw", "skills")),
			cwdRel(".zeptoclaw/skills"),
		}
	case "hermes":
		return []string{tildePath(filepath.Join(home, ".hermes", "skills"))}
	case "cursor":
		return []string{
			cwdRel(".cursor/skills"),
			cwdRel(".agents/skills"),
			tildePath(filepath.Join(home, ".cursor", "skills")),
			tildePath(filepath.Join(home, ".agents", "skills")),
		}
	case "windsurf":
		return []string{"unsupported/documented paths only"}
	case "geminicli":
		return []string{
			cwdRel(".gemini/skills"),
			cwdRel(".agents/skills"),
		}
	case "copilot":
		return []string{
			cwdRel(".github/skills"),
			cwdRel(".agents/skills"),
			tildePath(filepath.Join(home, ".copilot", "skills")),
		}
	default:
		return []string{
			cwdRel("skills"),
			tildePath(filepath.Join(home, ".openclaw", "skills")),
		}
	}
}

func mcpSources(connector string) []string {
	home, _ := os.UserHomeDir()
	switch connector {
	case "claudecode":
		return []string{
			tildePath(filepath.Join(home, ".claude", "settings.json")) + " (mcpServers)",
			cwdRel(".mcp.json"),
		}
	case "codex":
		return []string{
			tildePath(filepath.Join(home, ".codex", "config.toml")) + " ([mcp_servers])",
			cwdRel(".mcp.json"),
		}
	case "zeptoclaw":
		return []string{
			tildePath(filepath.Join(home, ".zeptoclaw", "config.json")) + " (mcp.servers)",
			cwdRel(".mcp.json"),
		}
	case "hermes":
		return []string{tildePath(filepath.Join(home, ".hermes", "config.yaml")) + " (mcp.servers)"}
	case "cursor":
		return []string{
			cwdRel(".cursor/mcp.json"),
			tildePath(filepath.Join(home, ".cursor", "mcp.json")),
		}
	case "windsurf":
		return []string{
			tildePath(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")),
			tildePath(filepath.Join(home, ".codeium", "windsurf", "mcp.json")),
		}
	case "geminicli":
		return []string{
			tildePath(filepath.Join(home, ".gemini", "settings.json")) + " (mcpServers)",
			cwdRel(".mcp.json"),
		}
	case "copilot":
		return []string{
			tildePath(filepath.Join(home, ".copilot", "mcp-config.json")),
			cwdRel(".github/mcp.json"),
			cwdRel(".mcp.json"),
		}
	default:
		return []string{"openclaw config get mcp.servers", "openclaw.json (mcp.servers)"}
	}
}

func pluginSources(connector string) []string {
	home, _ := os.UserHomeDir()
	switch connector {
	case "claudecode":
		return []string{tildePath(filepath.Join(home, ".claude", "plugins"))}
	case "codex":
		return []string{tildePath(filepath.Join(home, ".codex", "plugins"))}
	case "zeptoclaw":
		return []string{tildePath(filepath.Join(home, ".zeptoclaw", "plugins"))}
	case "hermes":
		return []string{
			tildePath(filepath.Join(home, ".hermes", "plugins")),
			cwdRel(".hermes/plugins") + " (discovery-only)",
		}
	case "geminicli":
		return []string{cwdRel(".gemini/extensions")}
	case "copilot":
		return []string{"copilot plugin list"}
	case "cursor", "windsurf":
		return []string{"unsupported"}
	default:
		return []string{tildePath(filepath.Join(home, ".openclaw", "extensions"))}
	}
}

func configSources(connector string) []string {
	home, _ := os.UserHomeDir()
	switch connector {
	case "claudecode":
		return []string{tildePath(filepath.Join(home, ".claude", "settings.json"))}
	case "codex":
		return []string{tildePath(filepath.Join(home, ".codex", "config.toml"))}
	case "zeptoclaw":
		return []string{tildePath(filepath.Join(home, ".zeptoclaw", "config.json"))}
	case "hermes":
		return []string{tildePath(filepath.Join(home, ".hermes", "config.yaml"))}
	case "cursor":
		return []string{tildePath(filepath.Join(home, ".cursor", "hooks.json"))}
	case "windsurf":
		return []string{tildePath(filepath.Join(home, ".codeium", "windsurf", "hooks.json"))}
	case "geminicli":
		return []string{tildePath(filepath.Join(home, ".gemini", "settings.json"))}
	case "copilot":
		return []string{cwdRel(".github/hooks/*.json")}
	default:
		return []string{tildePath(filepath.Join(home, ".openclaw", "openclaw.json"))}
	}
}

// ActiveConnectorName resolves the active connector identifier from
// (in order) the live /health snapshot's connector block, then
// cfg.Claw.Mode, falling back to "openclaw". Mirrors the Go
// activeConnector() resolution in internal/config/claw.go but does
// not depend on the proxy being up.
func ActiveConnectorName(health *HealthSnapshot, mode string) string {
	if health != nil && health.Connector != nil {
		if name := strings.TrimSpace(health.Connector.Name); name != "" {
			return name
		}
	}
	if name := strings.TrimSpace(mode); name != "" {
		return name
	}
	return "openclaw"
}
