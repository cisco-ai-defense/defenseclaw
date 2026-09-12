// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package acp implements DefenseClaw's Agent Client Protocol boundary.
// The package intentionally owns protocol validation and process mediation;
// editor-specific configuration belongs to the CLI.
package acp

import (
	"errors"
	"sort"
	"strings"
)

const (
	SchemaVersion = "schema-v1.21.0"
	SchemaSHA256  = "caf62ff962ada396878372ced11efb2c6764e59d90919a38583c319948931a42"
	MaxFrameBytes = 1 << 20
	MaxPendingIDs = 128
	MaxTurnBuffer = 4 << 20
)

type Support string

const (
	SupportCertified Support = "certified"
	SupportTested    Support = "tested"
	SupportCataloged Support = "cataloged"
)

// Agent describes an ACP agent entry point. Args are literal argv elements;
// callers must never route them through a shell.
type Agent struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Command     string   `json:"command" yaml:"command"`
	Args        []string `json:"args" yaml:"args"`
	Support     Support  `json:"support" yaml:"support"`
	ConnectorID string   `json:"connector_id,omitempty" yaml:"connector_id,omitempty"`
	Kind        string   `json:"kind,omitempty" yaml:"kind,omitempty"`
	RegistryID  string   `json:"registry_id,omitempty" yaml:"registry_id,omitempty"`
	SourceURL   string   `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	Notes       string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

// Client describes an editor that can spawn an ACP agent.
type Client struct {
	ID         string  `json:"id" yaml:"id"`
	Name       string  `json:"name" yaml:"name"`
	Support    Support `json:"support" yaml:"support"`
	ConfigKind string  `json:"config_kind" yaml:"config_kind"`
	SourceURL  string  `json:"source_url,omitempty" yaml:"source_url,omitempty"`
}

type Catalog struct {
	SchemaVersion string   `json:"schema_version" yaml:"schema_version"`
	SchemaSHA256  string   `json:"schema_sha256" yaml:"schema_sha256"`
	Agents        []Agent  `json:"agents" yaml:"agents"`
	Clients       []Client `json:"clients" yaml:"clients"`
}

var builtinCatalog = Catalog{
	SchemaVersion: SchemaVersion,
	SchemaSHA256:  SchemaSHA256,
	Clients: []Client{
		{ID: "zed", Name: "Zed", Support: SupportTested, ConfigKind: "zed-settings", SourceURL: "https://zed.dev/docs/ai/external-agents"},
		{ID: "jetbrains", Name: "JetBrains AI Assistant", Support: SupportCataloged, ConfigKind: "jetbrains-acp", SourceURL: "https://www.jetbrains.com/help/ai-assistant/acp.html"},
	},
	Agents: []Agent{
		{ID: "kiro", Name: "Kiro CLI", Command: "kiro-cli", Args: []string{"acp"}, Support: SupportTested, ConnectorID: "kiro", Kind: "native", SourceURL: "https://kiro.dev/docs/cli/acp/"},
		{ID: "cursor", Name: "Cursor Agent", Command: "agent", Args: []string{"acp"}, Support: SupportCataloged, ConnectorID: "cursor", Kind: "native", RegistryID: "cursor", SourceURL: "https://cursor.com/docs/cli/acp"},
		{ID: "opencode", Name: "OpenCode", Command: "opencode", Args: []string{"acp"}, Support: SupportCataloged, ConnectorID: "opencode", Kind: "native", RegistryID: "opencode", SourceURL: "https://opencode.ai/docs/cli/"},
		{ID: "hermes", Name: "Hermes Agent", Command: "hermes", Args: []string{"acp"}, Support: SupportCataloged, ConnectorID: "hermes", Kind: "native", SourceURL: "https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/programmatic-integration.md"},
		{ID: "copilot", Name: "GitHub Copilot CLI", Command: "copilot", Args: []string{"--acp", "--stdio"}, Support: SupportCataloged, ConnectorID: "copilot", Kind: "native", RegistryID: "github-copilot-cli", SourceURL: "https://docs.github.com/en/copilot/reference/copilot-cli-reference/acp-server"},
		{ID: "openhands", Name: "OpenHands", Command: "openhands", Args: []string{"acp"}, Support: SupportCataloged, ConnectorID: "openhands", Kind: "native", SourceURL: "https://docs.openhands.dev/openhands/usage/cli/ide/overview"},
		{ID: "openclaw", Name: "OpenClaw", Command: "openclaw", Args: []string{"acp"}, Support: SupportCataloged, ConnectorID: "openclaw", Kind: "bridge", SourceURL: "https://docs.openclaw.ai/cli/acp"},
		{ID: "gemini", Name: "Gemini CLI", Command: "gemini", Args: []string{"--acp"}, Support: SupportCataloged, ConnectorID: "geminicli", Kind: "native", RegistryID: "gemini", SourceURL: "https://agentclientprotocol.com/get-started/registry"},
		{ID: "devin", Name: "Devin", Command: "devin", Args: []string{"acp"}, Support: SupportCataloged, ConnectorID: "devin", Kind: "native", RegistryID: "devin", SourceURL: "https://agentclientprotocol.com/get-started/registry"},
		{ID: "amp", Name: "Amp ACP bridge", Command: "amp-acp", Args: []string{}, Support: SupportCataloged, ConnectorID: "amp", Kind: "bridge", RegistryID: "amp-acp", SourceURL: "https://agentclientprotocol.com/get-started/registry"},
		{ID: "antigravity", Name: "Google Antigravity ACP server", Command: "agy_acp_server", Args: []string{}, Support: SupportCataloged, ConnectorID: "antigravity", Kind: "bridge", RegistryID: "antigravity-acp", SourceURL: "https://agentclientprotocol.com/get-started/registry"},
		{ID: "claude", Name: "Claude ACP bridge", Command: "claude-agent-acp", Args: []string{}, Support: SupportCataloged, ConnectorID: "claudecode", Kind: "bridge", RegistryID: "claude-acp", SourceURL: "https://agentclientprotocol.com/get-started/registry"},
		{ID: "codex", Name: "Codex ACP bridge", Command: "codex-acp", Args: []string{}, Support: SupportCataloged, ConnectorID: "codex", Kind: "bridge", RegistryID: "codex-acp", SourceURL: "https://agentclientprotocol.com/get-started/registry"},
	},
}

func BuiltinCatalog() Catalog {
	c := builtinCatalog
	c.Agents = append([]Agent(nil), builtinCatalog.Agents...)
	for index := range c.Agents {
		if c.Agents[index].Args != nil {
			c.Agents[index].Args = append([]string{}, c.Agents[index].Args...)
		}
	}
	c.Clients = append([]Client(nil), builtinCatalog.Clients...)
	return c
}

func LookupAgent(id string) (Agent, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, agent := range builtinCatalog.Agents {
		if agent.ID == id {
			if agent.Args != nil {
				agent.Args = append([]string{}, agent.Args...)
			}
			return agent, nil
		}
	}
	return Agent{}, errors.New("unknown ACP agent: " + id)
}

func AgentIDs() []string {
	ids := make([]string, 0, len(builtinCatalog.Agents))
	for _, agent := range builtinCatalog.Agents {
		ids = append(ids, agent.ID)
	}
	sort.Strings(ids)
	return ids
}
