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

package connector

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Per-sandbox managed harness configuration.
//
// An overlay image carries the policy every sandbox of its harness shares:
// hooks, pinned helpers and telemetry. What differs per run is rendered by
// the sandbox manager for each sandbox and bind-mounted read-only into it:
// the model provider the run chose, whether the harness keeps its permission
// prompts (safe mode), and which MCP servers may start. The harness reads
// these files with managed precedence, so neither a repository's committed
// settings nor the workload-writable user settings can override them.
//
// The files are schema-checked here against the harness versions DefenseClaw
// reviewed (Claude Code 2.1.156, Codex 0.146.0): Claude Code silently drops a
// whole settings file that carries one schema-invalid field, and Codex
// refuses to start on a malformed requirements file. The live proof is the
// image package's run-config probe (TestLiveRunConfig).

// SandboxRunConfig is the per-run input of SandboxRunFiles.
type SandboxRunConfig struct {
	// Env is the sandbox creation environment. Claude Code pins its model
	// provider selection variables from it: the value this run sets, or ""
	// (unset) for every selection variable the run does not use.
	Env map[string]string
	// Credentials names the variables OpenShell delivers as provider
	// placeholders. Their values are revision-scoped and never pinned.
	Credentials []string
	// ModelProvider is the provider Codex runs with; nil when the run chose
	// none through DefenseClaw.
	ModelProvider *SandboxModelProvider
	// Workdir is the project's path inside the sandbox; imported stdio MCP
	// servers start there.
	Workdir string
	// Safe keeps the harness's permission prompts: its bypass mode is
	// refused whatever a flag, a project or a user setting asks for.
	Safe bool
	// MCPServers are the MCP servers the run brings along: the user's
	// servers DefenseClaw inventoried and did not block.
	MCPServers []SandboxMCPServer
	// AllowProjectMCPServers also lets the project's own MCP servers
	// (Claude Code .mcp.json, Codex .codex/config.toml) start: pack key
	// mcp.project_servers: allow. False confines the harness to MCPServers.
	AllowProjectMCPServers bool
}

// SandboxModelProvider is a Codex model provider a run pins.
type SandboxModelProvider struct {
	// ID is the provider id; SandboxModelProviderOpenAI is Codex's built-in
	// OpenAI provider, whose endpoint is BaseURL. Any other id is a custom
	// provider defined by Name, BaseURL, EnvKey and WireAPI.
	ID      string
	Name    string
	BaseURL string
	EnvKey  string
	WireAPI string
	// DefaultModel, when set, is the model the run pins for the provider
	// because it does not serve the harness's own default. Codex pins it
	// in the managed config, above user config and -c overrides; a -m at
	// launch still picks another.
	DefaultModel string
	// FunctionToolsOnly marks a provider that rejects every tool but
	// function tools (Bedrock Mantle's OpenAI-compatible models refuse the
	// namespace tool of Codex's multi-agent feature and its web search).
	// Codex pins features.multi_agent = false and web_search = "disabled" in
	// the managed config, so every Codex the sandbox starts leaves them out,
	// a `sandbox connect --shell` or the in-sandbox shim included.
	FunctionToolsOnly bool
}

// sandboxModelNamePattern is a model id a run may pin.
var sandboxModelNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// SandboxModelProviderOpenAI is Codex's built-in OpenAI provider id.
const SandboxModelProviderOpenAI = "openai"

// SandboxMCPServer is one MCP server a sandbox run brings along.
type SandboxMCPServer struct {
	// Name is the server name the harness shows (mcp__<name>__<tool>).
	Name string
	// Command and Args start a stdio server inside the sandbox.
	Command string
	Args    []string
	// Env is the server's non-secret environment.
	Env map[string]string
	// URL names a remote server; Transport is "http" (the default) or
	// "sse".
	URL       string
	Transport string
}

// Remote reports whether s is a remote (URL) server.
func (s SandboxMCPServer) Remote() bool { return s.URL != "" }

// SandboxRunConfigProvider is implemented by connectors whose harness reads
// per-run managed configuration. SandboxRunFiles renders it for the overlay
// image that target describes (the same target the image was built for):
// files mounted read-only at their Path, each checked against the harness
// schema and, where it replaces an image file, re-verified against the
// image's hook contract.
type SandboxRunConfigProvider interface {
	SandboxRunFiles(target SandboxRenderTarget, run SandboxRunConfig) ([]SandboxFile, error)
}

// Limits on imported MCP servers.
const (
	maxSandboxMCPServers = 64
	maxSandboxMCPArgs    = 64
	maxSandboxMCPValue   = 4096
)

var (
	// sandboxMCPNamePattern is Claude Code's allowlist serverName pattern,
	// which also keeps a name a single TOML key segment for Codex.
	sandboxMCPNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	sandboxEnvNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// ValidateSandboxMCPServer checks one imported server: a Claude Code
// compatible name, exactly one of a command or an http(s) URL, and values
// without NUL or line breaks. An URL may not carry "*", which Claude Code's
// allowlist would read as a wildcard.
func ValidateSandboxMCPServer(s SandboxMCPServer) error {
	if !sandboxMCPNamePattern.MatchString(s.Name) {
		return fmt.Errorf("MCP server name %q must be 1-64 letters, digits, '-' or '_'", s.Name)
	}
	switch {
	case s.Command != "" && s.URL != "":
		return fmt.Errorf("MCP server %s has both a command and a URL", s.Name)
	case s.Command == "" && s.URL == "":
		return fmt.Errorf("MCP server %s has neither a command nor a URL", s.Name)
	}
	if s.Command != "" {
		if s.Transport != "" && s.Transport != "stdio" {
			return fmt.Errorf("MCP server %s: a command server uses the stdio transport, not %q", s.Name, s.Transport)
		}
		if err := sandboxMCPValue(s.Name, "command", s.Command); err != nil {
			return err
		}
		if len(s.Args) > maxSandboxMCPArgs {
			return fmt.Errorf("MCP server %s has more than %d arguments", s.Name, maxSandboxMCPArgs)
		}
		for _, arg := range s.Args {
			if err := sandboxMCPValue(s.Name, "argument", arg); err != nil {
				return err
			}
		}
		for key, value := range s.Env {
			if !sandboxEnvNamePattern.MatchString(key) {
				return fmt.Errorf("MCP server %s: invalid environment variable name %q", s.Name, key)
			}
			if err := sandboxMCPValue(s.Name, "environment value", value); err != nil {
				return err
			}
		}
		return nil
	}
	switch s.Transport {
	case "", "http", "sse":
	default:
		return fmt.Errorf("MCP server %s: remote transport %q is not http or sse", s.Name, s.Transport)
	}
	if len(s.Env) > 0 {
		return fmt.Errorf("MCP server %s: a remote server has no environment", s.Name)
	}
	if err := sandboxMCPValue(s.Name, "URL", s.URL); err != nil {
		return err
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return fmt.Errorf("MCP server %s: URL %q must be an http(s) URL without credentials", s.Name, s.URL)
	}
	if strings.ContainsAny(s.URL, "* \t") {
		return fmt.Errorf("MCP server %s: URL %q may not contain '*' or spaces", s.Name, s.URL)
	}
	return nil
}

func sandboxMCPValue(server, what, value string) error {
	if value == "" && what != "argument" && what != "environment value" {
		return fmt.Errorf("MCP server %s: empty %s", server, what)
	}
	if len(value) > maxSandboxMCPValue || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("MCP server %s: %s is too long or contains NUL or a line break", server, what)
	}
	return nil
}

// validateSandboxMCPServers checks every server and that names are unique.
func validateSandboxMCPServers(servers []SandboxMCPServer) error {
	if len(servers) > maxSandboxMCPServers {
		return fmt.Errorf("at most %d MCP servers can be brought into a sandbox", maxSandboxMCPServers)
	}
	seen := map[string]bool{}
	for _, s := range servers {
		if err := ValidateSandboxMCPServer(s); err != nil {
			return err
		}
		if seen[s.Name] {
			return fmt.Errorf("MCP server %s is listed twice", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// sortedSandboxMCPServers returns servers sorted by name.
func sortedSandboxMCPServers(servers []SandboxMCPServer) []SandboxMCPServer {
	out := append([]SandboxMCPServer(nil), servers...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func validateSandboxModelProvider(p *SandboxModelProvider) error {
	if p == nil {
		return nil
	}
	if !sandboxMCPNamePattern.MatchString(p.ID) {
		return fmt.Errorf("model provider id %q must be letters, digits, '-' or '_'", p.ID)
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return fmt.Errorf("model provider %s: base URL %q must be an http(s) URL without credentials", p.ID, p.BaseURL)
	}
	if p.DefaultModel != "" && !sandboxModelNamePattern.MatchString(p.DefaultModel) {
		return fmt.Errorf("model provider %s: default model %q is not a plain model id", p.ID, p.DefaultModel)
	}
	if p.ID == SandboxModelProviderOpenAI {
		if p.Name != "" || p.EnvKey != "" || p.WireAPI != "" {
			return fmt.Errorf("model provider %s is built in: only its base URL can be pinned", p.ID)
		}
		return nil
	}
	if p.Name == "" || !sandboxEnvNamePattern.MatchString(p.EnvKey) {
		return fmt.Errorf("model provider %s needs a name and an env_key variable name", p.ID)
	}
	switch p.WireAPI {
	case "responses", "chat":
	default:
		return fmt.Errorf("model provider %s: wire_api %q is not responses or chat", p.ID, p.WireAPI)
	}
	for _, v := range []string{p.Name, p.BaseURL} {
		if strings.ContainsAny(v, "\x00\r\n") {
			return fmt.Errorf("model provider %s: values may not contain NUL or line breaks", p.ID)
		}
	}
	return nil
}

// sandboxArtifactFile returns the artifact at path.
func sandboxArtifactFile(arts SandboxArtifacts, path string) ([]byte, error) {
	for _, f := range arts.Files {
		if f.Path == path {
			return f.Data, nil
		}
	}
	return nil, fmt.Errorf("the %s overlay has no %s", arts.Connector, path)
}
