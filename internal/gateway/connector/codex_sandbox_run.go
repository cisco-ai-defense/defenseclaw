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
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// codexSandboxSafeApprovalPolicies are the Codex 0.146 approval policies
// that keep its prompts (every AskForApproval value but "never"). Codex
// falls back to the first one when a flag or a config asks for another, so
// on-request, the policy a safe launch passes, comes first.
var codexSandboxSafeApprovalPolicies = []string{"on-request", "on-failure", "untrusted"}

// codexSandboxSafeSandboxModes: Codex's own sandbox cannot run inside
// OpenShell, so safe mode still runs danger-full-access; Codex requires
// read-only in every allowed set.
var codexSandboxSafeSandboxModes = []string{"read-only", "danger-full-access"}

// codexSandboxRunManagedKeys and codexSandboxRunRequirementKeys are the keys
// the run adds; the image files must not already set them.
var (
	codexSandboxRunManagedKeys     = []string{"mcp_servers", "model_provider", "model_providers", "openai_base_url"}
	codexSandboxRunRequirementKeys = []string{"allowed_approval_policies", "allowed_sandbox_modes", "mcp_servers"}
)

// SandboxRunFiles renders the per-run Codex files for the image target
// describes. Codex reads a single /etc/codex/managed_config.toml and a
// single /etc/codex/requirements.toml (there is no drop-in directory), so
// both are the image's documents with the run's keys added, mounted
// read-only over the image's files:
//
//   - managed_config.toml (top precedence for the keys it sets, above user
//     config and -c flags): the run's model provider (model_provider plus
//     openai_base_url for the built-in OpenAI provider, or the custom
//     provider's model_providers table), which a user config.toml the
//     workload wrote could otherwise redirect (Codex 0.146 ignores these
//     keys in a project's .codex/config.toml); and the imported MCP servers,
//     with cwd and env_vars pinned;
//   - requirements.toml: in safe mode allowed_approval_policies without
//     "never" (Codex falls back to on-request when a flag, the user or the
//     project asks for never) and allowed_sandbox_modes; with project
//     servers blocked, an mcp_servers allowlist of the imported servers by
//     name and command or URL identity (none imported: an empty table, which
//     disables every server).
//
// Both documents are re-verified against the image's hook contract.
func (c *CodexConnector) SandboxRunFiles(target SandboxRenderTarget, run SandboxRunConfig) ([]SandboxFile, error) {
	rt, err := resolveSandboxTarget(c.Name(), target)
	if err != nil {
		return nil, err
	}
	if err := validateSandboxMCPServers(run.MCPServers); err != nil {
		return nil, fmt.Errorf("codex run config: %w", err)
	}
	for _, s := range run.MCPServers {
		if s.Remote() && s.Transport == "sse" {
			return nil, fmt.Errorf("codex run config: MCP server %s uses SSE, which Codex does not support", s.Name)
		}
	}
	if err := validateSandboxModelProvider(run.ModelProvider); err != nil {
		return nil, fmt.Errorf("codex run config: %w", err)
	}
	environment := strings.TrimSpace(target.OtelEnvironment)
	if environment == "" {
		environment = codexSandboxOtelEnvironment
	}
	baseRequirements, err := renderCodexSandboxRequirements(rt)
	if err != nil {
		return nil, err
	}
	baseManaged, err := renderCodexSandboxManagedConfig(rt, environment)
	if err != nil {
		return nil, err
	}
	requirements := map[string]interface{}{}
	if err := toml.Unmarshal(baseRequirements, &requirements); err != nil {
		return nil, fmt.Errorf("codex run config: re-read the image requirements: %w", err)
	}
	managed := map[string]interface{}{}
	if err := toml.Unmarshal(baseManaged, &managed); err != nil {
		return nil, fmt.Errorf("codex run config: re-read the image managed config: %w", err)
	}
	for _, key := range codexSandboxRunManagedKeys {
		if _, clash := managed[key]; clash {
			return nil, fmt.Errorf("codex run config: the image managed config already sets %s", key)
		}
	}
	for _, key := range codexSandboxRunRequirementKeys {
		if _, clash := requirements[key]; clash {
			return nil, fmt.Errorf("codex run config: the image requirements already set %s", key)
		}
	}
	addCodexSandboxRunManaged(managed, run)
	addCodexSandboxRunRequirements(requirements, run)

	managedBody, err := toml.Marshal(managed)
	if err != nil {
		return nil, fmt.Errorf("marshal Codex run managed config: %w", err)
	}
	requirementsBody, err := toml.Marshal(requirements)
	if err != nil {
		return nil, fmt.Errorf("marshal Codex run requirements: %w", err)
	}
	managedBody = append([]byte("# DefenseClaw managed Codex config for one OpenShell sandbox: the image's\n"+
		"# managed_config.toml plus this run's model provider and MCP servers, mounted\n"+
		"# read-only over the image file. Highest-precedence layer for the keys it sets.\n"), managedBody...)
	requirementsBody = append([]byte("# DefenseClaw managed Codex requirements for one OpenShell sandbox: the image's\n"+
		"# requirements.toml (hook contract "+rt.contract.ContractID+") plus this run's approval\n"+
		"# and MCP constraints, mounted read-only over the image file.\n"), requirementsBody...)
	if err := verifyCodexSandboxPolicy(requirementsBody, managedBody, rt, environment); err != nil {
		return nil, err
	}
	if err := verifyCodexSandboxRunPolicy(requirementsBody, managedBody, run); err != nil {
		return nil, err
	}
	return []SandboxFile{
		{Path: CodexSandboxManagedConfigPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: managedBody},
		{Path: CodexSandboxRequirementsPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: requirementsBody},
	}, nil
}

func addCodexSandboxRunManaged(managed map[string]interface{}, run SandboxRunConfig) {
	if p := run.ModelProvider; p != nil {
		managed["model_provider"] = p.ID
		if p.ID == SandboxModelProviderOpenAI {
			managed["openai_base_url"] = p.BaseURL
		} else {
			managed["model_providers"] = map[string]interface{}{p.ID: map[string]interface{}{
				"name": p.Name, "base_url": p.BaseURL, "env_key": p.EnvKey, "wire_api": p.WireAPI,
			}}
		}
	}
	servers := sortedSandboxMCPServers(run.MCPServers)
	if len(servers) == 0 {
		return
	}
	tables := map[string]interface{}{}
	for _, s := range servers {
		if s.Remote() {
			tables[s.Name] = map[string]interface{}{"url": s.URL}
			continue
		}
		// A trusted project's .codex/config.toml merges into a server table
		// of the same name key by key; every key set here wins, so the
		// project cannot change the command, arguments, working directory
		// or environment pass-through list.
		entry := map[string]interface{}{
			"command":  s.Command,
			"args":     append([]string{}, s.Args...),
			"env_vars": []string{},
		}
		if run.Workdir != "" {
			entry["cwd"] = run.Workdir
		}
		if len(s.Env) > 0 {
			env := map[string]interface{}{}
			for k, v := range s.Env {
				env[k] = v
			}
			entry["env"] = env
		}
		tables[s.Name] = entry
	}
	managed["mcp_servers"] = tables
}

func addCodexSandboxRunRequirements(requirements map[string]interface{}, run SandboxRunConfig) {
	if run.Safe {
		requirements["allowed_approval_policies"] = append([]string{}, codexSandboxSafeApprovalPolicies...)
		requirements["allowed_sandbox_modes"] = append([]string{}, codexSandboxSafeSandboxModes...)
	}
	if run.AllowProjectMCPServers {
		return
	}
	allow := map[string]interface{}{}
	for _, s := range sortedSandboxMCPServers(run.MCPServers) {
		identity := map[string]interface{}{"command": s.Command}
		if s.Remote() {
			identity = map[string]interface{}{"url": s.URL}
		}
		allow[s.Name] = map[string]interface{}{"identity": identity}
	}
	requirements["mcp_servers"] = allow
}

// verifyCodexSandboxRunPolicy re-reads the run documents and checks every
// run key landed as intended.
func verifyCodexSandboxRunPolicy(requirementsBody, managedBody []byte, run SandboxRunConfig) error {
	requirements := map[string]interface{}{}
	if err := toml.Unmarshal(requirementsBody, &requirements); err != nil {
		return fmt.Errorf("verify Codex run requirements: %w", err)
	}
	managed := map[string]interface{}{}
	if err := toml.Unmarshal(managedBody, &managed); err != nil {
		return fmt.Errorf("verify Codex run managed config: %w", err)
	}
	strs := func(v interface{}) []string {
		list, _ := v.([]interface{})
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, _ := item.(string)
			out = append(out, s)
		}
		return out
	}
	policies := strs(requirements["allowed_approval_policies"])
	switch {
	case run.Safe && !reflect.DeepEqual(policies, codexSandboxSafeApprovalPolicies):
		return fmt.Errorf("verify Codex run requirements: allowed_approval_policies = %v", policies)
	case !run.Safe && requirements["allowed_approval_policies"] != nil:
		return fmt.Errorf("verify Codex run requirements: approval policies are constrained outside safe mode")
	}
	for _, p := range policies {
		if p == "never" {
			return fmt.Errorf("verify Codex run requirements: safe mode allows approval policy never")
		}
	}
	allow, restricted := requirements["mcp_servers"].(map[string]interface{})
	if restricted == run.AllowProjectMCPServers {
		return fmt.Errorf("verify Codex run requirements: mcp_servers allowlist present=%t with project servers allowed=%t", restricted, run.AllowProjectMCPServers)
	}
	defined, _ := managed["mcp_servers"].(map[string]interface{})
	if len(defined) != len(run.MCPServers) {
		return fmt.Errorf("verify Codex run managed config: %d MCP servers defined, want %d", len(defined), len(run.MCPServers))
	}
	for _, s := range run.MCPServers {
		table, _ := defined[s.Name].(map[string]interface{})
		key, want := "command", s.Command
		if s.Remote() {
			key, want = "url", s.URL
		}
		if table[key] != want {
			return fmt.Errorf("verify Codex run managed config: mcp_servers.%s.%s = %#v", s.Name, key, table[key])
		}
		if !restricted {
			continue
		}
		entry, _ := allow[s.Name].(map[string]interface{})
		identity, _ := entry["identity"].(map[string]interface{})
		if len(identity) != 1 || identity[key] != want {
			return fmt.Errorf("verify Codex run requirements: mcp_servers.%s.identity = %#v", s.Name, identity)
		}
	}
	if restricted && len(allow) != len(run.MCPServers) {
		return fmt.Errorf("verify Codex run requirements: the MCP allowlist has %d servers, want %d", len(allow), len(run.MCPServers))
	}
	if p := run.ModelProvider; p != nil {
		if managed["model_provider"] != p.ID {
			return fmt.Errorf("verify Codex run managed config: model_provider = %#v", managed["model_provider"])
		}
		if p.ID == SandboxModelProviderOpenAI {
			if managed["openai_base_url"] != p.BaseURL {
				return fmt.Errorf("verify Codex run managed config: openai_base_url = %#v", managed["openai_base_url"])
			}
		} else {
			providers, _ := managed["model_providers"].(map[string]interface{})
			table, _ := providers[p.ID].(map[string]interface{})
			if table["base_url"] != p.BaseURL || table["env_key"] != p.EnvKey || table["wire_api"] != p.WireAPI || table["name"] != p.Name {
				return fmt.Errorf("verify Codex run managed config: model_providers.%s = %#v", p.ID, table)
			}
		}
	} else if managed["model_provider"] != nil {
		return fmt.Errorf("verify Codex run managed config: a model provider is pinned without a run provider")
	}
	return nil
}
