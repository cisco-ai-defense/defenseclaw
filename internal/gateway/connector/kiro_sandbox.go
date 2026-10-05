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
	"bytes"
	"encoding/json"
	"fmt"
	"path"
)

// In-image Kiro CLI layout (measured on kiro-cli 2.24.1, Linux). Kiro CLI
// reads agent configurations, hooks included, from ~/.kiro/agents and a
// project's .kiro/agents, and picks the agent --agent names by the `name`
// field of any file there, so a file of any name the workload or a repository
// adds can replace the DefenseClaw agent. KIRO_AGENT_CONFIG_DIR replaces both
// directories: with it set, Kiro reads agents only from that directory. The
// DefenseClaw agent therefore lives alone in a root-owned directory, which
// the launcher forces KIRO_AGENT_CONFIG_DIR to on every start (the sandbox
// env sets it as well, for a `kiro-cli chat` started without the launcher).
// Kiro has no system settings tier and still reads user and project settings
// and MCP servers, so the tamper tier stays user.
const (
	// KiroSandboxAgentName is the agent every sandbox launch selects.
	KiroSandboxAgentName = kiroManagedAgentName
	// KiroSandboxAgentDirEnv is the Kiro CLI variable that sets the one
	// directory Kiro reads agents from.
	KiroSandboxAgentDirEnv = "KIRO_AGENT_CONFIG_DIR"
	// KiroSandboxAgentDir is the root-owned agents directory; it holds only
	// the DefenseClaw agent.
	KiroSandboxAgentDir = SandboxLibDir + "/kiro"
	// KiroSandboxAgentPath is the root-owned DefenseClaw agent.
	KiroSandboxAgentPath = KiroSandboxAgentDir + "/" + kiroManagedAgentName + ".json"
	// KiroSandboxSettingsPath makes the DefenseClaw agent Kiro's default, so
	// a `kiro-cli chat` started without the launcher selects it as well.
	KiroSandboxSettingsPath = SandboxHomeDir + "/.kiro/settings/cli.json"
)

// kiroSandboxHookScript is the in-image Kiro hook.
func kiroSandboxHookScript() string {
	return path.Join(SandboxHookDir, kiroHookScriptName)
}

// kiroSandboxHookEvents are the CLI 2.x agent-hook triggers DefenseClaw
// registers in the sandbox image: the host's kiroV2HookSpecs plus the
// userPromptSubmit audit hook the pinned image was measured with (the host
// no longer registers it; see kiroV2HookSpecs). agentSpawn fires only for the
// default agent, not for one selected with --agent, and carries no tool call.
var kiroSandboxHookEvents = []string{"userPromptSubmit", "preToolUse", "postToolUse", "stop"}

// kiroSandboxHookContracts is the reviewed Kiro CLI hook surface of
// DefenseClaw's OpenShell images. Host Kiro hooks are not version-gated;
// a sandbox image always pins the build its hooks were measured on.
func kiroSandboxHookContracts() []HookContract {
	return []HookContract{{
		Connector:               "kiro",
		ContractID:              "kiro-cli-hooks-v1",
		ExactAgentVersions:      []string{"2.24.1"},
		HookScriptVersion:       "v1",
		HookConfigPathTemplates: []string{KiroSandboxAgentPath},
		ResponseFieldName:       "hook_output",
		Events:                  append([]string(nil), kiroSandboxHookEvents...),
		AIDSurfaces:             []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:           true,
			BlockEvents:        KiroBlockEventsForSurface(KiroHookSurfaceV2),
			SupportsFailClosed: true,
			Scope:              "user",
			ConfigPath:         KiroSandboxAgentPath,
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Sandbox-only contract for the pinned Kiro CLI 2.24.1 (kiro-cli-chat) running headless with --agent defenseclaw: the agent-hook triggers userPromptSubmit, preToolUse, postToolUse and stop fire, and exit 2 from preToolUse is the only veto (every other exit code is a warning and the tool runs).",
			"Kiro selects an agent by its name field from any file in ~/.kiro/agents or a project's .kiro/agents, and runs without hooks when the selected agent fails to load, so the agent lives alone in a root-owned directory the launcher forces KIRO_AGENT_CONFIG_DIR to (Kiro then reads no other agents directory).",
		},
	}}
}

// SandboxArtifacts renders the Kiro CLI overlay: the sandbox hook scripts,
// the DefenseClaw agent (hooks on every tool call and prompt) alone in its
// root-owned agents directory, the sandbox env that points Kiro at that
// directory, and the settings that make the agent the default.
func (c *KiroConnector) SandboxArtifacts(target SandboxRenderTarget) (SandboxArtifacts, error) {
	rt, err := resolveSandboxTarget(c.Name(), target)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	hookFiles, err := renderSandboxHookFiles(c.Name(), rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	agent, err := renderKiroSandboxAgent()
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyKiroSandboxAgent(agent); err != nil {
		return SandboxArtifacts{}, err
	}
	settings, err := json.MarshalIndent(kiroSandboxSettings(), "", "  ")
	if err != nil {
		return SandboxArtifacts{}, fmt.Errorf("marshal Kiro sandbox settings: %w", err)
	}
	files := append(hookFiles,
		SandboxFile{Path: KiroSandboxAgentPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: agent},
		SandboxFile{Path: KiroSandboxSettingsPath, Mode: 0o644, Owner: SandboxOwnerUser, Data: append(settings, '\n')},
	)
	return finalizeSandboxArtifacts(SandboxArtifacts{
		Connector:    c.Name(),
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierUser,
		Files:        files,
		Env:          map[string]string{KiroSandboxAgentDirEnv: KiroSandboxAgentDir},
		Binaries:     append(sandboxHookRuntimeBinaries(), harnessBinary("kiro-cli-chat")),
	})
}

// kiroSandboxSettings select the DefenseClaw agent by default, switch Kiro's
// telemetry and auto-update off, and skip the first-run greeting and the
// startup confirmation of --trust-all-tools (every key measured valid on
// 2.24.1; the hooks fire with them set).
func kiroSandboxSettings() map[string]interface{} {
	return map[string]interface{}{
		kiroDefaultAgentSettingKey:         kiroManagedAgentName,
		"telemetry.enabled":                false,
		"app.disableAutoupdates":           true,
		"chat.disableTrustAllConfirmation": true,
		"chat.greeting.enabled":            false,
	}
}

// kiroSandboxAgentHook is one DefenseClaw agent-hook entry: the host's CLI
// 2.x shape with the in-image hook and the glob matcher that matches every
// tool (kiroV2MatchAllTools; ".*" matches none on Kiro 2.24.1).
func kiroSandboxAgentHook(description string) map[string]interface{} {
	return map[string]interface{}{
		"command":     kiroSandboxHookScript(),
		"matcher":     kiroV2MatchAllTools,
		"timeout_ms":  kiroV2HookTimeoutMillis,
		"description": description,
	}
}

// renderKiroSandboxAgent renders the DefenseClaw agent. It offers every tool
// but pre-approves none: --trust-all-tools (the launcher's yolo mode) is
// what skips Kiro's own prompts.
func renderKiroSandboxAgent() ([]byte, error) {
	descriptions := map[string]string{"userPromptSubmit": "DefenseClaw prompt inspection"}
	for _, spec := range kiroV2HookSpecs {
		descriptions[spec.event] = spec.description
	}
	hooks := make(map[string]interface{}, len(kiroSandboxHookEvents))
	for _, event := range kiroSandboxHookEvents {
		description, ok := descriptions[event]
		if !ok {
			return nil, fmt.Errorf("kiro: no hook description for %s", event)
		}
		hooks[event] = []interface{}{kiroSandboxAgentHook(description)}
	}
	body, err := json.MarshalIndent(map[string]interface{}{
		"name":           kiroManagedAgentName,
		"description":    "DefenseClaw-guarded Kiro agent (OpenShell sandbox)",
		"tools":          []string{"*"},
		"includeMcpJson": true,
		"hooks":          hooks,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Kiro sandbox agent: %w", err)
	}
	return append(body, '\n'), nil
}

// verifyKiroSandboxAgent reads the agent back and requires exactly one
// DefenseClaw hook per registered trigger, no other hooks and no
// pre-approved tools.
func verifyKiroSandboxAgent(body []byte) error {
	var doc struct {
		Name          string                       `json:"name"`
		Description   string                       `json:"description"`
		Tools         []string                     `json:"tools"`
		IncludeMCP    bool                         `json:"includeMcpJson"`
		Hooks         map[string][]json.RawMessage `json:"hooks"`
		AllowedTools  []string                     `json:"allowedTools,omitempty"`
		ToolsSettings map[string]interface{}       `json:"toolsSettings,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("verify Kiro sandbox agent: %w", err)
	}
	if doc.Name != kiroManagedAgentName {
		return fmt.Errorf("verify Kiro sandbox agent: name %q", doc.Name)
	}
	if len(doc.AllowedTools) != 0 || len(doc.ToolsSettings) != 0 {
		return fmt.Errorf("verify Kiro sandbox agent: tools are pre-approved")
	}
	if len(doc.Hooks) != len(kiroSandboxHookEvents) {
		return fmt.Errorf("verify Kiro sandbox agent: %d hook triggers, want %d", len(doc.Hooks), len(kiroSandboxHookEvents))
	}
	for _, event := range kiroSandboxHookEvents {
		entries := doc.Hooks[event]
		if len(entries) != 1 {
			return fmt.Errorf("verify Kiro sandbox agent: %s has %d hooks, want 1", event, len(entries))
		}
		var got map[string]interface{}
		if err := json.Unmarshal(entries[0], &got); err != nil {
			return fmt.Errorf("verify Kiro sandbox agent: %s: %w", event, err)
		}
		if got["command"] != kiroSandboxHookScript() || got["matcher"] != kiroV2MatchAllTools ||
			!kiroV2HookTimeoutIs(got["timeout_ms"], kiroV2HookTimeoutMillis) || len(got) != 4 {
			return fmt.Errorf("verify Kiro sandbox agent: %s hook %v is not the DefenseClaw hook", event, got)
		}
	}
	return nil
}
