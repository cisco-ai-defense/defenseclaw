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
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// Per-run Claude Code managed files (see SandboxRunConfig).
const (
	claudeCodeSandboxRunDropInName = "60-defenseclaw-run.json"
	// ClaudeCodeSandboxRunDropInPath sorts after the image's
	// 50-defenseclaw.json, so its values win inside the managed tier.
	ClaudeCodeSandboxRunDropInPath = claudeCodeSandboxManagedRoot + "/managed-settings.d/" + claudeCodeSandboxRunDropInName
	// ClaudeCodeSandboxManagedMCPPath is Claude's enterprise MCP file. While
	// it exists Claude runs only the servers it lists and ignores user,
	// local, project (.mcp.json), plugin and --mcp-config servers.
	ClaudeCodeSandboxManagedMCPPath = claudeCodeSandboxManagedRoot + "/managed-mcp.json"
	// ClaudeCodeSandboxRunMCPServersPath carries the imported servers when
	// project servers are allowed (no managed-mcp.json); the launcher
	// merges them into ~/.claude.json on every start.
	ClaudeCodeSandboxRunMCPServersPath = SandboxLibDir + "/run/claude-mcp-servers.json"
)

// claudeCodeSandboxProviderEnv are the settings-env variables through which a
// settings file can move Claude Code 2.1.156 to another model endpoint: the
// provider switches (CLAUDE_CODE_USE_*), each provider's base URL, and the
// bearer and extra headers every request carries. The per-run drop-in pins
// each one to the value the run uses, or to "" (Claude reads an empty value
// as unset) when the run does not use it, so a repository's committed
// .claude/settings.json, or a user settings file the workload wrote, cannot
// point the conversation at another endpoint. Variables the run receives as
// OpenShell credential placeholders are left out: their values change on
// every start.
var claudeCodeSandboxProviderEnv = []string{
	"ANTHROPIC_AUTH_TOKEN",
	"ANTHROPIC_AWS_BASE_URL",
	"ANTHROPIC_BASE_URL",
	"ANTHROPIC_BEDROCK_BASE_URL",
	"ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
	"ANTHROPIC_CUSTOM_HEADERS",
	"ANTHROPIC_FOUNDRY_BASE_URL",
	"ANTHROPIC_VERTEX_BASE_URL",
	"CLAUDE_CODE_USE_ANTHROPIC_AWS",
	"CLAUDE_CODE_USE_BEDROCK",
	"CLAUDE_CODE_USE_FOUNDRY",
	"CLAUDE_CODE_USE_MANTLE",
	"CLAUDE_CODE_USE_VERTEX",
}

// ClaudeCodeSandboxProviderEnv lists the model-provider variables the
// per-run drop-in pins.
func ClaudeCodeSandboxProviderEnv() []string {
	return append([]string(nil), claudeCodeSandboxProviderEnv...)
}

// claudeCodeSandboxModelEnv are the settings-env variables that choose
// Claude Code 2.1.156's model: the main model and the models the Opus,
// Sonnet and Haiku aliases (the /model picker) and background tasks resolve
// to. The per-run drop-in pins each one the run sets (a provider that
// serves the models under other ids, such as Bedrock Mantle), so a settings
// file cannot pick a model that endpoint does not serve; --model and /model
// still pick another. Variables the run leaves unset stay unpinned.
var claudeCodeSandboxModelEnv = []string{
	"ANTHROPIC_DEFAULT_HAIKU_MODEL",
	"ANTHROPIC_DEFAULT_OPUS_MODEL",
	"ANTHROPIC_DEFAULT_SONNET_MODEL",
	"ANTHROPIC_MODEL",
	"ANTHROPIC_SMALL_FAST_MODEL",
}

// ClaudeCodeSandboxModelEnv lists the model variables the per-run drop-in
// pins when the run sets them.
func ClaudeCodeSandboxModelEnv() []string {
	return append([]string(nil), claudeCodeSandboxModelEnv...)
}

// SandboxRunEnv names the variables of the creation environment the per-run
// drop-in pins (SandboxRunEnvReader): the model-provider and model ones.
func (c *ClaudeCodeConnector) SandboxRunEnv() []string {
	return append(ClaudeCodeSandboxProviderEnv(), claudeCodeSandboxModelEnv...)
}

// SandboxRunFiles renders the per-run Claude Code files for the image target
// describes:
//
//   - 60-defenseclaw-run.json (always): the model-provider env pins and the
//     model the run sets (claudeCodeSandboxModelEnv); in safe
//     mode permissions.disableBypassPermissionsMode "disable" (Claude then
//     refuses bypassPermissions from --dangerously-skip-permissions,
//     --permission-mode or any settings defaultMode) and
//     skipDangerousModePermissionPrompt false; with project servers blocked,
//     allowManagedMcpServersOnly and allowedMcpServers holding only the
//     imported servers, by exact command or URL (never by name, which a
//     repository's server could reuse);
//   - with project servers blocked, managed-mcp.json listing the imported
//     servers (possibly none): Claude's exclusive MCP mode;
//   - with project servers allowed and servers imported, the file the
//     launcher merges into ~/.claude.json.
//
// The drop-in is checked against the 2.1.156 settings schema for every key
// it sets, and merged with the image's drop-in as Claude merges them, which
// must leave the image's hook contract and pins intact.
func (c *ClaudeCodeConnector) SandboxRunFiles(target SandboxRenderTarget, run SandboxRunConfig) ([]SandboxFile, error) {
	rt, err := resolveSandboxTarget(c.Name(), target)
	if err != nil {
		return nil, err
	}
	if err := validateSandboxMCPServers(run.MCPServers); err != nil {
		return nil, fmt.Errorf("claudecode run config: %w", err)
	}
	base, err := renderClaudeCodeSandboxDropIn(rt)
	if err != nil {
		return nil, err
	}
	servers := sortedSandboxMCPServers(run.MCPServers)
	settings, err := claudeCodeSandboxRunSettings(run, servers)
	if err != nil {
		return nil, err
	}
	dropIn, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Claude Code run settings: %w", err)
	}
	dropIn = append(dropIn, '\n')
	if err := validateClaudeCodeRunSettingsSchema(dropIn); err != nil {
		return nil, fmt.Errorf("claudecode run config: %w", err)
	}
	if err := verifyClaudeCodeSandboxRunDropIn(base, dropIn, settings, rt); err != nil {
		return nil, err
	}
	files := []SandboxFile{{Path: ClaudeCodeSandboxRunDropInPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: dropIn}}
	mcp, err := claudeCodeSandboxMCPConfig(servers)
	if err != nil {
		return nil, err
	}
	switch {
	case !run.AllowProjectMCPServers:
		files = append(files, SandboxFile{Path: ClaudeCodeSandboxManagedMCPPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: mcp})
	case len(servers) > 0:
		files = append(files, SandboxFile{Path: ClaudeCodeSandboxRunMCPServersPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: mcp})
	}
	return files, nil
}

// claudeCodeSandboxRunSettings builds the per-run drop-in document.
func claudeCodeSandboxRunSettings(run SandboxRunConfig, servers []SandboxMCPServer) (map[string]interface{}, error) {
	credentials := map[string]bool{}
	for _, name := range run.Credentials {
		credentials[name] = true
	}
	env := map[string]interface{}{}
	for _, key := range claudeCodeSandboxProviderEnv {
		if credentials[key] {
			continue
		}
		value := run.Env[key]
		if strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("claudecode run config: %s contains NUL or a line break", key)
		}
		env[key] = value
	}
	for _, key := range claudeCodeSandboxModelEnv {
		value := run.Env[key]
		if value == "" || credentials[key] {
			continue
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("claudecode run config: %s contains NUL or a line break", key)
		}
		env[key] = value
	}
	settings := map[string]interface{}{"env": env}
	if run.Safe {
		settings["permissions"] = map[string]interface{}{"disableBypassPermissionsMode": "disable"}
		settings["skipDangerousModePermissionPrompt"] = false
	}
	if !run.AllowProjectMCPServers {
		allowed := make([]interface{}, 0, len(servers))
		for _, s := range servers {
			if s.Remote() {
				allowed = append(allowed, map[string]interface{}{"serverUrl": s.URL})
				continue
			}
			command := []interface{}{s.Command}
			for _, arg := range s.Args {
				command = append(command, arg)
			}
			allowed = append(allowed, map[string]interface{}{"serverCommand": command})
		}
		settings["allowManagedMcpServersOnly"] = true
		settings["allowedMcpServers"] = allowed
	}
	return settings, nil
}

// claudeCodeSandboxMCPConfig renders {"mcpServers": {...}} in the shape of
// .mcp.json and managed-mcp.json.
func claudeCodeSandboxMCPConfig(servers []SandboxMCPServer) ([]byte, error) {
	out := map[string]interface{}{}
	for _, s := range servers {
		if s.Remote() {
			transport := s.Transport
			if transport == "" {
				transport = "http"
			}
			out[s.Name] = map[string]interface{}{"type": transport, "url": s.URL}
			continue
		}
		args := append([]string{}, s.Args...)
		entry := map[string]interface{}{"type": "stdio", "command": s.Command, "args": args}
		if len(s.Env) > 0 {
			entry["env"] = s.Env
		}
		out[s.Name] = entry
	}
	body, err := json.MarshalIndent(map[string]interface{}{"mcpServers": out}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Claude Code MCP servers: %w", err)
	}
	return append(body, '\n'), nil
}

// claudeCodeServerNamePattern is the 2.1.156 allowlist serverName pattern.
var claudeCodeServerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validateClaudeCodeRunSettingsSchema checks the per-run drop-in against the
// Claude Code 2.1.156 settings schema (zod) for every key DefenseClaw sets,
// read from the Claude Code binary:
//
//	env                               record(string, coerce.string)
//	permissions.disableBypassPermissionsMode  enum(["disable"])
//	skipDangerousModePermissionPrompt boolean
//	allowManagedMcpServersOnly        boolean
//	allowedMcpServers                 array(object{serverName: string
//	                                  /^[a-zA-Z0-9_-]+$/, serverCommand:
//	                                  array(string).min(1), serverUrl:
//	                                  string}) with exactly one field set
//
// Any other key is refused: one field Claude rejects makes it drop the whole
// file silently, taking the provider pin, the MCP allowlist and safe mode
// with it.
func validateClaudeCodeRunSettingsSchema(data []byte) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("run settings are not a JSON object: %w", err)
	}
	for key, value := range doc {
		switch key {
		case "env":
			env, ok := value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("env must be an object")
			}
			for name, v := range env {
				if !sandboxEnvNamePattern.MatchString(name) {
					return fmt.Errorf("env: invalid variable name %q", name)
				}
				if _, ok := v.(string); !ok {
					return fmt.Errorf("env.%s must be a string", name)
				}
			}
		case "permissions":
			perms, ok := value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("permissions must be an object")
			}
			for name, v := range perms {
				if name != "disableBypassPermissionsMode" {
					return fmt.Errorf("permissions.%s is not a key the run drop-in sets", name)
				}
				if v != "disable" {
					return fmt.Errorf(`permissions.disableBypassPermissionsMode must be "disable", got %#v`, v)
				}
			}
		case "skipDangerousModePermissionPrompt", "allowManagedMcpServersOnly":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		case "allowedMcpServers":
			entries, ok := value.([]interface{})
			if !ok {
				return fmt.Errorf("allowedMcpServers must be an array")
			}
			for i, raw := range entries {
				if err := validateClaudeCodeAllowlistEntry(raw); err != nil {
					return fmt.Errorf("allowedMcpServers[%d]: %w", i, err)
				}
			}
		default:
			return fmt.Errorf("%s is not a key the run drop-in sets", key)
		}
	}
	return nil
}

func validateClaudeCodeAllowlistEntry(raw interface{}) error {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("must be an object")
	}
	set := 0
	for key, value := range entry {
		set++
		switch key {
		case "serverName":
			name, ok := value.(string)
			if !ok || !claudeCodeServerNamePattern.MatchString(name) {
				return fmt.Errorf("serverName %#v must match %s", value, claudeCodeServerNamePattern)
			}
		case "serverCommand":
			parts, ok := value.([]interface{})
			if !ok || len(parts) == 0 {
				return fmt.Errorf("serverCommand must be a non-empty array")
			}
			for _, part := range parts {
				if _, ok := part.(string); !ok {
					return fmt.Errorf("serverCommand must hold strings only")
				}
			}
		case "serverUrl":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("serverUrl must be a string")
			}
		default:
			return fmt.Errorf("unknown field %s", key)
		}
	}
	if set != 1 {
		return fmt.Errorf(`must have exactly one of "serverName", "serverCommand" or "serverUrl"`)
	}
	return nil
}

// verifyClaudeCodeSandboxRunDropIn merges the image's drop-in and the run's
// as Claude does and checks that the image's hook contract and pins survive
// and that every run key reaches the merged managed tier unchanged.
func verifyClaudeCodeSandboxRunDropIn(base, dropIn []byte, want map[string]interface{}, rt resolvedSandboxTarget) error {
	var baseDoc map[string]interface{}
	if err := json.Unmarshal(base, &baseDoc); err != nil {
		return fmt.Errorf("verify Claude Code run settings: %w", err)
	}
	baseEnv, _ := baseDoc["env"].(map[string]interface{})
	for _, key := range append(ClaudeCodeSandboxProviderEnv(), claudeCodeSandboxModelEnv...) {
		if _, clash := baseEnv[key]; clash {
			return fmt.Errorf("verify Claude Code run settings: the image drop-in pins %s, which the run drop-in owns", key)
		}
	}
	source, err := stageClaudeCodeManagedSettings(map[string][]byte{
		claudeCodeSandboxDropInName:    base,
		claudeCodeSandboxRunDropInName: dropIn,
	})
	if err != nil {
		return err
	}
	if err := verifyClaudeCodeSandboxManagedSource(source, rt); err != nil {
		return err
	}
	merged := source.settings
	env, _ := merged["env"].(map[string]interface{})
	wantEnv, _ := want["env"].(map[string]interface{})
	keys := make([]string, 0, len(wantEnv))
	for key := range wantEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if env[key] != wantEnv[key] {
			return fmt.Errorf("verify Claude Code run settings: merged env %s = %#v, want %#v", key, env[key], wantEnv[key])
		}
	}
	for key, value := range baseEnv {
		if env[key] != value {
			return fmt.Errorf("verify Claude Code run settings: the run drop-in changed the image's env %s", key)
		}
	}
	perms, _ := merged["permissions"].(map[string]interface{})
	_, safe := want["permissions"]
	skip, _ := merged["skipDangerousModePermissionPrompt"].(bool)
	switch {
	case safe && (perms["disableBypassPermissionsMode"] != "disable" || skip):
		return fmt.Errorf("verify Claude Code run settings: safe mode did not disable bypassPermissions in the merged managed tier")
	case !safe && perms["disableBypassPermissionsMode"] != nil:
		return fmt.Errorf("verify Claude Code run settings: bypassPermissions is disabled outside safe mode")
	}
	for _, key := range []string{"allowManagedMcpServersOnly", "allowedMcpServers"} {
		got, present := merged[key]
		expected, wanted := want[key]
		if present != wanted || (wanted && !reflect.DeepEqual(got, jsonRoundTrip(expected))) {
			return fmt.Errorf("verify Claude Code run settings: merged %s = %#v, want %#v", key, got, expected)
		}
	}
	return nil
}

// jsonRoundTrip normalizes v to what encoding/json decodes it to.
func jsonRoundTrip(v interface{}) interface{} {
	body, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return v
	}
	return out
}
