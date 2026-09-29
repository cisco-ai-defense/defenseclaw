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
	"path"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// In-image OmniGent policy. OmniGent evaluates policies in its server: the
// server loads the modules named by policy_modules and attaches the
// server-wide entries of policies from its configuration, which a local
// server started by `omnigent run` reads from $OMNIGENT_CONFIG_HOME/config.yaml.
// The image ships that configuration root-owned under /etc/omnigent (the
// launcher points OMNIGENT_CONFIG_HOME there), and the policy bridge
// root-owned beside the other DefenseClaw runtime files, on the harness's
// import path through a .pth file the harness install writes. The bridge is
// the host bridge rendered for the sandbox ingress with the sandbox
// transport appended (hooks/omnigent-policy-sandbox.py).
const (
	OmnigentSandboxConfigHome = "/etc/omnigent"
	OmnigentSandboxConfigPath = OmnigentSandboxConfigHome + "/config.yaml"
)

// OmnigentSandboxMinVersion is the oldest OmniGent DefenseClaw's sandbox
// images accept. The sandbox agent's openai-agents harness runs in
// OmniGent's runner, whose stream the server relays, and before 0.13.0 the
// server evaluated the response phase only for an assistant message posted
// to its events route, which a runner-relayed harness never posts: 0.13.0
// added the relay's own response-phase check (server/routes/_sessions
// _relay_response_policy_deny_reason). An image of 0.12.0, inside the host
// contract, failed the hook-fire probe with "hook AfterAgentResponse never
// fired" (RT-A-2), so a sandbox refuses anything older before it builds.
const OmnigentSandboxMinVersion = "0.13.0"

// omnigentSandboxHookContracts is omnigent-custom-policy-v1 as DefenseClaw's
// OpenShell images run it: the Linux host contract from
// OmnigentSandboxMinVersion. It keeps the host contract's ID, so a binding
// that pins it resolves to the same events and capabilities.
func omnigentSandboxHookContracts() []HookContract {
	contracts := hookContractsForOS("omnigent", "linux")
	for i := range contracts {
		contracts[i].MinAgentVersion = OmnigentSandboxMinVersion
		contracts[i].Notes = append(contracts[i].Notes,
			"Sandbox images start at OmniGent "+OmnigentSandboxMinVersion+": before it the server never evaluated the response phase (AfterAgentResponse) for the sandbox agent, whose runner it relays.")
	}
	return contracts
}

// omnigentSandboxRefusal is why a sandbox refuses an OmniGent the host
// contract accepts.
const omnigentSandboxRefusal = "OmniGent before " + OmnigentSandboxMinVersion + " never runs the response policy phase (AfterAgentResponse) for the sandbox agent, " +
	"whose runner its server relays, so its image cannot pass the hook-fire probe; sandbox images accept >=" + OmnigentSandboxMinVersion + ",<0.14.0"

// OmnigentSandboxPolicyDir holds the root-owned policy bridge; the harness
// install adds it to the OmniGent environment's import path.
var OmnigentSandboxPolicyDir = SandboxCanonicalDir("omnigent")

// OmnigentSandboxPolicyModulePath is the bridge module file.
var OmnigentSandboxPolicyModulePath = path.Join(OmnigentSandboxPolicyDir, omnigentPolicyModuleName+".py")

// OmnigentSandboxAgentPath is the agent the image ships for sandboxes, and
// the default agent of `omnigent run --model <m>`: an openai-agents coding agent
// whose os_env shell runs in the caller process without OmniGent's own
// bubblewrap sandbox, which cannot nest inside OpenShell. Every tool call
// still passes the DefenseClaw policy.
var OmnigentSandboxAgentPath = path.Join(OmnigentSandboxPolicyDir, "agent")

// omnigentSandboxAgent is the sandbox agent's spec. A DefenseClaw deny
// reaches the user only through the model: OmniGent 0.13.0's TUI hides tool
// results until Ctrl+T (with no setting to show them), the deny reason
// travels only as the denied call's tool result, a policy result has no
// field meant for the user (result, reason, data, state_updates,
// set_labels), and the TUI does not render the server's
// response.policy_denied event. So the prompt asks the model to pass the
// reason on.
const omnigentSandboxAgent = `# DefenseClaw OmniGent agent for OpenShell sandboxes (root-owned).
# OpenShell is the sandbox: OmniGent's own bubblewrap sandbox cannot nest
# inside it, so the shell runs in the caller process. Every request, model
# call and tool call still passes the DefenseClaw policy the server loads.
spec_version: 1
name: defenseclaw-sandbox
description: >-
  Coding agent for DefenseClaw OpenShell sandboxes, with a shell and file
  tools in the working directory.
executor:
  type: omnigent
  config:
    harness: openai-agents
os_env:
  type: caller_process
  cwd: .
  sandbox:
    type: none
prompt: |
  You are a coding agent working in the current directory, which is the
  user's project inside a DefenseClaw OpenShell sandbox. Use your sys_os_*
  tools to read, edit and run what the task needs.

  DefenseClaw checks every tool call, and the user's terminal does not show
  tool results. When a tool result says the call was denied by policy, tell
  the user that DefenseClaw blocked it and quote the reason the result
  gives, word for word, before you go on.
`

// SandboxArtifacts renders the OmniGent overlay: the policy bridge and the
// server configuration that loads and attaches it.
func (c *OmnigentConnector) SandboxArtifacts(target SandboxRenderTarget) (SandboxArtifacts, error) {
	rt, err := resolveSandboxTarget(c.Name(), target)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	module, err := renderOmnigentSandboxPolicy(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	config, err := renderOmnigentSandboxConfig(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyOmnigentSandboxConfig(config); err != nil {
		return SandboxArtifacts{}, err
	}
	return finalizeSandboxArtifacts(SandboxArtifacts{
		Connector:    c.Name(),
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierManaged,
		Files: []SandboxFile{
			{Path: OmnigentSandboxPolicyModulePath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: module},
			{Path: OmnigentSandboxConfigPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: config},
			{Path: path.Join(OmnigentSandboxAgentPath, "config.yaml"), Mode: 0o644, Owner: SandboxOwnerRoot, Data: []byte(omnigentSandboxAgent)},
		},
		Env:      map[string]string{},
		Binaries: []SandboxBinary{{Name: "omnigent", Role: SandboxBinaryHarness}},
	})
}

// renderOmnigentSandboxPolicy renders the bridge with the baked ingress, no
// token file and fail mode closed, then appends the sandbox transport, whose
// defenseclaw_policy replaces the host one.
func renderOmnigentSandboxPolicy(rt resolvedSandboxTarget) ([]byte, error) {
	template, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		return nil, fmt.Errorf("omnigent read policy template: %w", err)
	}
	tail, err := hookFS.ReadFile("hooks/omnigent-policy-sandbox.py")
	if err != nil {
		return nil, fmt.Errorf("omnigent read sandbox transport: %w", err)
	}
	rendered := renderOmnigentPolicy(string(template), rt.ingressAddr, "", rt.failMode)
	for _, token := range []string{"{{API_ADDR_B64}}", "{{TOKEN_FILE_B64}}", "{{FAIL_MODE_B64}}"} {
		if strings.Contains(rendered, token) {
			return nil, fmt.Errorf("omnigent sandbox policy left %s unrendered", token)
		}
	}
	return []byte(rendered + string(tail)), nil
}

// omnigentSandboxConfig is the server configuration the image pins. The CLI
// reads the same file as its global configuration, so default_agent makes a
// bare `omnigent run` start the sandbox agent: without it OmniGent falls
// back to its first-run plan (polly, Codex or Pi), which needs native CLIs
// and a bubblewrap sandbox the image does not have.
//
// The TUI keeps its user preferences (tui.theme) in the same file. Without
// a theme its first-launch picker runs whenever a terminal is attached and
// then fails writing this root-owned file, which ends the session before
// the REPL starts (omnigent-ui-sdk 0.13.0 _config.update_user_config), so
// the image pins OmniGent's dark theme; /theme cannot change it inside a
// sandbox.
//
// telemetry: false switches off OmniGent's usage telemetry, which otherwise
// fetches config.omnigent-telemetry.io at every server start and posts
// events to its ingestion host (omnigent 0.13.0 telemetry/client.py). Every
// OmniGent process reads this file through OMNIGENT_CONFIG_HOME, including
// the runner, whose environment OmniGent strips to an allowlist that an
// environment switch such as OMNIGENT_DISABLE_TELEMETRY is not on.
func omnigentSandboxConfig() map[string]interface{} {
	return map[string]interface{}{
		"default_agent":  OmnigentSandboxAgentPath,
		"policy_modules": []interface{}{omnigentPolicyModuleName},
		"policies": map[string]interface{}{
			omnigentPolicyConfigKey: map[string]interface{}{"type": "function", "handler": omnigentPolicyHandler},
		},
		"telemetry": false,
		"tui":       map[string]interface{}{"theme": "dark"},
	}
}

// omnigentThemeNote explains, in the file OmniGent's /theme error names
// ("Failed to write TUI user config at /etc/omnigent/config.yaml: [Errno
// 13] Permission denied"), why the theme cannot change. The file cannot be
// made writable, nor its directory (the TUI writes a temporary file there
// and renames it over this one): it carries DefenseClaw's policy.
const omnigentThemeNote = "# OmniGent's /theme cannot change the TUI theme in a sandbox: it writes this file,\n" +
	"# which holds DefenseClaw's policy and stays root-owned, so the theme is pinned to dark.\n"

func renderOmnigentSandboxConfig(rt resolvedSandboxTarget) ([]byte, error) {
	body, err := yaml.Marshal(omnigentSandboxConfig())
	if err != nil {
		return nil, fmt.Errorf("marshal OmniGent sandbox config: %w", err)
	}
	header := "# DefenseClaw managed OmniGent server configuration (OpenShell sandbox image, root-owned).\n" +
		"# Read through OMNIGENT_CONFIG_HOME=" + OmnigentSandboxConfigHome + "; policy contract " + rt.contract.ContractID + ".\n" +
		omnigentThemeNote
	return append([]byte(header), body...), nil
}

// verifyOmnigentSandboxConfig reads the configuration back and requires the
// DefenseClaw module, its server-wide policy, telemetry off and the pinned
// TUI theme, and nothing else.
func verifyOmnigentSandboxConfig(data []byte) error {
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("verify OmniGent sandbox config: %w", err)
	}
	if !reflect.DeepEqual(cfg, omnigentSandboxConfig()) {
		return fmt.Errorf("verify OmniGent sandbox config: got %v", cfg)
	}
	return nil
}

var _ SandboxArtifactProvider = (*OmnigentConnector)(nil)
