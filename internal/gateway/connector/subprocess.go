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
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

//go:embed shims/*.sh
var shimFS embed.FS

//go:embed hooks/*.sh
var hookFS embed.FS

// shimBinaries lists the high-risk commands that get PATH shims.
var shimBinaries = []string{"curl", "wget", "ssh", "nc", "pip", "npm"}

// templateData holds the values injected into hook and shim templates.
type templateData struct {
	APIAddr  string
	APIToken string // gateway bearer token; empty when unconfigured (loopback-allow)
}

// WriteShimScripts generates PATH shim scripts for all high-risk binaries
// into the given directory. Each shim calls /api/v1/inspect/tool before
// delegating to the real binary.
func WriteShimScripts(shimDir, apiAddr string) error {
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}

	data := templateData{APIAddr: apiAddr}

	for _, name := range shimBinaries {
		content, err := shimFS.ReadFile("shims/" + name + ".sh")
		if err != nil {
			return fmt.Errorf("read shim template %s: %w", name, err)
		}

		rendered, err := renderTemplate(string(content), data)
		if err != nil {
			return fmt.Errorf("render shim %s: %w", name, err)
		}

		shimPath := filepath.Join(shimDir, name)
		if err := os.WriteFile(shimPath, []byte(rendered), 0o700); err != nil {
			return fmt.Errorf("write shim %s: %w", name, err)
		}
	}

	// Create ncat symlink to nc shim
	ncatPath := filepath.Join(shimDir, "ncat")
	_ = os.Remove(ncatPath)
	if err := os.Symlink("nc", ncatPath); err != nil {
		return fmt.Errorf("symlink ncat → nc: %w", err)
	}

	return nil
}

// genericHookScripts are agent-agnostic inspection scripts generated for
// every connector.
var genericHookScripts = []string{
	"inspect-tool.sh",
	"inspect-request.sh",
	"inspect-response.sh",
	"inspect-tool-response.sh",
}

// connectorHookScripts maps connector names to their agent-specific
// lifecycle hook scripts. Only the matching connector's scripts are
// written during setup.
var connectorHookScripts = map[string][]string{
	"claudecode": {"claude-code-hook.sh"},
	"codex":      {"codex-hook.sh"},
}

// hookScripts returns the full list of hook scripts (generic + all
// connector-specific) for backward compatibility with tests and
// teardown logic that enumerate all possible scripts.
var hookScripts = func() []string {
	all := make([]string, len(genericHookScripts))
	copy(all, genericHookScripts)
	for _, scripts := range connectorHookScripts {
		all = append(all, scripts...)
	}
	return all
}()

// WriteHookScript generates the shared inspect-tool.sh hook script.
// Kept for backward compatibility — calls WriteHookScriptsWithToken with
// an empty token (loopback-allow path).
func WriteHookScript(hookDir, apiAddr string) error {
	return WriteHookScriptsWithToken(hookDir, apiAddr, "")
}

// WriteHookScriptsWithToken generates every hook script into hookDir,
// baking the gateway bearer token into the curl Authorization header so
// the API server's auth middleware accepts the hook's POST. When token
// is empty the scripts omit the header entirely so the middleware's
// loopback-allow branch still applies.
//
// Hook scripts generated:
//   - inspect-tool.sh          (pre-tool)
//   - inspect-request.sh       (pre-request)
//   - inspect-response.sh      (post-response)
//   - inspect-tool-response.sh (post-tool)
//   - claude-code-hook.sh      (Claude Code lifecycle events)
//   - codex-hook.sh            (Codex lifecycle events)
func WriteHookScriptsWithToken(hookDir, apiAddr, token string) error {
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("create hook dir: %w", err)
	}

	// Write the token to a separate file with restrictive permissions
	// instead of baking it into the script body. The scripts source
	// this file at runtime.
	tokenPath := filepath.Join(hookDir, ".token")
	tokenContent := fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", token)
	if err := os.WriteFile(tokenPath, []byte(tokenContent), 0o600); err != nil {
		return fmt.Errorf("write hook token file: %w", err)
	}

	// Never bake the real token into template output — scripts read
	// the .token file or the env var at runtime.
	data := templateData{APIAddr: apiAddr, APIToken: ""}

	for _, name := range hookScripts {
		content, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			return fmt.Errorf("read hook template %s: %w", name, err)
		}

		rendered, err := renderTemplate(string(content), data)
		if err != nil {
			return fmt.Errorf("render hook %s: %w", name, err)
		}

		hookPath := filepath.Join(hookDir, name)
		if err := os.WriteFile(hookPath, []byte(rendered), 0o700); err != nil {
			return fmt.Errorf("write hook %s: %w", name, err)
		}
	}

	return nil
}

// WriteAllHookScripts generates every hook script with no gateway token
// baked in (loopback-allow path). Kept for connectors that don't need
// the API bearer — e.g. the inspect-* hooks reach the chat-completions
// proxy on port 4000, which has its own X-DC-Auth path.
func WriteAllHookScripts(hookDir, apiAddr string) error {
	return WriteHookScriptsWithToken(hookDir, apiAddr, "")
}

// WriteHookScriptsForConnector generates the generic inspection scripts
// plus only the connector-specific lifecycle script for the named
// connector. Avoids writing vendor-specific scripts (e.g. codex-hook.sh)
// into hook directories of unrelated connectors.
func WriteHookScriptsForConnector(hookDir, apiAddr, token, connectorName string) error {
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("create hook dir: %w", err)
	}

	tokenPath := filepath.Join(hookDir, ".token")
	tokenContent := fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", token)
	if err := os.WriteFile(tokenPath, []byte(tokenContent), 0o600); err != nil {
		return fmt.Errorf("write hook token file: %w", err)
	}

	data := templateData{APIAddr: apiAddr, APIToken: ""}

	scripts := make([]string, len(genericHookScripts))
	copy(scripts, genericHookScripts)
	if extra, ok := connectorHookScripts[connectorName]; ok {
		scripts = append(scripts, extra...)
	}

	for _, name := range scripts {
		content, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			return fmt.Errorf("read hook template %s: %w", name, err)
		}
		rendered, err := renderTemplate(string(content), data)
		if err != nil {
			return fmt.Errorf("render hook %s: %w", name, err)
		}
		hookPath := filepath.Join(hookDir, name)
		if err := os.WriteFile(hookPath, []byte(rendered), 0o700); err != nil {
			return fmt.Errorf("write hook %s: %w", name, err)
		}
	}
	return nil
}

// HookScripts returns the list of hook script names that are generated.
func HookScripts() []string {
	out := make([]string, len(hookScripts))
	copy(out, hookScripts)
	return out
}

type sandboxPolicy struct {
	Sandbox struct {
		Mode       string         `yaml:"mode"`
		Exec       sandboxExec    `yaml:"exec"`
		Network    sandboxNetwork `yaml:"network"`
		Filesystem sandboxFilesys `yaml:"filesystem"`
	} `yaml:"sandbox"`
}

type sandboxExec struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type sandboxNetwork struct {
	AllowEgress []string `yaml:"allow_egress"`
	DenyEgress  string   `yaml:"deny_egress"`
}

type sandboxFilesys struct {
	DenyWrite []string `yaml:"deny_write"`
}

// WriteSandboxPolicy generates a sandbox policy YAML for OpenShell enforcement.
// The policy restricts exec, network egress, and filesystem writes.
func WriteSandboxPolicy(dataDir, proxyAddr, apiAddr string) error {
	policyDir := filepath.Join(dataDir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		return fmt.Errorf("create policy dir: %w", err)
	}

	var pol sandboxPolicy
	pol.Sandbox.Mode = "enforce"
	pol.Sandbox.Exec.Allow = []string{
		"/usr/bin/git", "/usr/bin/node", "/usr/bin/python3", "/usr/bin/npm",
	}
	pol.Sandbox.Exec.Deny = []string{
		"/usr/bin/curl", "/usr/bin/wget", "**/nc", "**/ncat", "**/ssh",
	}
	pol.Sandbox.Network.AllowEgress = []string{proxyAddr, apiAddr}
	pol.Sandbox.Network.DenyEgress = "*"
	pol.Sandbox.Filesystem.DenyWrite = []string{"/etc/", "~/.ssh/", "~/.aws/credentials"}

	out, err := yaml.Marshal(&pol)
	if err != nil {
		return fmt.Errorf("marshal sandbox policy: %w", err)
	}

	policyPath := filepath.Join(policyDir, "defenseclaw-policy.yaml")
	return os.WriteFile(policyPath, out, 0o644)
}

// ResolveSubprocessPolicy determines the effective subprocess policy for
// this platform. Sandbox requires Linux (Landlock + seccomp); macOS and
// other platforms fall back to shims.
func ResolveSubprocessPolicy(preferred SubprocessPolicy) SubprocessPolicy {
	if preferred == SubprocessNone {
		return SubprocessNone
	}
	if preferred == SubprocessSandbox && runtime.GOOS != "linux" {
		return SubprocessShims
	}
	return preferred
}

// SetupSubprocessEnforcement wires the appropriate subprocess enforcement
// tier based on the resolved policy.
func SetupSubprocessEnforcement(policy SubprocessPolicy, opts SetupOpts) error {
	switch policy {
	case SubprocessSandbox:
		if err := WriteSandboxPolicy(opts.DataDir, opts.ProxyAddr, opts.APIAddr); err != nil {
			return fmt.Errorf("sandbox policy: %w", err)
		}
		shimDir := filepath.Join(opts.DataDir, "shims")
		if err := WriteShimScripts(shimDir, opts.APIAddr); err != nil {
			return fmt.Errorf("shim scripts (sandbox supplement): %w", err)
		}

	case SubprocessShims:
		shimDir := filepath.Join(opts.DataDir, "shims")
		if err := WriteShimScripts(shimDir, opts.APIAddr); err != nil {
			return fmt.Errorf("shim scripts: %w", err)
		}

	case SubprocessNone:
		// No enforcement to set up.
	}
	return nil
}

// TeardownSubprocessEnforcement removes shim scripts, individual hook scripts,
// and sandbox policies. It removes files by name rather than nuking the shared
// hooks/ directory, which may be used by other active connectors.
func TeardownSubprocessEnforcement(opts SetupOpts) error {
	shimDir := filepath.Join(opts.DataDir, "shims")
	_ = os.RemoveAll(shimDir)

	hookDir := filepath.Join(opts.DataDir, "hooks")
	for _, name := range hookScripts {
		_ = os.Remove(filepath.Join(hookDir, name))
	}

	policyPath := filepath.Join(opts.DataDir, "policies", "defenseclaw-policy.yaml")
	_ = os.Remove(policyPath)

	return nil
}

// ShimBinaries returns the list of binary names that are shimmed.
func ShimBinaries() []string {
	out := make([]string, len(shimBinaries))
	copy(out, shimBinaries)
	return out
}

func renderTemplate(tmpl string, data templateData) (string, error) {
	t, err := template.New("").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
