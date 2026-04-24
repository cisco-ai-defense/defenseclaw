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
)

//go:embed shims/*.sh
var shimFS embed.FS

//go:embed hooks/*.sh
var hookFS embed.FS

// shimBinaries lists the high-risk commands that get PATH shims.
var shimBinaries = []string{"curl", "wget", "ssh", "nc", "pip", "npm"}

// templateData holds the values injected into hook and shim templates.
type templateData struct {
	APIAddr string
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
		if err := os.WriteFile(shimPath, []byte(rendered), 0o755); err != nil {
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

// hookScripts lists all hook scripts that are generated at setup time.
var hookScripts = []string{
	"inspect-tool.sh",
	"inspect-request.sh",
	"inspect-response.sh",
	"inspect-tool-response.sh",
	"claude-code-hook.sh",
	"codex-hook.sh",
}

// WriteHookScript generates the shared inspect-tool.sh hook script.
// Kept for backward compatibility — calls WriteAllHookScripts internally.
func WriteHookScript(hookDir, apiAddr string) error {
	return WriteAllHookScripts(hookDir, apiAddr)
}

// WriteAllHookScripts generates all four hook scripts into hookDir:
//   - inspect-tool.sh       (pre-tool: inspect tool args before execution)
//   - inspect-request.sh    (pre-request: inspect user query before LLM call)
//   - inspect-response.sh   (post-response: inspect LLM response)
//   - inspect-tool-response.sh (post-tool: inspect tool output before LLM sees it)
func WriteAllHookScripts(hookDir, apiAddr string) error {
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		return fmt.Errorf("create hook dir: %w", err)
	}

	data := templateData{APIAddr: apiAddr}

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
		if err := os.WriteFile(hookPath, []byte(rendered), 0o755); err != nil {
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

// WriteSandboxPolicy generates a sandbox policy YAML for OpenShell enforcement.
// The policy restricts exec, network egress, and filesystem writes.
func WriteSandboxPolicy(dataDir, proxyAddr, apiAddr string) error {
	policyDir := filepath.Join(dataDir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		return fmt.Errorf("create policy dir: %w", err)
	}

	policy := fmt.Sprintf(`sandbox:
  mode: enforce
  exec:
    allow:
      - /usr/bin/git
      - /usr/bin/node
      - /usr/bin/python3
      - /usr/bin/npm
    deny:
      - /usr/bin/curl
      - /usr/bin/wget
      - "**/nc"
      - "**/ncat"
      - "**/ssh"
  network:
    allow_egress:
      - %s
      - %s
    deny_egress: "*"
  filesystem:
    deny_write:
      - /etc/
      - ~/.ssh/
      - ~/.aws/credentials
`, proxyAddr, apiAddr)

	policyPath := filepath.Join(policyDir, "defenseclaw-policy.yaml")
	return os.WriteFile(policyPath, []byte(policy), 0o644)
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
