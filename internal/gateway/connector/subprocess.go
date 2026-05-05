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

// Embed every .sh under hooks/, including helpers prefixed with `_`
// (Go's default embed skips `_*` and `.*` files; the `all:` prefix
// opts in). Plan B4 needs hooks/_hardening.sh in the embed.
//
//go:embed all:hooks
var hookFS embed.FS

// shimBinaries lists the high-risk commands that get PATH shims.
var shimBinaries = []string{"curl", "wget", "ssh", "nc", "pip", "npm"}

// templateData holds the values injected into hook and shim templates.
type templateData struct {
	APIAddr  string
	APIToken string // gateway bearer token; empty when unconfigured (loopback-allow)
	FailMode string // "open" (default, response-layer fails allow with a stderr warning) or "closed" (response-layer fails block); transport failures (gateway unreachable / 5xx) always fail open in the hooks unless DEFENSECLAW_STRICT_AVAILABILITY=1
}

// defaultHookFailMode is the fail mode injected into the response-
// layer ({{.FailMode}}) of every hook when the caller doesn't supply
// an explicit override. It governs ONLY response-layer failures —
// 4xx, malformed JSON, missing action — where the gateway answered
// but the answer was wrong (typically misconfiguration). Transport-
// layer failures (curl exit non-zero, 5xx) are handled by each
// hook's fail_unreachable helper in _hardening.sh and ALWAYS fail
// open unless the operator opts into strict availability via
// DEFENSECLAW_STRICT_AVAILABILITY=1.
//
// "open" is the default because a DefenseClaw hook that exits 2 on
// every gateway hiccup bricks the user's agent for the duration of
// any DefenseClaw outage, which is strictly worse UX than a brief
// observability gap. Operators who run a strict policy posture can
// flip this to "closed" via DEFENSECLAW_FAIL_MODE=closed at runtime
// or — for connectors that route through
// WriteHookScriptsForConnectorObjectWithOpts — by enabling per-
// connector enforcement at setup time.
const defaultHookFailMode = "open"

// normalizeHookFailMode coerces a caller-supplied string to one of
// the two values the hook scripts understand. Anything other than
// "closed" (case-sensitive — the env var contract is documented as
// lowercase) collapses to "open" so a typo never accidentally puts
// the agent into fail-closed mode.
func normalizeHookFailMode(mode string) string {
	if strings.TrimSpace(mode) == "closed" {
		return "closed"
	}
	return "open"
}

// WriteShimScripts generates PATH shim scripts for all high-risk binaries
// into the given directory. Each shim calls /api/v1/inspect/tool before
// delegating to the real binary.
func WriteShimScripts(shimDir, apiAddr string) error {
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}

	data := templateData{APIAddr: apiAddr, FailMode: defaultHookFailMode}

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

// hookHelperScripts lists support files that hooks `source` at runtime.
// They are written into the hook dir alongside the executable hooks but
// NEVER appear in HookScripts() / connector enumerations — agents do
// not invoke them directly. Plan B4: _hardening.sh centralizes the
// shell-side rlimit + env sanitization helpers.
var hookHelperScripts = []string{
	"_hardening.sh",
}

// writeHookHelpers writes the helper scripts (_hardening.sh, etc.) into
// hookDir at mode 0o600. Helpers are sourced — never executed
// directly — so they don't need the executable bit.
func writeHookHelpers(hookDir string) error {
	for _, name := range hookHelperScripts {
		content, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			return fmt.Errorf("read hook helper %s: %w", name, err)
		}
		helperPath := filepath.Join(hookDir, name)
		if err := os.WriteFile(helperPath, content, 0o600); err != nil {
			return fmt.Errorf("write hook helper %s: %w", name, err)
		}
	}
	return nil
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
//
// Plan B4: the shared _hardening.sh helper is also written so each
// hook can `source` it at runtime to pick up the rlimit + env
// sanitization policy.
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

	if err := writeHookHelpers(hookDir); err != nil {
		return err
	}

	// Never bake the real token into template output — scripts read
	// the .token file or the env var at runtime. FailMode defaults
	// to "open" so a fresh setup never bricks the agent on a
	// gateway outage; see defaultHookFailMode for rationale.
	data := templateData{APIAddr: apiAddr, APIToken: "", FailMode: defaultHookFailMode}

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

// writeHookScriptsCommon shares the on-disk dance (mkdir, .token,
// helpers) between every variant. `extras` is the per-connector list
// of basenames stacked on top of the generic ones. Returning an error
// if a name is not in the embed FS is intentional (plan C2): a
// connector that mis-spells a hook name fails loud at setup, never
// silently ships a hook dir missing its template.
func writeHookScriptsCommon(hookDir, apiAddr, token string, extras []string) error {
	return writeHookScriptsCommonWithFailMode(hookDir, apiAddr, token, defaultHookFailMode, extras)
}

func writeHookScriptsCommonWithFailMode(hookDir, apiAddr, token, failMode string, extras []string) error {
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("create hook dir: %w", err)
	}

	tokenPath := filepath.Join(hookDir, ".token")
	tokenContent := fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", token)
	if err := os.WriteFile(tokenPath, []byte(tokenContent), 0o600); err != nil {
		return fmt.Errorf("write hook token file: %w", err)
	}

	if err := writeHookHelpers(hookDir); err != nil {
		return err
	}

	data := templateData{APIAddr: apiAddr, APIToken: "", FailMode: normalizeHookFailMode(failMode)}

	scripts := make([]string, 0, len(genericHookScripts)+len(extras))
	scripts = append(scripts, genericHookScripts...)
	// De-dup: generic scripts must never collide with connector-owned
	// names, but a hostile/buggy connector returning "inspect-tool.sh"
	// shouldn't be silently overwritten by the second iteration. Skip
	// duplicates and keep the first occurrence.
	seen := make(map[string]struct{}, len(scripts))
	for _, n := range scripts {
		seen[n] = struct{}{}
	}
	for _, n := range extras {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		scripts = append(scripts, n)
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

// WriteHookScriptsForConnectorObject is the canonical, interface-driven
// entry (plan C2 / S2.5). The connector itself is the source of truth
// for which vendor-specific hook templates land in hookDir: if it
// implements HookScriptOwner, those names are unioned with the
// generic inspect-* set; if not, only the generic scripts are written.
//
// Prefer this over the string-keyed WriteHookScriptsForConnector for
// new callsites. The string variant is preserved as a thin wrapper for
// CLI paths that resolve connectors by name.
func WriteHookScriptsForConnectorObject(hookDir, apiAddr, token string, c Connector) error {
	opts := SetupOpts{APIAddr: apiAddr, APIToken: token}
	var extras []string
	if owner, ok := c.(HookScriptOwner); ok {
		extras = owner.HookScriptNames(opts)
	}
	return writeHookScriptsCommon(hookDir, apiAddr, token, extras)
}

// WriteHookScriptsForConnectorObjectWithOpts is the setup-time variant that
// has access to connector enforcement flags AND the operator's
// chosen response-layer fail mode (opts.HookFailMode).
//
// Resolution order for the response-layer FailMode template var
// (see templateData.FailMode and defaultHookFailMode for the
// contract):
//
//  1. An EXPLICIT operator value in opts.HookFailMode — either
//     "open" or "closed" — always wins. The operator answered
//     `defenseclaw setup guardrail`'s fail-mode prompt (or used
//     `defenseclaw guardrail fail-mode <value>`); silently
//     overriding their answer would violate the operator-defined
//     fail-mode contract documented in
//     “GuardrailConfig.HookFailMode“.
//  2. EMPTY/unset opts.HookFailMode falls back to per-connector
//     enforcement: enabling proxy-redirect enforcement
//     (CodexEnforcement / ClaudeCodeEnforcement) implies a strict
//     policy posture, so the response-layer default flips to
//     "closed" too. This only fires when the operator never made
//     an explicit choice.
//  3. Otherwise: defaultHookFailMode ("open").
//
// Transport-layer failures (gateway unreachable / 5xx) are NOT
// governed by FailMode — they always allow unless the operator opts
// in via DEFENSECLAW_STRICT_AVAILABILITY=1, regardless of which
// connector, enforcement state, or HookFailMode value.
func WriteHookScriptsForConnectorObjectWithOpts(hookDir string, opts SetupOpts, c Connector) error {
	var extras []string
	if owner, ok := c.(HookScriptOwner); ok {
		extras = owner.HookScriptNames(opts)
	}
	// Distinguish "operator did not answer" (empty string — fall
	// through to enforcement-derived default) from an explicit
	// "open" answer that must NOT be silently upgraded by the
	// per-connector enforcement flags below. normalizeHookFailMode
	// collapses both to "open", so we have to inspect the raw input
	// here before normalisation to preserve the operator's intent.
	rawTrimmed := strings.TrimSpace(opts.HookFailMode)
	explicitChoice := rawTrimmed != ""
	failMode := normalizeHookFailMode(opts.HookFailMode)
	if !explicitChoice && failMode != "closed" {
		switch c.Name() {
		case "codex":
			if opts.CodexEnforcement {
				failMode = "closed"
			}
		case "claudecode":
			if opts.ClaudeCodeEnforcement {
				failMode = "closed"
			}
		}
	}
	return writeHookScriptsCommonWithFailMode(hookDir, opts.APIAddr, opts.APIToken, failMode, extras)
}

// WriteHookScriptsForConnector generates the generic inspection scripts
// plus only the connector-specific lifecycle script for the named
// connector. Avoids writing vendor-specific scripts (e.g. codex-hook.sh)
// into hook directories of unrelated connectors.
//
// Plan C2 / S2.5: this is now a back-compat shim over the
// interface-driven WriteHookScriptsForConnectorObject. It first tries
// the default registry (so a real connector's HookScriptOwner is
// authoritative) and falls back to the legacy package-level map for
// names that aren't registered (older tests / CLI fixtures).
func WriteHookScriptsForConnector(hookDir, apiAddr, token, connectorName string) error {
	if c, ok := NewDefaultRegistry().Get(connectorName); ok {
		return WriteHookScriptsForConnectorObject(hookDir, apiAddr, token, c)
	}
	extras := connectorHookScripts[connectorName]
	return writeHookScriptsCommon(hookDir, apiAddr, token, extras)
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
