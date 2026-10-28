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
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/template"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

//go:embed shims/*.sh shims/peer.inc
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
	APIAddr     string
	APIToken    string // gateway bearer token; empty when unconfigured (loopback-allow)
	TokenFileJS string // absolute token path, escaped for a JavaScript double-quoted string
	// NativePostBinaryJS is the administrator-owned native gateway helper a
	// Secure Client plugin uses to verify the connected service before POST.
	NativePostBinaryJS string
	// GatewayBinaryJS is the gateway binary a per-user in-agent plugin runs
	// for hook-post and session facts (perUserPluginGatewayBinary), escaped
	// for a JavaScript double-quoted string; empty keeps ~/.local/bin.
	GatewayBinaryJS string
	// HookSocketJS is the standalone gateway's unix hook socket, escaped for a
	// JavaScript double-quoted string; empty keeps the TCP transport.
	HookSocketJS string
	// InstallMarkerJS is the managed deployment's install marker, escaped for
	// a JavaScript double-quoted string; empty when unused.
	InstallMarkerJS string
	// LifecycleMarkerJS is the standalone Unix lifecycle's public, root-owned
	// run marker. Plugins close promptly while install or upgrade holds it.
	LifecycleMarkerJS string
	// ServiceUID is the standalone gateway's service uid trusted as the
	// hook socket owner (with root); 0 when unused.
	ServiceUID int
	// ForeignHookGuardJS is the administrator-owned hook binary an in-agent
	// plugin runs for the standalone foreign-hook guard, escaped for a
	// JavaScript double-quoted string; empty skips the check.
	ForeignHookGuardJS string
	// ListenerProofJS is "1" when an in-agent plugin on loopback TCP must
	// make the listener prove it is the gateway before sending its per-user
	// credential (UserScopedListenerProof); empty skips the proof.
	ListenerProofJS string
	// WindowsPowerShellJS is the system Windows PowerShell (resolved with
	// GetSystemDirectoryW) a per-user plugin runs to check the native
	// helper's owner and DACL on Windows, escaped for a JavaScript
	// double-quoted string.
	WindowsPowerShellJS string
	FailMode            string // Rendered non-outage mode; per-user hooks bake "closed" and ask the current config for a classified outage.
	Managed             bool
	SecureClient        bool // render-time profile marker for Unix shell identity headers
	// SecureClientDelivery marks a Secure Client render on a verified install.
	// Every shell hook uses the installed mode, never the agent environment.
	SecureClientDelivery bool
	TokenFile            string
	// HookHomeSH is the data directory a per-user host render is written
	// into, quoted for a POSIX shell. The shell hooks look for the
	// installer's lock there as well, so a hard link, a symlink or a copy of
	// a hook run from any folder is held by that install's lock (oss-outage-
	// open round k). Empty for managed and sandbox renders and for a folder
	// that is not absolute.
	HookHomeSH    string
	ScopedToken   bool
	ConnectorName string
	HookBinaryPS  string // absolute launcher path, escaped for a PowerShell single-quoted literal
	HookTimeoutMS int    // Default native PowerShell adapter child timeout; zero for templates that do not use it
	// Cursor's 30-second host contract must also cover the stable launcher's
	// custody verification and the adapter's bounded child cleanup.
	CursorHookTimeoutMS int
	// Copilot has the same 30-second command-hook envelope and needs an
	// explicit byte-stream adapter for the GUI-subsystem launcher on Windows.
	CopilotHookTimeoutMS int
	// HookSocketTransportSH is the standalone unix-socket transport block a
	// connector shell hook runs before it builds its bearer header (see
	// shellHookSocketTransport). Empty keeps the TCP transport, and the
	// rendered hook is then byte-identical to one without the block.
	HookSocketTransportSH string
	// HermesNativeHookSH is a trusted, quoted managed hook binary path. The
	// Hermes shell keeps its registered command while the native hook handles
	// the answer and its delivery receipt.
	HermesNativeHookSH string
	// ManagedHTTPFailureSH is the one answer classifier rendered into each
	// standalone managed shell hook. Other profiles keep their pinned bytes.
	ManagedHTTPFailureSH string
	// ForeignHookGuardSH is the standalone foreign-hook guard block the
	// Hermes shell hook runs before its gateway request (see
	// shellHookForeignGuard). HookSocketTransportSH carries the block itself
	// (it runs before the socket checks, GAP-0354); the Hermes template
	// reads this field only to keep the agent's HOME for the check. Empty
	// for every other hook and install, whose renders are then
	// byte-identical to one without it.
	ForeignHookGuardSH string

	// Sandbox selects the OpenShell in-image variant (sandbox_hooks.go):
	// APIAddr is the baked hook ingress, FailMode is baked rather than
	// env-overridable, and the token comes only from DEFENSECLAW_SANDBOX_TOKEN.
	// Host renders leave it false and every Sandbox* field zero.
	Sandbox bool
	// Sandbox ingress budgets in whole seconds (curl --connect-timeout and
	// --max-time for the first attempt, the retry and Codex SessionEnd).
	SandboxConnectTimeout    int
	SandboxMaxTime           int
	SandboxRetryMaxTime      int
	SandboxSessionEndMaxTime int

	// CursorTargetModesJSON64 is the canonical, token-free protected
	// SID-to-delivery-mode map baked into the managed Windows Cursor adapter;
	// empty for every other render.
	CursorTargetModesJSON64 string
}

// defaultHookFailMode is injected into every hook when the caller does not
// supply an explicit override. It governs malformed/incomplete responses,
// authorization failures, and transport failures consistently. Strict
// availability remains an unconditional force-closed override.
//
// "closed" is the safer default: an absent or untrustworthy verdict BLOCKS
// rather than forwarding an uninspected action. Operators who would rather
// accept an observability gap than a hard block during a DefenseClaw
// outage choose "open" with guardrail fail-mode or the per-connector setup
// flow (both persist guardrail.hook_fail_mode in config.yaml). Shell hooks
// read only the installed fail mode (GAP-0461).
// Secure Client is the one profile whose unset mode renders open (secureClientHookFailMode, #1163).
const defaultHookFailMode = "closed"

// secureClientHookFailMode is the unset delivery mode under the Secure Client
// profile (#1163): availability failures are logged and the event allowed;
// valid policy denials still block.
const secureClientHookFailMode = "open"

// SecureClientDeploymentVerified reports whether this host is an
// authenticated Secure Client deployment. internal/cli sets it to its strict
// host classifier (managed_host_guard_windows.go on Windows: protected
// deployment metadata, trusted install tree and registered gateway service;
// the root-owned install directory on macOS; never on Linux), and every
// binary that renders or runs hooks links internal/cli. The Secure Client
// fail-open render defaults (setupHookFailMode, shellHookSecureClientDelivery)
// need it as well as the profile the caller resolved, so a process-level
// profile alone never opens a hook (main-sync review finding 5). The
// package default fails closed until the host classifier is linked.
var SecureClientDeploymentVerified = func() bool { return false }

// windowsHookAdapterTimeoutMS matches the existing 10-second connector request
// budget for adapters that do not have a larger documented host contract.
const windowsHookAdapterTimeoutMS = 10_000

// cursorWindowsHookAdapterTimeoutMS reserves the existing bounded kill/drain
// window from Cursor's exact 30-second command-hook contract.
// The remaining child budget covers both stable-launcher custody verification
// and the full hook's own bounded gateway request; those stages are serial and
// therefore cannot share the old 10-second request-only deadline.
const (
	cursorWindowsHookContractTimeoutMS  = 30_000
	cursorWindowsHookCleanupBudgetMS    = 5_000
	cursorWindowsHookAdapterTimeoutMS   = cursorWindowsHookContractTimeoutMS - cursorWindowsHookCleanupBudgetMS
	copilotWindowsHookContractTimeoutMS = 30_000
	copilotWindowsHookCleanupBudgetMS   = 5_000
	copilotWindowsHookAdapterTimeoutMS  = copilotWindowsHookContractTimeoutMS - copilotWindowsHookCleanupBudgetMS
)

// cursorAdapterTimeoutMS matches the existing 10-second Cursor shell-hook
// request budget while staying inside Cursor's 30-second command-hook timeout.
// Keeping the adapter bound shorter than the vendor timeout gives it time to
// terminate the launcher and emit the configured fail-open/fail-closed JSON.
const cursorAdapterTimeoutMS = 10_000

// normalizeHookFailMode coerces a caller-supplied string to one of
// the two values the hook scripts understand. Anything other than
// "open" (matched case-insensitively after trimming, like the config
// resolver) collapses to "closed", so an empty value or a typo never
// accidentally puts the agent into fail-OPEN mode at the hook failure
// boundary (CodeGuard rule codeguard-0-authorization-access-control: deny
// by default).
func normalizeHookFailMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "open") {
		return "open"
	}
	return "closed"
}

// setupHookFailMode is the delivery mode a render takes from opts without a
// connector-specific rule. Per-user hooks are always closed, including when
// an older config supplies open. A managed explicit value is normalized, and
// an unset value opens only under a verified Secure Client deployment.
func setupHookFailMode(opts SetupOpts) string {
	if !opts.ManagedEnterprise {
		return defaultHookFailMode
	}
	if strings.TrimSpace(opts.HookFailMode) == "" && opts.SecureClientHookDelivery && SecureClientDeploymentVerified() {
		return secureClientHookFailMode
	}
	return normalizeHookFailMode(opts.HookFailMode)
}

// WriteShimScripts generates PATH shim scripts for all high-risk binaries
// into the given directory. Each shim calls /api/v1/inspect/tool before
// delegating to the real binary.
//
// Avarice F-2029 / chain F-3397: the shim now authenticates each
// inspection call using the gateway bearer token. The token is written
// to ${shimDir}/.token (mode 0600) by WriteShimScriptsWithToken, the
// same way the inspect-* hooks discover their token. WriteShimScripts
// keeps the legacy no-token signature for backward compatibility but
// internally always lays down a (possibly empty) token file so the
// shim can find it; an empty token file produces shims that send no
// Authorization header — matching the loopback-allow path used by
// developer setups without a configured gateway token.
func WriteShimScripts(shimDir, apiAddr string) error {
	return WriteShimScriptsWithToken(shimDir, apiAddr, "")
}

// WriteShimScriptsWithToken generates the PATH shim scripts AND
// persists a .token sidecar so each shim can authenticate inspection
// calls. See F-2029 / F-3397 for the security rationale.
func WriteShimScriptsWithToken(shimDir, apiAddr, token string) error {
	return writeShimScriptsWithMode(shimDir, apiAddr, token, defaultHookFailMode, "openclaw")
}

// writeShimScriptsWithMode records the installed outage choice in the shim.
// A reachable gateway's block or malformed answer is handled by the shim
// itself and is never opened by this mode. connectorName is the connector
// that installs the shims: at call time a shim asks the outage mode the
// config gives that connector (its per-connector choice, else the global
// one), never a connector named "subprocess" (GAP-1989).
func writeShimScriptsWithMode(shimDir, apiAddr, token, failMode, connectorName string) error {
	connectorName = normalizeConnectorName(connectorName)
	if !shimConnectorNameRE.MatchString(connectorName) {
		return fmt.Errorf("shim scripts: connector name %q is not a plain connector name", connectorName)
	}
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}

	// F-2029 / F-3397: write the bearer token next to the shim
	// scripts. The .token file is 0o600 so other workspace tooling
	// can't slurp it; the shim sources the file at runtime via
	// `. "${SHIM_DIR}/.token"`. An empty token still produces a
	// well-formed file so the shim's source-or-fallback logic
	// behaves deterministically across loopback-allow and
	// authenticated deployments.
	tokenPath := filepath.Join(shimDir, ".token")
	tokenContent := fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", token)
	if err := atomicWriteFile(tokenPath, []byte(tokenContent), 0o600); err != nil {
		return fmt.Errorf("write shim token file: %w", err)
	}

	data := templateData{APIAddr: apiAddr, FailMode: normalizeHookFailMode(failMode), TokenFile: ".token", ConnectorName: connectorName}
	peerHelper, err := shimFS.ReadFile("shims/peer.inc")
	if err != nil {
		return fmt.Errorf("read shim peer helper: %w", err)
	}

	for _, name := range shimBinaries {
		content, err := shimFS.ReadFile("shims/" + name + ".sh")
		if err != nil {
			return fmt.Errorf("read shim template %s: %w", name, err)
		}

		// Embed the transport in each shim so runtime lookup cannot be
		// redirected to a file writable by a different account.
		withHelper := strings.Replace(string(content), "#!/bin/bash\n", "#!/bin/bash\n"+string(peerHelper)+"\n", 1)
		rendered, err := renderTemplate(withHelper, data)
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

func subprocessGeneratedFiles(opts SetupOpts) []string {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	return []string{
		filepath.Join(opts.DataDir, "shims", ".token"),
		filepath.Join(opts.DataDir, "policies", "defenseclaw-policy.yaml"),
	}
}

func subprocessGeneratedExecutables(opts SetupOpts) []string {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	out := make([]string, 0, len(shimBinaries))
	for _, name := range shimBinaries {
		out = append(out, filepath.Join(opts.DataDir, "shims", name))
	}
	return out
}

func subprocessCreatedDirs(opts SetupOpts) []string {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	return []string{
		filepath.Join(opts.DataDir, "shims"),
		filepath.Join(opts.DataDir, "policies"),
	}
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
	"antigravity": {"antigravity-hook.sh"},
	"claudecode":  {"claude-code-hook.sh"},
	"codex":       {"codex-hook.sh"},
	"copilot":     {"copilot-hook.sh"},
	"cursor":      {"cursor-hook.sh"},
	"devin":       {"devin-hook.sh"},
	"hermes":      {"hermes-hook.sh"},
	"kiro":        {"kiro-hook.sh"},
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

// hookHelperScripts lists support files that hooks `source` at runtime.
// They are written into the hook dir alongside the executable hooks but
// NEVER appear in HookScripts() / connector enumerations — agents do
// not invoke them directly. Plan B4: _hardening.sh centralizes the
// shell-side rlimit + env sanitization helpers.
var hookHelperScripts = []string{
	"_hardening.sh",
}

// hookSchemaVersionMarker is the line-2 prefix every generated hook
// (and the hooks/_hardening.sh helper) carries. The version digit
// after the prefix is parsed by parseHookSchemaVersion to drive the
// downgrade-safety check in writeHookHelpers. Kept as its own const
// (rather than reused from claudecode.go's hookMarker) so the
// subprocess writer doesn't pull a dependency on connector-specific
// teardown internals.
const hookSchemaVersionMarker = "# defenseclaw-managed-hook v"

// parseHookSchemaVersion returns the schema version digit that
// follows hookSchemaVersionMarker on line 2 of a defenseclaw-managed
// hook script. Returns 0 when the marker is absent, the digit is
// missing, or the file is too short to contain it — the zero is the
// "older than any tagged version" sentinel so writeHookHelpers will
// always overwrite a malformed helper on disk.
//
// Only the first 512 bytes are scanned; the marker MUST appear
// near the top of the file (line 2 by contract). Refusing to scan
// the whole file caps the cost of inspecting an attacker-supplied
// path and matches the bound used by claudecode.go::scriptHasMarker.
func parseHookSchemaVersion(content []byte) int {
	if len(content) > 512 {
		content = content[:512]
	}
	idx := bytesIndex(content, hookSchemaVersionMarker)
	if idx < 0 {
		return 0
	}
	rest := content[idx+len(hookSchemaVersionMarker):]
	v := 0
	consumed := 0
	for consumed < len(rest) {
		c := rest[consumed]
		if c < '0' || c > '9' {
			break
		}
		// Cap the version width so a hostile file with a long
		// digit run can't pin the helper at int-overflow.
		if consumed >= 6 {
			return 0
		}
		v = v*10 + int(c-'0')
		consumed++
	}
	if consumed == 0 {
		return 0
	}
	return v
}

// bytesIndex is a stdlib-light alternative to bytes.Index — kept
// inline so subprocess.go doesn't grow another import for one
// call site. Returns the first index where needle appears in hay,
// or -1 when absent.
func bytesIndex(hay []byte, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(hay) {
		return -1
	}
	limit := len(hay) - len(needle)
	for i := 0; i <= limit; i++ {
		if string(hay[i:i+len(needle)]) == needle {
			return i
		}
	}
	return -1
}

// writeHookHelpers writes the helper scripts (_hardening.sh, etc.) into
// hookDir at mode 0o600. Helpers are sourced — never executed
// directly — so they don't need the executable bit.
//
// Downgrade safety: if a helper is already on disk and carries a
// schema version GREATER than the one embedded in this binary, the
// existing file is left in place. This closes the "hook artifact
// drift on re-setup" bug: when `defenseclaw setup guardrail` ends
// with `defenseclaw-gateway restart`, the binary that boots and
// runs Connector.Setup may be older than the templates the operator
// has freshly installed (typical when an older `defenseclaw-gateway`
// shadows a newer one on $PATH). Without this check the older
// binary unconditionally clobbers the helper with its v2 embed,
// dropping the new `category` arg from `defenseclaw_log_hook_failure`
// and leaving hook-failures.jsonl entries without the field —
// even though the just-rendered hook scripts pass it.
//
// Equal versions replace only changed bytes, so same-version bug-fix patches
// still land without causing no-op guardian reconciles to retrigger fsnotify.
// Strictly-newer disk content is preserved. Bumping the embedded
// `# defenseclaw-managed-hook vN` marker is the explicit signal to roll
// forward.
func writeHookHelpers(hookDir string) error {
	return writeHookHelpersForMode(hookDir, false)
}

func writeHookHelpersForMode(hookDir string, managedEnterprise bool) error {
	writeFile := hookRuntimeFileWriter(managedEnterprise)
	if !managedEnterprise {
		if err := writePerUserGatewayHelperRecord(hookDir); err != nil {
			return err
		}
	}
	for _, name := range hookHelperScripts {
		content, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			return fmt.Errorf("read hook helper %s: %w", name, err)
		}
		helperPath := filepath.Join(hookDir, name)
		if !managedEnterprise {
			existing, err := readConnectorStateFile(helperPath)
			if err == nil {
				diskV := parseHookSchemaVersion(existing)
				embedV := parseHookSchemaVersion(content)
				if diskV > 0 && embedV > 0 && diskV > embedV {
					// Newer-on-disk wins. Skip silently so a
					// repeat-setup with an older binary doesn't
					// noisily report "downgraded" when the
					// operator's intent was to keep the newer
					// helper installed by a more recent build.
					continue
				}
			}
		}
		if err := writeFile(helperPath, content, 0o600); err != nil {
			return fmt.Errorf("write hook helper %s: %w", name, err)
		}
	}
	return nil
}

// The record is written at setup beside the installed hook files. Agent
// environment never selects the executable that receives a bearer or reads
// a call-time outage decision. Plugins use the same record as shell hooks.
func writePerUserGatewayHelperRecord(hookDir string) error {
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return err
	}
	home := userHomeDir()
	dataDir := filepath.Dir(filepath.Clean(hookDir))
	if filepath.Base(dataDir) == ".defenseclaw" {
		home = filepath.Dir(dataDir)
	}
	if !filepath.IsAbs(home) {
		return fmt.Errorf("hook helper account home is not absolute")
	}
	name := "defenseclaw-gateway"
	if runtime.GOOS == "windows" {
		name = windowsGatewayBinaryName
	}
	// A custom per-user data root can carry the gateway installation itself.
	// Resolve that path once during setup, from the installed hook location;
	// the hook never derives an executable from its caller's environment.
	if dataDir != home && filepath.Base(dataDir) != ".defenseclaw" {
		// The gateway or the hook-post helper the shell hooks run beside it
		// (GAP-1755) marks the data root that carries the installation.
		for _, installed := range []string{name, "defenseclaw-hook-post"} {
			if info, err := os.Lstat(filepath.Join(dataDir, ".local", "bin", installed)); err == nil && info.Mode().IsRegular() {
				home = dataDir
				break
			}
		}
	}
	binary := filepath.Join(home, ".local", "bin", name)
	if err := hookRuntimeFileWriter(false)(filepath.Join(hookDir, ".gateway-helper"), []byte(binary+"\n"), 0o600); err != nil {
		return fmt.Errorf("write hook helper record: %w", err)
	}
	return nil
}

// WriteHookScriptsWithToken generates every hook script into hookDir and
// writes the gateway bearer token to the .token file the scripts read at run
// time, so the API server's auth middleware accepts the hook's POST. The
// scripts hand the token to curl on a descriptor (defenseclaw_gateway_post in
// _hardening.sh), never on its command line. When token is empty the scripts
// omit the header entirely so the middleware's loopback-allow branch still
// applies.
//
// Hook scripts generated:
//   - inspect-tool.sh          (pre-tool)
//   - inspect-request.sh       (pre-request)
//   - inspect-response.sh      (post-response)
//   - inspect-tool-response.sh (post-tool)
//   - connector-specific lifecycle hooks listed in connectorHookScripts
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
	if err := atomicWriteFile(tokenPath, []byte(tokenContent), 0o600); err != nil {
		return fmt.Errorf("write hook token file: %w", err)
	}

	if err := writeHookHelpers(hookDir); err != nil {
		return err
	}

	// Never bake the real token into template output — scripts read
	// the .token file or the env var at runtime. This legacy all-script
	// writer uses the product-wide default; connector-aware setup uses
	// resolveHookFailMode so Cursor can apply its action/observe boundary.
	data := templateData{APIAddr: apiAddr, APIToken: "", FailMode: defaultHookFailMode, TokenFile: ".token"}

	for _, name := range hookScripts {
		rendered, err := renderHookTemplate(name, data)
		if err != nil {
			return err
		}

		hookPath := filepath.Join(hookDir, name)
		if err := removeHookScriptLink(hookPath); err != nil {
			return err
		}
		if err := atomicWriteFile(hookPath, rendered, 0o700); err != nil {
			return fmt.Errorf("write hook %s: %w", name, err)
		}
	}

	if err := writeHookConfigSidecar(hookDir, apiAddr, "", defaultHookFailMode, false); err != nil {
		return err
	}

	return nil
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
	return writeHookScriptsCommonWithOptions(hookDir, apiAddr, token, failMode, extras, false, "", false)
}

func writeHookScriptsCommonWithOptions(hookDir, apiAddr, token, failMode string, extras []string, managed bool, connectorName string, scopedToken bool) error {
	return writeHookScriptsCommonWithTransport(hookDir, apiAddr, token, failMode, HookFailModeSourceConfig, extras, managed, connectorName, scopedToken, "", "", false, false)
}

// writeHookScriptsCommonWithTransport is writeHookScriptsCommonWithOptions
// plus the connector scripts' standalone socket transport block (empty for
// TCP) and foreign-hook guard block (empty unless the connector's standalone
// shell hook runs the guard). The shared inspect-* scripts keep TCP: no
// per-user enterprise hook registration invokes them. failModeSource is the
// sidecar source of failMode (HookFailModeSourceConfig for resolved modes).
func writeHookScriptsCommonWithTransport(hookDir, apiAddr, token, failMode, failModeSource string, extras []string, managed bool, connectorName string, scopedToken bool, socketTransport, foreignGuard string, secureClient, secureClientDelivery bool, hermesNativeHook ...string) error {
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("create hook dir: %w", err)
	}

	tokenScope := ""
	if scopedToken {
		tokenScope = connectorName
	}
	writeFile := hookRuntimeFileWriter(managed)
	tokenFile, err := writeHookTokenFilesUsing(hookDir, tokenScope, token, writeFile)
	if err != nil {
		return err
	}

	if err := writeHookHelpersForMode(hookDir, managed); err != nil {
		return err
	}

	scripts, err := renderHookScripts(apiAddr, failMode, tokenFile, extras, managed, connectorName, scopedToken, socketTransport, foreignGuard, secureClient, secureClientDelivery, filepath.Dir(filepath.Clean(hookDir)), hermesNativeHook...)
	if err != nil {
		return err
	}
	for _, script := range scripts {
		if !managed {
			if err := removeHookScriptLink(filepath.Join(hookDir, script.name)); err != nil {
				return err
			}
		}
		if err := writeFile(filepath.Join(hookDir, script.name), script.body, 0o700); err != nil {
			return fmt.Errorf("write hook %s: %w", script.name, err)
		}
	}
	if err := writeHookConfigSidecarUsing(
		hookDir,
		apiAddr,
		connectorName,
		normalizeHookFailMode(failMode),
		failModeSource,
		managed,
		writeFile,
	); err != nil {
		return err
	}
	return nil
}

// removeHookScriptLink removes a link put in place of a generated hook script,
// so the render writes a regular file in the hook folder again instead of
// writing through the link, and doctor --fix converges (GAP-2022). The link's
// target is left as it is. An entry this account cannot even look at is
// removed too: on Windows a link another account (SYSTEM) made in the
// account's hook folder carries no entry for the account, so Lstat is
// refused, but the account's full control of the folder lets it delete the
// entry, and the render then writes its own file. Left there, every render
// failed and the gateway did not start.
func removeHookScriptLink(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink == 0:
		return nil
	case err != nil && !errors.Is(err, os.ErrPermission):
		return nil
	}
	if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		what := "is a link"
		if err != nil {
			what = "cannot be read by this account"
		}
		return fmt.Errorf("hook script %s %s and could not be removed so DefenseClaw can write its own copy (%v); "+
			"remove it (as an administrator if this account cannot), then run the setup again", path, what, rmErr)
	}
	return nil
}

// renderedHookScript is one generated hook script: its basename in the hook
// directory and its rendered bytes.
type renderedHookScript struct {
	name string
	body []byte
}

// renderHookScripts renders, without writing anything, the shared inspect-*
// scripts and the connector-owned lifecycle scripts named in extras, in the
// order writeHookScriptsCommonWithTransport writes them. tokenFile is the
// basename of the token file the connector scripts read; hookHome is the
// data directory the hooks are written into (HookHomeSH).
func renderHookScripts(apiAddr, failMode, tokenFile string, extras []string, managed bool, connectorName string, scopedToken bool, socketTransport, foreignGuard string, secureClient, secureClientDelivery bool, hookHome string, hermesNativeHook ...string) ([]renderedHookScript, error) {
	// A per-user script bakes closed for non-outage failures. Its current
	// config decides a classified outage at call time.
	homeSH := ""
	if !managed {
		failMode = "closed"
		if filepath.IsAbs(hookHome) {
			homeSH = shellSingleQuote(filepath.Clean(hookHome))
		}
	}
	connectorData := templateData{
		APIAddr:              apiAddr,
		APIToken:             "",
		FailMode:             normalizeHookFailMode(failMode),
		Managed:              managed,
		SecureClient:         secureClient,
		SecureClientDelivery: secureClient && secureClientDelivery,
		TokenFile:            tokenFile,
		HookHomeSH:           homeSH,
		ScopedToken:          scopedToken,
		ConnectorName:        strings.ToLower(strings.TrimSpace(connectorName)),
		HookBinaryPS:         strings.ReplaceAll(defenseclawHookBinary(), "'", "''"),
		HookTimeoutMS:        windowsHookAdapterTimeoutMS,
		CursorHookTimeoutMS:  cursorWindowsHookAdapterTimeoutMS,
		CopilotHookTimeoutMS: copilotWindowsHookAdapterTimeoutMS,
		// Rendered only when a managed standalone install names a hook
		// socket; see WriteHookScriptsForConnectorObjectWithOpts.
		HookSocketTransportSH: socketTransport,
		ForeignHookGuardSH:    foreignGuard,
	}
	if managed && !secureClient && socketTransport != "" && connectorData.ConnectorName == "hermes" &&
		len(hermesNativeHook) == 1 && filepath.IsAbs(hermesNativeHook[0]) && !strings.ContainsAny(hermesNativeHook[0], "\x00\r\n") {
		connectorData.HermesNativeHookSH = shellSingleQuote(hermesNativeHook[0])
	}
	// The inspect-* family has one physical copy per data directory.  Its
	// bytes must therefore depend only on install-wide inputs; connector mode,
	// identity and scoped credential selection happen at invocation time.  The
	// connector-owned lifecycle scripts retain the selected connector data.
	sharedData := templateData{APIAddr: apiAddr, Managed: managed, SecureClient: connectorData.SecureClient,
		SecureClientDelivery: connectorData.SecureClientDelivery, HookHomeSH: homeSH}
	// renderHookScriptSet is the one renderer the host and sandbox hook
	// files share (hook_render.go).
	set, err := renderHookScriptSet(connectorData, sharedData, extras)
	if err != nil {
		return nil, err
	}
	scripts := make([]renderedHookScript, 0, len(set))
	for _, file := range set {
		scripts = append(scripts, renderedHookScript{name: file.Name, body: file.Data})
	}
	return scripts, nil
}

// hookRuntimeRenderMaxBytes bounds each installed hook runtime file
// HookScriptRenderDrift reads.
const hookRuntimeRenderMaxBytes = 4 << 20

// renderedHookRuntimeFile is a per-user hook runtime file Setup writes: its
// path and the bytes this release renders for it.
type renderedHookRuntimeFile struct {
	path string
	body []byte
}

// HookScriptRenderDrift compares the hook runtime files conn's managed Setup
// writes into opts.DataDir/hooks with the bytes this release renders for
// opts, and returns the first file that is missing or differs, or "" when
// every file matches. For a shell hook connector these are its own hook
// scripts, the shared inspect-* scripts and the _hardening.sh helper they
// source. A connector whose Setup publishes
// a managed in-agent plugin (Amp, OpenCode) writes none of them:
// ManagedPluginArtifactDrift covers the plugin. The standalone Unix guardian
// relies on this rather than on the digests recorded at the last write: after
// a package upgrade the files still match those digests but carry the
// previous release's render, and the user can edit a file together with its
// recorded digest. Files are read with the caller's credentials, bounded and
// without following a link.
func HookScriptRenderDrift(conn Connector, opts SetupOpts) (string, error) {
	files, err := renderedHookRuntimeFiles(conn, opts)
	if err != nil {
		return filepath.Join(opts.DataDir, "hooks"), err
	}
	for _, file := range files {
		installed, err := safefile.ReadRegularFileBounded(file.path, hookRuntimeRenderMaxBytes)
		if errors.Is(err, os.ErrNotExist) {
			return file.path, nil
		}
		if err != nil {
			return file.path, err
		}
		if !bytes.Equal(installed, file.body) {
			return file.path, nil
		}
	}
	return "", nil
}

// HookRuntimeTokenFile returns the connector-scoped token file the hook
// scripts of conn read after a managed setup with opts, and the credential
// that setup writes in it; "" when the render keeps no scoped token file (a
// plugin-only connector, a proxy connector or no data directory). The
// standalone guardian verifies it (GAP-0424).
func HookRuntimeTokenFile(opts SetupOpts, conn Connector) (path, token string, err error) {
	if conn == nil || strings.TrimSpace(opts.DataDir) == "" {
		return "", "", nil
	}
	if _, ok := conn.(HookScriptOwner); !ok || len(ManagedPluginArtifacts(conn, opts)) > 0 {
		return "", "", nil
	}
	render := resolveConnectorHookRender(opts, conn)
	if !render.scopedToken || strings.TrimSpace(render.token) == "" {
		return "", "", nil
	}
	path, err = HookTokenFilePath(filepath.Join(opts.DataDir, "hooks"), conn.Name())
	if err != nil {
		return "", "", err
	}
	return path, render.token, nil
}

// renderedHookRuntimeFiles renders the files HookScriptRenderDrift compares,
// as a managed install writes them.
func renderedHookRuntimeFiles(conn Connector, opts SetupOpts) ([]renderedHookRuntimeFile, error) {
	if conn == nil || strings.TrimSpace(opts.DataDir) == "" {
		return nil, nil
	}
	if _, ok := conn.(HookScriptOwner); !ok || len(ManagedPluginArtifacts(conn, opts)) > 0 {
		return nil, nil
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	render := resolveConnectorHookRender(opts, conn)
	tokenFile := ".token"
	if render.scopedToken {
		path, err := HookTokenFilePath(hookDir, conn.Name())
		if err != nil {
			return nil, err
		}
		tokenFile = filepath.Base(path)
	}
	scripts, err := renderHookScripts(opts.APIAddr, render.failMode, tokenFile, render.extras, opts.ManagedEnterprise,
		conn.Name(), render.scopedToken, render.socketTransport, render.foreignGuard, shellHookSecureClientProfile(opts),
		shellHookSecureClientDelivery(opts), opts.DataDir, render.hermesNativeHook)
	if err != nil {
		return nil, err
	}
	files := make([]renderedHookRuntimeFile, 0, len(hookHelperScripts)+len(scripts))
	// A managed install writes the embedded helpers as they are.
	for _, name := range hookHelperScripts {
		content, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			return nil, fmt.Errorf("read hook helper %s: %w", name, err)
		}
		files = append(files, renderedHookRuntimeFile{path: filepath.Join(hookDir, name), body: content})
	}
	for _, script := range scripts {
		files = append(files, renderedHookRuntimeFile{path: filepath.Join(hookDir, script.name), body: script.body})
	}
	return files, nil
}

// hookRuntimeFileWriter selects the final-descriptor publication primitive for
// managed Windows runtime files. Generic atomicWriteFile intentionally uses an
// owner-only two-ACE private descriptor; the managed runtime contract instead
// requires the target, SYSTEM, Administrators, and OWNER RIGHTS four-ACE DACL.
// Publishing through WriteManagedTargetRuntimeFile also makes an identical
// canonical write a true no-op, avoiding an observable ACL/identity transition
// during normal Guardian reconciliation.
func hookRuntimeFileWriter(managedEnterprise bool) func(string, []byte, os.FileMode) error {
	if managedEnterprise && runtime.GOOS == "windows" {
		return func(path string, data []byte, _ os.FileMode) error {
			return WriteManagedTargetRuntimeFile(path, data)
		}
	}
	return atomicWriteFile
}

// writeHookTokenFilesUsing is the writer-injectable form used by managed-mode
// callers so token files can be published with the platform's exact managed
// runtime descriptor rather than atomicWriteFile's generic private contract.
func writeHookTokenFilesUsing(
	hookDir, connectorName, token string,
	writeFile func(string, []byte, os.FileMode) error,
) (string, error) {
	legacyPath := filepath.Join(hookDir, ".token")
	if strings.TrimSpace(connectorName) == "" {
		tokenContent := fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", token)
		if err := writeFile(legacyPath, []byte(tokenContent), 0o600); err != nil {
			return "", fmt.Errorf("write hook token file: %w", err)
		}
		return filepath.Base(legacyPath), nil
	}
	// Connector-scoped installs must not leave a legacy .token behind. Older
	// releases put the master gateway bearer there, so retaining it on upgrade
	// would preserve the exact cross-connector authority this migration removes.
	// Setup rewrites every generated hook to the scoped basename before it
	// returns, making removal safe for the managed artifacts in this directory.
	if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove legacy hook token file: %w", err)
	}
	scopedPath, err := HookTokenFilePath(hookDir, connectorName)
	if err != nil {
		return "", fmt.Errorf("resolve connector-scoped hook token file: %w", err)
	}
	if strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("write connector-scoped hook token file: token contains a line break")
	}
	if err := writeFile(scopedPath, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write connector-scoped hook token file: %w", err)
	}
	return filepath.Base(scopedPath), nil
}

// hookConfigSidecarName is the shared connector-aware runtime state read by
// the native Windows hook and the generic Unix inspect scripts. It lets hook
// commands stay free of per-install flags while preserving mixed fail modes.
const hookConfigSidecarName = ".hookcfg"

// Hook runtime records are generated from a handful of scalar fields. A
// generous 64-KiB ceiling avoids changing legitimate unmanaged installations
// while ensuring a target-owned sparse/huge sidecar is rejected from metadata
// before the guardian allocates for it.
const hookRuntimeSidecarMaxBytes int64 = 64 << 10

type hookConfigSidecar struct {
	Version     int               `json:"version"`
	GatewayAddr string            `json:"gateway_addr"`
	FailModes   map[string]string `json:"fail_modes,omitempty"`
	// FailModeSources says, per connector entry, where its mode came from:
	// HookFailModeSourceConfig for a mode this release resolved from the
	// config. Earlier releases wrote no such field; the native hook does not
	// trust their open (it may be an unset mode resolved from the guardrail
	// mode) unless the config sets open. Unmanaged sidecars only: a managed
	// hook takes its mode from protected runtime state.
	FailModeSources map[string]string `json:"fail_mode_sources,omitempty"`
	Managed         bool              `json:"managed_enterprise,omitempty"`
	// LegacyMode is migration-only fallback for connectors that do not yet
	// have a map entry. Connector entries always win, so it cannot collapse a
	// mixed-mode runtime and becomes inert after every peer is refreshed.
	LegacyMode string `json:"legacy_fail_mode,omitempty"`
	// LegacySource is FailModeSources for LegacyMode.
	LegacySource string `json:"legacy_fail_mode_source,omitempty"`
}

// HookFailModeSourceConfig marks a sidecar fail mode that the resolver chose.
// Per-user modes stay closed even when an older config saved open.
const HookFailModeSourceConfig = "config"

// writeHookConfigSidecar persists the gateway address and connector fail mode
// resolved at runtime. Connector entries always win; the legacy fallback is
// written only for unscoped callers and cannot collapse mixed connector state.
func writeHookConfigSidecar(hookDir, apiAddr, connectorName, failMode string, managed bool) error {
	return writeHookConfigSidecarUsing(
		hookDir,
		apiAddr,
		connectorName,
		failMode,
		HookFailModeSourceConfig,
		managed,
		hookRuntimeFileWriter(managed),
	)
}

// managedNativeHookRuntimeConnector reports whether a connector's hook is
// administrator machine policy that runs the hook binary with a
// runtime-only per-user footprint: Codex, Claude Code, Cursor, Copilot, and
// OpenCode through its managed plugin on the standalone profile.
func managedNativeHookRuntimeConnector(name string) bool {
	switch name {
	case "codex", "claudecode", "cursor", "copilot", "opencode":
		return true
	default:
		return false
	}
}

// ReconcileManagedNativeHookRuntime writes only DefenseClaw's connector-scoped
// native runtime. It deliberately does not invoke the connector Setup method,
// so Windows machine-policy connectors never read or modify the agent's
// user-level configuration file.
//
// On Windows these writes use the target-aware managed-runtime publisher, so
// both the staging inode and the published name have the exact final DACL.
// Other platforms retain the existing private atomic writer.
func ReconcileManagedNativeHookRuntime(
	dataDir, apiAddr, connectorName, token string,
	failMode ...string,
) error {
	mode := defaultHookFailMode
	if len(failMode) > 0 {
		mode = normalizeHookFailMode(failMode[0])
	}
	name := normalizeConnectorName(connectorName)
	if !managedNativeHookRuntimeConnector(name) {
		return fmt.Errorf("unsupported managed native hook connector %q", connectorName)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("create managed native hook directory: %w", err)
	}
	writeFile := hookRuntimeFileWriter(true)
	if _, err := writeHookTokenFilesUsing(hookDir, name, token, writeFile); err != nil {
		return err
	}
	return writeHookConfigSidecarUsing(
		hookDir,
		apiAddr,
		name,
		mode,
		"",
		true,
		writeFile,
	)
}

// ValidateManagedNativeHookRuntime requires the v2 managed marker, protected
// endpoint agreement, canonical delivery mode, flat record, and scoped token.
func ValidateManagedNativeHookRuntime(
	dataDir, apiAddr, connectorName string,
	expectedFailMode ...string,
) error {
	name := normalizeConnectorName(connectorName)
	if !managedNativeHookRuntimeConnector(name) {
		return fmt.Errorf("unsupported managed native hook connector %q", connectorName)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	body, _, err := readStableHookRuntimeSidecar(
		filepath.Join(hookDir, hookConfigSidecarName),
		"managed hook config sidecar",
		false,
	)
	if err != nil {
		return fmt.Errorf("read managed hook config sidecar: %w", err)
	}
	var state hookConfigSidecar
	if err := decodeManagedHookConfigSidecar(body, &state); err != nil {
		return fmt.Errorf("parse managed hook config sidecar: %w", err)
	}
	if state.Version != 2 || !state.Managed {
		return fmt.Errorf(
			"managed hook config has version=%d managed_enterprise=%t, want version=2 managed_enterprise=true",
			state.Version,
			state.Managed,
		)
	}
	if strings.TrimSpace(state.GatewayAddr) != strings.TrimSpace(apiAddr) {
		return fmt.Errorf(
			"managed hook gateway address %q does not match protected address %q",
			state.GatewayAddr,
			apiAddr,
		)
	}
	mode := state.FailModes[name]
	if (mode != "closed" && mode != "open") ||
		(len(expectedFailMode) > 0 && mode != normalizeHookFailMode(expectedFailMode[0])) {
		return fmt.Errorf(
			"managed hook connector %s fail mode %q, want %q",
			name,
			state.FailModes[name],
			strings.Join(expectedFailMode, ","),
		)
	}
	flat, _, err := readStableHookRuntimeSidecar(
		filepath.Join(hookDir, hookConfigSidecarName+"."+name),
		"managed connector runtime sidecar",
		false,
	)
	if err != nil {
		return fmt.Errorf("read managed connector runtime sidecar: %w", err)
	}
	if got, ok := flatHookRecordValue(flat, "DEFENSECLAW_CONNECTOR"); !ok || got != name {
		return fmt.Errorf("managed shell runtime connector %q, want %q", got, name)
	}
	if got, ok := flatHookRecordValue(flat, "DEFENSECLAW_FAIL_MODE"); !ok || got != mode {
		return fmt.Errorf("managed shell runtime fail mode %q, want %q", got, mode)
	}
	tokenPath, err := HookTokenFilePath(hookDir, name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(tokenPath); err != nil {
		return fmt.Errorf("inspect managed connector token: %w", err)
	}
	return nil
}

type hookRuntimeFileSnapshot struct {
	path    string
	existed bool
	// regular is false for a link or another file that is not regular (the
	// unmanaged snapshot follows it; a managed one refuses it).
	regular bool
	data    []byte
}

func snapshotHookRuntimeFile(path string) (hookRuntimeFileSnapshot, error) {
	snapshot := hookRuntimeFileSnapshot{path: path}
	data, err := readConnectorStateFile(path)
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	snapshot.existed = true
	snapshot.data = data
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		snapshot.regular = true
	}
	return snapshot, nil
}

func snapshotHookRuntimeFileForMode(
	path string,
	managedEnterprise bool,
) (hookRuntimeFileSnapshot, error) {
	if !managedEnterprise {
		return snapshotHookRuntimeFile(path)
	}
	snapshot := hookRuntimeFileSnapshot{path: path}
	data, exists, err := readStableManagedRuntimeFile(
		path,
		"managed hook runtime snapshot",
		true,
		hookRuntimeSidecarMaxBytes,
	)
	if err != nil {
		return snapshot, err
	}
	if !exists {
		return snapshot, nil
	}
	snapshot.existed = true
	snapshot.regular = true
	snapshot.data = data
	return snapshot, nil
}

func restoreHookRuntimeFilesUsing(
	snapshots []hookRuntimeFileSnapshot,
	writeFile func(string, []byte, os.FileMode) error,
) error {
	var failures []string
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if snapshot.existed {
			if err := writeFile(snapshot.path, snapshot.data, 0o600); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
			}
			continue
		}
		if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
			failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("restore hook runtime files: %s", strings.Join(failures, "; "))
	}
	return nil
}

// carryableHookConfigSidecar returns the peer state a rewrite should preserve,
// accepting the v2 map form and the legacy scalar form. State a reader closes
// on (a malformed legacy file, or JSON outside the readers' contract:
// hookSidecarRewriteRefused, a fail_modes of null included) is refused, never
// settled into a mode a reader would open on.
func carryableHookConfigSidecar(data []byte) (hookConfigSidecar, error) {
	var prior hookConfigSidecar
	if err := json.Unmarshal(data, &prior); err != nil {
		values, ok := ParseLegacyHookSidecar(data)
		legacyMode := values["DEFENSECLAW_FAIL_MODE"]
		if !ok || (legacyMode != "open" && legacyMode != "closed") {
			return hookConfigSidecar{}, fmt.Errorf("parse hook config sidecar: %w", err)
		}
		return hookConfigSidecar{LegacyMode: legacyMode}, nil
	}
	if err := hookSidecarRewriteRefused(data); err != nil {
		if errors.Is(err, errHookSidecarNullFailModes) && prior.Version == 2 {
			// The rest of the document meets the contract: the caller may
			// repair the map (writeHookConfigSidecarLocked) or refuse.
			return prior, err
		}
		return hookConfigSidecar{}, err
	}
	if prior.Version != 2 {
		return hookConfigSidecar{}, fmt.Errorf("unsupported hook config sidecar version %d", prior.Version)
	}
	return prior, nil
}

// writeHookConfigSidecarUsing records source (HookFailModeSourceConfig, or ""
// for a mode the config did not choose) with an unmanaged entry. A managed
// hook takes its mode from protected state, and the managed readers decode
// the sidecar strictly, so a managed sidecar records no source.
func writeHookConfigSidecarUsing(
	hookDir, apiAddr, connectorName, failMode, source string,
	managed bool,
	writeFile func(string, []byte, os.FileMode) error,
) error {
	path := filepath.Join(hookDir, hookConfigSidecarName)
	return withFileLockMode(path, managed, func() error {
		return writeHookConfigSidecarLocked(hookDir, apiAddr, connectorName, failMode, source, managed, writeFile)
	})
}

// writeHookConfigSidecarLocked is writeHookConfigSidecarUsing for a caller
// that holds the sidecar lock (refreshHookFailModesLocked).
func writeHookConfigSidecarLocked(
	hookDir, apiAddr, connectorName, failMode, source string,
	managed bool,
	writeFile func(string, []byte, os.FileMode) error,
) error {
	if managed {
		source = ""
	}
	path := filepath.Join(hookDir, hookConfigSidecarName)
	name := normalizeConnectorName(connectorName)
	runtimeName := name
	if runtimeName == "" {
		runtimeName = "legacy"
	}
	flatPath := filepath.Join(hookDir, hookConfigSidecarName+"."+runtimeName)
	jsonSnapshot, err := snapshotHookRuntimeFileForMode(path, managed)
	if err != nil {
		return fmt.Errorf("read hook config sidecar: %w", err)
	}
	flatSnapshot, err := snapshotHookRuntimeFileForMode(flatPath, managed)
	if err != nil {
		return fmt.Errorf("read shell hook runtime sidecar: %w", err)
	}
	snapshots := []hookRuntimeFileSnapshot{jsonSnapshot, flatSnapshot}

	state := hookConfigSidecar{Version: 2, GatewayAddr: apiAddr, FailModes: map[string]string{}, Managed: managed}
	if jsonSnapshot.existed {
		prior, err := carryableHookConfigSidecar(jsonSnapshot.data)
		if errors.Is(err, errHookSidecarNullFailModes) && !managed {
			// GAP-0512: repaired below from the corroborating flat records.
			err = nil
		}
		if err == nil && !jsonSnapshot.regular {
			// The shared hooks close on a link (or any file that is not
			// regular); the rewrite would put a regular file there.
			err = errHookConfigSidecarNotRegular
		}
		// A managed sidecar is guardian-owned and every connector reconciles
		// on its own schedule, so unreadable content is replaced outright and
		// at most one peer entry waits for its own pass. An unmanaged sidecar
		// is the operator's only record of peer fail modes, so it is kept and
		// the write refused instead.
		if err != nil && !managed {
			return err
		}
		if err == nil {
			if !managed && nullHookFailModeMap(jsonSnapshot.data) {
				prior.FailModes, err = recoverFlatHookFailModes(hookDir, prior.FailModeSources)
				if err != nil {
					return fmt.Errorf("repair null hook fail-mode map: %w", err)
				}
			}
			if prior.FailModes != nil {
				state.FailModes = prior.FailModes
			}
			state.LegacyMode = prior.LegacyMode
			if !managed {
				state.FailModeSources = prior.FailModeSources
				state.LegacySource = prior.LegacySource
			}
		}
	}
	mode := normalizeHookFailMode(failMode)
	if name != "" {
		state.FailModes[name] = mode
		if source == "" {
			delete(state.FailModeSources, name)
		} else {
			if state.FailModeSources == nil {
				state.FailModeSources = map[string]string{}
			}
			state.FailModeSources[name] = source
		}
	} else {
		state.LegacyMode = mode
		state.LegacySource = source
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal hook config sidecar: %w", err)
	}
	body = append(body, '\n')
	if err := writeFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write hook config sidecar: %w", err)
	}
	// Shell hooks need a parser-independent connector record because jq and
	// python3 are not guaranteed on the hardened macOS/Linux PATH.  One flat
	// file per connector preserves mixed modes; an unscoped legacy record is
	// a fallback only and never overrides a connector file.
	if err := writeFile(flatPath, hookRuntimeFlatRecord(name, mode, source), 0o600); err != nil {
		if restoreErr := restoreHookRuntimeFilesUsing(snapshots, writeFile); restoreErr != nil {
			return fmt.Errorf("write shell hook runtime sidecar: %v (%v)", err, restoreErr)
		}
		return fmt.Errorf("write shell hook runtime sidecar: %w", err)
	}
	return nil
}

// A present null map is malformed, even though encoding/json decodes it as a
// nil map. The connector-scoped flat records are the other persisted copy of
// each mode. Recover only records whose connector, mode and source agree;
// never invent an open peer mode from the legacy fallback.
// flatRecordNames reports a well-formed connector record that names name.
func flatRecordNames(body []byte, name string) bool {
	got, ok := flatHookRecordValue(body, "DEFENSECLAW_CONNECTOR")
	return ok && got == name
}

func nullHookFailModeMap(data []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(fields["fail_modes"]), []byte("null"))
}

func recoverFlatHookFailModes(hookDir string, sources map[string]string) (map[string]string, error) {
	modes := make(map[string]string)
	for _, name := range flatHookRuntimeRecordNames(hookDir) {
		body, _, err := readStableHookRuntimeSidecar(
			filepath.Join(hookDir, hookConfigSidecarName+"."+name), "connector hook runtime record", false,
		)
		if err != nil {
			return nil, err
		}
		mode, _ := flatHookRecordValue(body, "DEFENSECLAW_FAIL_MODE")
		if mode != "open" && mode != "closed" {
			return nil, fmt.Errorf("%s has no valid fail mode", name)
		}
		source, _ := flatHookRecordValue(body, "FAIL_MODE_SOURCE")
		if source != "" && source != HookFailModeSourceConfig {
			return nil, fmt.Errorf("%s has an unrecognized fail-mode source", name)
		}
		if recorded, ok := sources[name]; ok && recorded != source {
			return nil, fmt.Errorf("%s fail-mode source disagrees with its flat record", name)
		}
		if mode == "open" && sources[name] != HookFailModeSourceConfig {
			// A leftover flat file alone cannot authorize an open mode in a
			// shared map that lost its entries. The current connector is set
			// from config after recovery; peers need both persisted proofs.
			continue
		}
		modes[name] = mode
	}
	for name := range sources {
		if _, ok := modes[name]; !ok {
			return nil, fmt.Errorf("%s has no readable flat hook runtime record", name)
		}
	}
	if len(modes) == 0 {
		return nil, fmt.Errorf("no connector-scoped runtime records prove the previous fail modes")
	}
	return modes, nil
}

// hookRuntimeFlatRecord is a connector's flat shell runtime record. Its
// source line says the config chose the mode (HookFailModeSourceConfig); the
// shared shell readers follow an open only with it.
func hookRuntimeFlatRecord(name, mode, source string) []byte {
	body := "DEFENSECLAW_CONNECTOR=" + name + "\nDEFENSECLAW_FAIL_MODE=" + mode + "\n"
	if source != "" {
		body += "FAIL_MODE_SOURCE=" + source + "\n"
	}
	return []byte(body)
}

// HookFailModeRefresh is what RefreshHookFailModes changed.
type HookFailModeRefresh struct {
	// Sidecar names the entries rewritten in hooks/.hookcfg and its flat
	// records ("legacy" for the unscoped entry).
	Sidecar []string
	// Scripts names the connector hook scripts whose baked open was closed.
	Scripts []string
}

// RefreshHookFailModes updates legacy per-user hook records in hookDir to
// mode(connector), the mode the config chooses (OutageHookFailMode). Every
// hooks/.hookcfg entry and flat record gets that mode with its config source,
// and a connector script that bakes an open (or lets the environment open it)
// is closed. Scripts of this release ask their own config at call time;
// older scripts still read the records. Scripts are only tightened: the
// gateway renders them when it starts. Installers run this before the
// running gateway stops and again once it is stopped, before the new hooks go
// in: an earlier release may have recorded or baked open for a mode nobody
// set, which the old hooks would follow while the gateway is down. mode
// returns "" for a connector it cannot resolve, which is left as it is;
// mode("") is the unscoped legacy entry. A managed sidecar is not touched.
func RefreshHookFailModes(hookDir string, mode func(connector string) string) (HookFailModeRefresh, error) {
	var out HookFailModeRefresh
	err := withHookFailModeLock(hookDir, func() error {
		var err error
		out, err = refreshHookFailModesLocked(hookDir, mode)
		return err
	})
	return out, err
}

// withHookFailModeLock runs fn holding the hook sidecar lock
// (hooks/.hookcfg.lock), which every release's sidecar writer takes, 0.8.10
// on, so no gateway records a fail mode between fn's reads and writes. A
// missing hook directory has nothing to refresh, and fn does not run.
func withHookFailModeLock(hookDir string, fn func() error) error {
	info, err := os.Stat(hookDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect hook directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("hook directory %s is not a directory", hookDir)
	}
	return withFileLock(filepath.Join(hookDir, hookConfigSidecarName), fn)
}

// refreshHookFailModesLocked is RefreshHookFailModes for a caller that holds
// the sidecar lock (withHookFailModeLock).
func refreshHookFailModesLocked(hookDir string, mode func(connector string) string) (HookFailModeRefresh, error) {
	var out HookFailModeRefresh
	path := filepath.Join(hookDir, hookConfigSidecarName)
	var state hookConfigSidecar
	data, err := readConnectorStateFile(path)
	switch {
	case err == nil:
		prior, err := carryableHookConfigSidecar(data)
		if err != nil {
			// The writer keeps an unmanaged sidecar it cannot read (it is the
			// only record of peer modes), so its hooks cannot be made safe here.
			return out, fmt.Errorf("%s: %w; remove it and run the upgrade again (the gateway writes it when it starts)", path, err)
		}
		if prior.Managed {
			return out, nil
		}
		state = prior
		if state.GatewayAddr == "" {
			if values, ok := ParseLegacyHookSidecar(data); ok {
				state.GatewayAddr = values["DEFENSECLAW_GATEWAY_ADDR"]
			}
		}
	case !os.IsNotExist(err):
		return out, fmt.Errorf("read hook config sidecar: %w", err)
	}
	names := map[string]bool{}
	for name := range state.FailModes {
		names[name] = true
	}
	for _, name := range flatHookRuntimeRecordNames(hookDir) {
		names[name] = true
	}
	for _, name := range sortedNames(names) {
		if _, retired := RetiredConnector(name); retired {
			// A retired connector's files are removed by its teardown or
			// left as they are, never refreshed: the upgrade rewrote
			// .hookcfg.openhands of the removed OpenHands (GAP-0610).
			continue
		}
		want := mode(name)
		if want == "" {
			continue
		}
		if err := writeHookConfigSidecarLocked(hookDir, state.GatewayAddr, name, want, HookFailModeSourceConfig, false, hookRuntimeFileWriter(false)); err != nil {
			return out, fmt.Errorf("refresh %s hook fail mode: %w", name, err)
		}
		out.Sidecar = append(out.Sidecar, name)
	}
	if state.LegacyMode != "" || hookRuntimeRecordFile(filepath.Join(hookDir, hookConfigSidecarName+".legacy")) {
		if want := mode(""); want != "" {
			if err := writeHookConfigSidecarLocked(hookDir, state.GatewayAddr, "", want, HookFailModeSourceConfig, false, hookRuntimeFileWriter(false)); err != nil {
				return out, fmt.Errorf("refresh the legacy hook fail mode: %w", err)
			}
			out.Sidecar = append(out.Sidecar, "legacy")
		}
	}
	scriptOwners := map[string]bool{}
	for name := range connectorHookScripts {
		scriptOwners[name] = true
	}
	for name := range connectorHookAdapters {
		scriptOwners[name] = true
	}
	for _, name := range sortedNames(scriptOwners) {
		// A per-user script bakes closed for every failure in every tier: its
		// outage mode is the runtime record written above, never the script.
		// An open an earlier release baked is closed whatever the mode.
		if mode(name) == "" {
			continue
		}
		for _, script := range connectorHookScripts[name] {
			closed, err := closeBakedHookFailMode(filepath.Join(hookDir, script), bakedHookFailModeOpens)
			if err != nil {
				return out, err
			}
			if closed {
				out.Scripts = append(out.Scripts, script)
			}
		}
		for _, adapter := range connectorHookAdapters[name] {
			closed, err := closeBakedHookFailMode(filepath.Join(hookDir, adapter), bakedAdapterFailModeOpens)
			if err != nil {
				return out, err
			}
			if closed {
				out.Scripts = append(out.Scripts, adapter)
			}
		}
	}
	named, err := nameInstallInLegacyHardening(hookDir)
	if err != nil {
		return out, err
	}
	if named {
		out.Scripts = append(out.Scripts, legacyHardeningScript)
	}
	return out, nil
}

// legacyHardeningScript is the shared shell helper file every released
// per-user hook sources from its own folder.
const legacyHardeningScript = "_hardening.sh"

// legacyInstallWindowMarker opens the block nameInstallInLegacyHardening
// appends; it makes the append happen once.
const legacyInstallWindowMarker = "# defenseclaw-legacy-install-window-text-v1"

// legacyInstallWindowText is the sentence this release's _hardening.sh
// (defenseclaw_unreachable_next_step) gives while an install holds the lock.
const legacyInstallWindowText = "DefenseClaw is being installed or upgraded for this account and its gateway starts again when that is done; try again in a moment, or run the installer again if it has stopped (`defenseclaw-gateway status` shows its state)"

// nameInstallInLegacyHardening makes a released _hardening.sh that predates
// the install-lock text (1.0.2 and older) name the install while the lock is
// held (GAP-1899). Those hooks say "this account's gateway is not running;
// run `defenseclaw-gateway start`" for every refused connection, also while
// the installer has stopped the gateway on purpose. The appended block wraps
// that release's own defenseclaw_unreachable_next_step: with the lock held
// in the hook's data folder it prints this release's install sentence,
// otherwise it answers as before. Only the text changes: the block, the
// fail modes and the outage table stay the same. The gateway of this release
// writes its own _hardening.sh when it starts, which drops the block. A
// 1.0.3 or later file already names the install and is left as it is.
// Remove with the 1.0.2 upgrade path.
func nameInstallInLegacyHardening(hookDir string) (bool, error) {
	path := filepath.Join(hookDir, legacyHardeningScript)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect hook %s: %w", legacyHardeningScript, err)
	}
	if !info.Mode().IsRegular() || info.Size() > hookScriptMaxBytes {
		return false, nil
	}
	body, err := readConnectorStateFile(path)
	if err != nil {
		return false, fmt.Errorf("read hook %s: %w", legacyHardeningScript, err)
	}
	text := string(body)
	if strings.Contains(text, "being installed or upgraded") ||
		!strings.Contains(text, "defenseclaw_unreachable_next_step()") {
		return false, nil
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += legacyInstallWindowBlock(filepath.Dir(hookDir))
	if err := atomicWriteFile(path, []byte(text), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("update hook %s: %w", legacyHardeningScript, err)
	}
	return true, nil
}

// legacyInstallWindowBlock is the shell appended to a released
// _hardening.sh. dataDir is the hook folder's data directory; the hook's own
// DEFENSECLAW_HOME is read too, as that release reads it.
func legacyInstallWindowBlock(dataDir string) string {
	return legacyInstallWindowMarker + ` (GAP-1899): written by the upgrade's fail-mode refresh;
# the new gateway replaces this file when it starts.
if declare -F defenseclaw_unreachable_next_step >/dev/null 2>&1 && ! declare -F _dc_legacy_unreachable_next_step >/dev/null 2>&1; then
  _dc_legacy_src="$(declare -f defenseclaw_unreachable_next_step)"
  eval "_dc_legacy_unreachable_next_step ${_dc_legacy_src#defenseclaw_unreachable_next_step}"
  unset _dc_legacy_src
  defenseclaw_unreachable_next_step() {
    local _dc_lock_data
    if [ -z "${DEFENSECLAW_HOOK_SOCKET:-}" ]; then
      case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
        1|true|TRUE|yes|YES) ;;
        *)
          for _dc_lock_data in ` + shellSingleQuote(dataDir) + ` "${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"; do
            if [ -e "${_dc_lock_data}/.install.lock" ] || [ -L "${_dc_lock_data}/.install.lock" ]; then
              printf '%s' ` + shellSingleQuote(legacyInstallWindowText) + `
              return 0
            fi
          done
          ;;
      esac
    fi
    _dc_legacy_unreachable_next_step "$@"
  }
fi
`
}

// connectorHookAdapters are the Windows PowerShell adapters a per-user Cursor
// or Copilot registration runs before the native hook (HookScriptNames). An
// adapter answers for itself when the hook launcher is missing or times out
// (the installer swaps it), so its baked open is closed as a script's is.
var connectorHookAdapters = map[string][]string{
	"copilot": {"copilot-hook.ps1"},
	"cursor":  {"cursor-hook.ps1"},
}

func sortedNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// flatHookRuntimeRecordNames lists the connectors with a flat runtime record
// in hookDir (.hookcfg.<name> naming its own connector), as the shared shell
// readers find them.
func flatHookRuntimeRecordNames(hookDir string) []string {
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		name, ok := strings.CutPrefix(entry.Name(), hookConfigSidecarName+".")
		if !ok || name == "legacy" || name == "lock" || !validFlatHookRuntimeName(name) {
			continue
		}
		path := filepath.Join(hookDir, entry.Name())
		if !hookRuntimeRecordFile(path) {
			continue
		}
		if body, err := readConnectorStateFile(path); err == nil && flatRecordNames(body, name) {
			names = append(names, name)
		}
	}
	return names
}

func validFlatHookRuntimeName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// hookRuntimeRecordFile reports a regular, bounded runtime record (never a
// link).
func hookRuntimeRecordFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() <= hookRuntimeSidecarMaxBytes
}

// bakedHookFailModeOpens are the forms in which a per-user connector hook
// script of 0.8.10 up to this release bakes an open fail mode or lets the
// environment open it, each with its closed form. "_DC_HOME_FAIL_MODE" and
// "[ "open" = "closed" ]" are the missing-home checks. The 1.0.0 to 1.0.3
// per-user copilot-hook.sh let a tool call run on every gateway failure
// whatever FAIL_MODE said (exit 0 with no denial), so its two failure
// functions get Copilot's native denial for tool boundaries.
var bakedHookFailModeOpens = strings.NewReplacer(
	`FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-open}"`, `FAIL_MODE="closed"`,
	`FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-closed}"`, `FAIL_MODE="closed"`,
	`FAIL_MODE="open"`, `FAIL_MODE="closed"`,
	`[ "open" = "closed" ]`, `[ "closed" = "closed" ]`,
	copilotOpenFailUnreachable, copilotClosedFailure(copilotOpenFailUnreachable),
	copilotOpenFailResponse, copilotClosedFailure(copilotOpenFailResponse),
)

// The failure functions of the 1.0.0 to 1.0.3 per-user copilot-hook.sh, as
// rendered, and the native denial their closed form prints before it exits.
const (
	copilotOpenFailUnreachable = "fail_unreachable() {\n" +
		"  defenseclaw_log_hook_failure copilot copilot-hook \"$1\" transport \"$FAIL_MODE\"\n" +
		"  defenseclaw_emit_unreachable_stderr \"copilot tool\" \"$1\"\n" +
		"  exit 0\n}\n"
	copilotOpenFailResponse = "fail_response() {\n" +
		"  defenseclaw_log_hook_failure copilot copilot-hook \"$1\" response \"$FAIL_MODE\"\n" +
		"  echo \"defenseclaw: copilot hook error: $1\" >&2\n" +
		"  exit 0\n}\n"
	copilotToolDenial = copilotDenyReason +
		`  case "${COPILOT_HOOK_EVENT:-}" in` + "\n" +
		`    preToolUse) printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$_dc_deny" ;;` + "\n" +
		`    permissionRequest) printf '{"behavior":"deny","message":"%s"}\n' "$_dc_deny" ;;` + "\n" +
		"  esac\n"
	// copilotInstallWindowReason is the reason this release's per-user
	// copilot-hook.sh (copilot_per_user_install_block) gives Copilot while
	// an install or upgrade holds the account's lock.
	copilotInstallWindowReason = "DefenseClaw is being installed or upgraded for this account; try again in a moment, or run the installer again if it has stopped."
	// copilotDenyReason sets the reason a refreshed released copilot-hook.sh
	// denies with: the install sentence while the lock in the hook's own data
	// folder (HOOK_DIR/..) is held, so Copilot names the upgrade the
	// installer's hold is for (GAP-2319); otherwise the generic one. Only the
	// text depends on the lock: the call is denied either way.
	copilotDenyReason = `  _dc_deny='DefenseClaw hook failed closed'` + "\n" +
		`  if [ -n "${HOOK_DIR:-}" ] && { [ -e "${HOOK_DIR}/../.install.lock" ] || [ -L "${HOOK_DIR}/../.install.lock" ]; }; then _dc_deny='` +
		copilotInstallWindowReason + `'; fi` + "\n"
)

func copilotClosedFailure(open string) string {
	return strings.Replace(open, "  exit 0\n}\n", copilotToolDenial+"  exit 0\n}\n", 1)
}

// hookScriptMaxBytes bounds the hook script closeBakedHookFailMode reads.
const hookScriptMaxBytes = 1 << 20

// bakedAdapterFailModeOpens are the fail-open answers of the per-user Windows
// adapters of 0.8.10 up to this release, each with its closed form. Cursor's
// (cursor-hook.ps1) prints {"continue":true} and exits 0 when the hook
// launcher fails, whatever the mode in 0.8.10 and for a rendered open after
// it; its closed form is the template's. Copilot's (copilot-hook.ps1, 1.0.0
// on) printed nothing, so Copilot ran the tool; its closed form prints
// Copilot's native denial for a tool boundary (copilotAdapterClosedFailure).
// Each match is one line, so an adapter written with CRLF line ends is
// closed too.
var bakedAdapterFailModeOpens = strings.NewReplacer(
	`[Console]::Out.Write('{"continue":true}')`, `[Console]::Out.Write('`+cursorAdapterClosedResponse+`')`,
	"            [Console]::Error.WriteLine('defenseclaw: open gateway-outage mode does not apply to local Cursor adapter failure')\r\n\r\n", "",
	"            [Console]::Error.WriteLine('defenseclaw: open gateway-outage mode does not apply to local Cursor adapter failure')\n\n", "",
	"$exitCode = 0\r\n", "$exitCode = 2\r\n",
	"$exitCode = 0\n", "$exitCode = 2\n",
	copilotAdapterOpenFailure, copilotAdapterClosedFailure,
	copilotAdapterReleasedRead+"\r\n"+copilotAdapterReleasedWrite, copilotAdapterReleasedRead+copilotAdapterCrashCheck+"\r\n"+copilotAdapterReleasedWrite,
	copilotAdapterReleasedRead+"\n"+copilotAdapterReleasedWrite, copilotAdapterReleasedRead+copilotAdapterCrashCheck+"\n"+copilotAdapterReleasedWrite,
)

const (
	// copilotAdapterReleasedRead and copilotAdapterReleasedWrite are the two
	// lines of a 1.0.0 to 1.0.3 copilot-hook.ps1 between which the launcher's
	// answer is passed on. A launcher that crashed (non-zero exit, no answer)
	// threw nothing there, so Copilot got no answer and ran the tool; the
	// catch rewrite alone never ran (GAP-0343). The refresh adds the current
	// template's check on the read line, so the closed catch answers it. The
	// match spans the line end, so a refreshed adapter is not changed again.
	copilotAdapterReleasedRead  = `    $stderr = $stderrTask.GetAwaiter().GetResult()`
	copilotAdapterReleasedWrite = `    if ($stdout.Length -gt 0) {`
	copilotAdapterCrashCheck    = `; if ($stdout.Length -eq 0 -and $process.ExitCode -ne 0) { if ($stderr.Length -gt 0) { [Console]::Error.Write($stderr) }; ` +
		`throw "DefenseClaw hook launcher exited $($process.ExitCode) without an answer" }`
	// cursorAdapterClosedResponse is Cursor's denial in cursor-hook.ps1.
	cursorAdapterClosedResponse = `{"continue":false,"permission":"deny","user_message":"DefenseClaw hook failed closed","agent_message":"DefenseClaw hook failed closed"}`
	// copilotAdapterOpenFailure is the catch block of copilot-hook.ps1 for
	// an open mode: a diagnostic only, so Copilot runs the tool.
	copilotAdapterOpenFailure = `[Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed open: ' + $_.Exception.Message)`
	// copilotAdapterClosedFailure is the catch block for a closed mode:
	// Copilot ignores a failed hook process but honors its native denial,
	// so a tool boundary gets one (the native hook's failNativeDecision).
	copilotAdapterClosedFailure = `[Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed closed: ' + $_.Exception.Message); ` +
		`if (-not $responseWritten) { if ($Event -ceq 'preToolUse') { [Console]::Out.Write('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}') } ` +
		`elseif ($Event -ceq 'permissionRequest') { [Console]::Out.Write('{"behavior":"deny","message":"DefenseClaw hook failed closed"}') } }`
)

// closeBakedHookFailMode rewrites the open a hook script or adapter bakes as
// closed with opens. A missing file, a link or an oversized file is left
// alone.
func closeBakedHookFailMode(path string, opens *strings.Replacer) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect hook %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() || info.Size() > hookScriptMaxBytes {
		return false, nil
	}
	body, err := readConnectorStateFile(path)
	if err != nil {
		return false, fmt.Errorf("read hook %s: %w", filepath.Base(path), err)
	}
	closed := opens.Replace(string(body))
	if filepath.Base(path) == "copilot-hook.sh" {
		closed, err = closeReleasedCopilotEarlyFailures(closed)
		if err != nil {
			return false, fmt.Errorf("close released Copilot hook %s: %w; run setup copilot to repair it", path, err)
		}
	}
	if closed == string(body) {
		return false, nil
	}
	if err := atomicWriteFile(path, []byte(closed), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("close hook %s: %w", filepath.Base(path), err)
	}
	return true, nil
}

const copilotUpgradeEarlyMarker = "_DC_COPILOT_UPGRADE_EARLY=1"

// hookBodyIsDisabledTombstone reports a hook script whose line-2 marker is
// the v0 one teardown writes (writeDisabledHookTombstone and the failed-setup
// placeholder): it calls no gateway and has no failure paths to close, so a
// refresh leaves it as it is (GAP-2282: an upgrade with a torn-down Copilot
// hook stopped with "unrecognized released hook layout").
func hookBodyIsDisabledTombstone(body string) bool {
	lines := strings.SplitN(body, "\n", 3)
	return len(lines) >= 2 && strings.HasPrefix(lines[1], "# defenseclaw-managed-hook v0 ")
}

// closeReleasedCopilotEarlyFailures closes the paths of a 0.8.10 or 1.0.0 to
// 1.0.3 per-user copilot-hook.sh that run before its failure functions: a
// missing helper, token or payload exited 0, so Copilot ran the tool even
// after the refresh closed fail_unreachable and fail_response (GAP-0345).
// Each such exit prints Copilot's native denial on a tool boundary instead,
// whatever the mode, as the installer's own window does (GAP-0649). The
// installer runs this before it stops the old gateway; a current render
// (copilot_hook_failure) or an already closed one is left as it is.
func closeReleasedCopilotEarlyFailures(body string) (string, error) {
	if strings.Contains(body, copilotUpgradeEarlyMarker) || strings.Contains(body, "copilot_hook_failure()") ||
		!strings.Contains(body, "# defenseclaw-managed-hook v") || hookBodyIsDisabledTombstone(body) {
		return body, nil
	}
	const start = "set -euo pipefail\n"
	cut := strings.Index(body, "API_ADDR=")
	if !strings.Contains(body, start) || cut < 0 {
		return "", fmt.Errorf("unrecognized released hook layout")
	}
	prefix, suffix := body[:cut], body[cut:]
	// The released scripts allowed helper and token failures with exit 0.
	// Every such early exit, the no-home and malformed-event branches too,
	// becomes a native denial on tool boundaries.
	prefix = strings.ReplaceAll(prefix, "exit 0", "_dc_copilot_upgrade_early_failure")
	prefix = strings.ReplaceAll(prefix, "allowing copilot tool", "blocking copilot tool")
	prefix = strings.Replace(prefix,
		"defenseclaw_handle_missing_token copilot copilot-hook \"copilot tool\"",
		"(defenseclaw_handle_missing_token copilot copilot-hook \"copilot tool\") || true\n  _dc_copilot_upgrade_early_failure", 1)
	// Any exit while the marker is armed is an early failure, whatever its
	// status: macOS /bin/bash 3.2 runs the EXIT trap with $? 0 when a
	// sourced helper is missing (GAP-2141), so the trap cannot test the
	// status. The denial disarms the marker first, so its own exit 0 does
	// not print a second object.
	//
	// The released scripts read --event only after these exits, so the
	// preamble reads it from the script's own arguments. A hook bound to no
	// event (0.8.10) prints one object with both denies, as copilot_deny does.
	preamble := copilotUpgradeEarlyMarker + `
_DC_COPILOT_UPGRADE_EVENT=""
if [ "$#" -eq 2 ] && [ "$1" = "--event" ]; then _DC_COPILOT_UPGRADE_EVENT="$2"; fi
_dc_copilot_upgrade_early_failure() {
  _DC_COPILOT_UPGRADE_EARLY=0
` + copilotDenyReason + `  case "$_DC_COPILOT_UPGRADE_EVENT" in
    preToolUse) printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$_dc_deny" ;;
    permissionRequest) printf '{"behavior":"deny","message":"%s"}\n' "$_dc_deny" ;;
    sessionStart|sessionEnd|userPromptSubmitted|userPromptTransformed|postToolUse|agentStop|subagentStart|subagentStop|postToolUseFailure|errorOccurred|preCompact|notification) ;;
    *) printf '{"permissionDecision":"deny","permissionDecisionReason":"%s","behavior":"deny","message":"%s"}\n' "$_dc_deny" "$_dc_deny" ;;
  esac
  exit 0
}
trap 'if [ "${_DC_COPILOT_UPGRADE_EARLY:-0}" = 1 ]; then _dc_copilot_upgrade_early_failure; fi' EXIT
`
	prefix = strings.Replace(prefix, start, start+preamble, 1)
	// Hardening installs its own cleanup trap: keep it and re-arm the
	// native denial until the first gateway request has been prepared.
	cleanup := "trap '_defenseclaw_hook_cleanup; if [ \"${_DC_COPILOT_UPGRADE_EARLY:-0}\" = 1 ]; then _dc_copilot_upgrade_early_failure; fi' EXIT"
	if strings.Contains(prefix, "if ! defenseclaw_harden_env; then") {
		anchor := "fi\n\n# Copilot documents timeout failures"
		if !strings.Contains(prefix, anchor) {
			return "", fmt.Errorf("unrecognized hardening exit")
		}
		prefix = strings.Replace(prefix, anchor, "fi\n"+cleanup+"\n\n# Copilot documents timeout failures", 1)
	} else if strings.Contains(prefix, "defenseclaw_harden_env\n") {
		prefix = strings.Replace(prefix, "defenseclaw_harden_env\n",
			"defenseclaw_harden_env || _dc_copilot_upgrade_early_failure\n"+cleanup+"\n", 1)
	} else {
		return "", fmt.Errorf("missing hardening call")
	}
	const responseStart = "fail_unreachable() {"
	at := strings.Index(suffix, responseStart)
	if at < 0 {
		return "", fmt.Errorf("missing released failure response")
	}
	return prefix + suffix[:at] + "_DC_COPILOT_UPGRADE_EARLY=0\n" + suffix[at:], nil
}

// OutageHookFailMode records the tier's mode for legacy per-user hook refresh
// and setup metadata. Current per-user hooks read the config at call time.
// Managed and Secure Client renders keep their resolved mode.
func OutageHookFailMode(opts SetupOpts, conn Connector) string {
	if perUserOutageRender(opts) {
		return normalizeHookFailMode(opts.HookFailMode)
	}
	return resolveHookFailMode(opts, conn)
}

// perUserOutageRender reports a per-user render: neither managed nor the
// Secure Client delivery contract.
func perUserOutageRender(opts SetupOpts) bool {
	return !opts.ManagedEnterprise && !opts.SecureClientHookDelivery
}

// renderedHookFailMode is the fail mode conn's rendered hooks bake and its
// sidecar entry records: the outage mode, subject to Secure Client's vendor
// capability limit (CapableHookFailMode).
func renderedHookFailMode(opts SetupOpts, conn Connector) string {
	return CapableHookFailMode(opts, conn, OutageHookFailMode(opts, conn))
}

// clearHookConfigSidecarEntry removes only one connector's runtime selection.
// The shared JSON state and every peer's flat record remain intact. Runtime
// state is cleared before its contract entry, so a teardown can never leave a
// removed connector selectable by the shared Unix hooks.
func clearHookConfigSidecarEntry(hookDir, connectorName string) error {
	name := normalizeConnectorName(connectorName)
	if strings.TrimSpace(hookDir) == "" || name == "" {
		return nil
	}
	if _, err := os.Stat(hookDir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect hook runtime directory: %w", err)
	}
	path := filepath.Join(hookDir, hookConfigSidecarName)
	return withFileLock(path, func() error {
		_, err := clearHookConfigSidecarEntryLocked(hookDir, name, false)
		return err
	})
}

func clearHookConfigSidecarEntryLocked(
	hookDir, name string,
	managedEnterprise bool,
) ([]hookRuntimeFileSnapshot, error) {
	writeFile := hookRuntimeFileWriter(managedEnterprise)
	path := filepath.Join(hookDir, hookConfigSidecarName)
	flatPath := filepath.Join(hookDir, hookConfigSidecarName+"."+name)
	jsonSnapshot, err := snapshotHookRuntimeFileForMode(path, managedEnterprise)
	if err != nil {
		return nil, fmt.Errorf("read hook config sidecar: %w", err)
	}
	flatSnapshot, err := snapshotHookRuntimeFileForMode(flatPath, managedEnterprise)
	if err != nil {
		return nil, fmt.Errorf("read shell hook runtime sidecar: %w", err)
	}
	snapshots := []hookRuntimeFileSnapshot{jsonSnapshot, flatSnapshot}
	if jsonSnapshot.existed {
		var state hookConfigSidecar
		if err := json.Unmarshal(jsonSnapshot.data, &state); err != nil {
			// A legacy scalar sidecar has no connector entry to remove and
			// remains available for unmigrated callers. Unknown malformed JSON
			// is not overwritten because that could destroy peer state.
			values, ok := ParseLegacyHookSidecar(jsonSnapshot.data)
			legacyMode := values["DEFENSECLAW_FAIL_MODE"]
			if !ok || (legacyMode != "open" && legacyMode != "closed") {
				return nil, fmt.Errorf("parse hook config sidecar: %w", err)
			}
		} else if err := hookSidecarRewriteRefused(jsonSnapshot.data); err != nil {
			// Rewriting it would settle it, maybe into an open mode the
			// readers close on now.
			return nil, err
		} else if !jsonSnapshot.regular {
			return nil, errHookConfigSidecarNotRegular
		} else {
			if state.Version != 2 {
				return nil, fmt.Errorf("unsupported hook config sidecar version %d", state.Version)
			}
			if _, ok := state.FailModes[name]; ok {
				delete(state.FailModes, name)
				delete(state.FailModeSources, name)
				body, err := json.MarshalIndent(state, "", "  ")
				if err != nil {
					return nil, fmt.Errorf("marshal hook config sidecar: %w", err)
				}
				body = append(body, '\n')
				if err := writeFile(path, body, 0o600); err != nil {
					return nil, fmt.Errorf("write hook config sidecar: %w", err)
				}
			}
		}
	}
	if err := os.Remove(flatPath); err != nil && !os.IsNotExist(err) {
		if restoreErr := restoreHookRuntimeFilesUsing(snapshots, writeFile); restoreErr != nil {
			return nil, fmt.Errorf("remove shell hook runtime sidecar: %v (%v)", err, restoreErr)
		}
		return nil, fmt.Errorf("remove shell hook runtime sidecar: %w", err)
	}
	return snapshots, nil
}

// validateHookRuntimeStateForContract closes the reconcile/teardown race: a
// contract entry is committed only while its connector-aware JSON and flat
// runtime records still agree. Absence of the shared sidecar is tolerated for
// legacy/direct lock writers that do not install hooks; once the sidecar
// exists, a missing or stale selected entry is an error.
func validateHookRuntimeStateForContract(
	dataDir, connectorName, failMode string,
	managedEnterprise bool,
) error {
	name := normalizeConnectorName(connectorName)
	if strings.TrimSpace(dataDir) == "" || name == "" {
		return nil
	}
	if name != "claudecode" && name != "codex" && name != "cursor" {
		return nil
	}
	hookDir := filepath.Join(dataDir, "hooks")
	path := filepath.Join(hookDir, hookConfigSidecarName)
	var (
		body   []byte
		exists bool
		err    error
	)
	if managedEnterprise {
		body, exists, err = readStableHookRuntimeSidecar(
			path,
			"hook config sidecar",
			true,
		)
	} else {
		// Preserve the pre-enterprise unmanaged contract exactly: follow the
		// operator's path and let json.Unmarshal handle the complete file.
		body, err = readConnectorStateFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		exists = err == nil
	}
	if err != nil {
		return fmt.Errorf("read hook config sidecar: %w", err)
	}
	if !exists {
		return nil
	}
	var state hookConfigSidecar
	if managedEnterprise {
		if err := decodeManagedHookConfigSidecar(body, &state); err != nil {
			return fmt.Errorf("parse managed hook config sidecar: %w", err)
		}
		if !state.Managed {
			return errors.New("managed hook config sidecar is missing managed_enterprise=true")
		}
	} else if err := json.Unmarshal(body, &state); err != nil {
		return fmt.Errorf("parse hook config sidecar: %w", err)
	} else if HookSidecarJSONAmbiguous(body) {
		return errAmbiguousHookConfigSidecar
	}
	if state.Version != 2 {
		return fmt.Errorf("unsupported hook config sidecar version %d", state.Version)
	}
	want := normalizeHookFailMode(failMode)
	if got := state.FailModes[name]; got != want {
		return fmt.Errorf("connector %s JSON fail mode %q, want %q", name, got, want)
	}
	flatPath := filepath.Join(hookDir, hookConfigSidecarName+"."+name)
	var flat []byte
	if managedEnterprise {
		flat, _, err = readStableHookRuntimeSidecar(
			flatPath,
			"connector shell runtime sidecar",
			false,
		)
	} else {
		flat, err = readConnectorStateFile(flatPath)
	}
	if err != nil {
		return fmt.Errorf("read connector shell runtime sidecar: %w", err)
	}
	if got, ok := flatHookRecordValue(flat, "DEFENSECLAW_CONNECTOR"); !ok || got != name {
		return fmt.Errorf("shell runtime connector %q, want %q", got, name)
	}
	if got, ok := flatHookRecordValue(flat, "DEFENSECLAW_FAIL_MODE"); !ok || got != want || got != state.FailModes[name] {
		return fmt.Errorf("connector %s shell fail mode %q, want %q", name, got, want)
	}
	return nil
}

func decodeManagedHookConfigSidecar(data []byte, state *hookConfigSidecar) error {
	if state == nil {
		return errors.New("managed hook config destination is nil")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(state); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("managed hook config contains trailing JSON")
		}
		return err
	}
	return hookSidecarRewriteRefused(data)
}

// errAmbiguousHookConfigSidecar is a JSON sidecar that names a key twice or
// a field in another case (HookSidecarJSONAmbiguous).
var errAmbiguousHookConfigSidecar = errors.New("parse hook config sidecar: a key is given twice or a field is named in another case")

// errHookConfigSidecarNotRegular is a hooks/.hookcfg that is a link or
// another file that is not regular, which the shared hooks close on.
var errHookConfigSidecarNotRegular = errors.New("parse hook config sidecar: not a regular file")

// readStableHookRuntimeSidecar bounds allocation from file metadata, rejects
// links and non-regular objects, pins the opened file identity, and performs
// two identical bounded reads. The second read closes same-inode rewrite and
// truncate races that an lstat/open/lstat sequence alone would miss.
func readStableHookRuntimeSidecar(
	path, label string,
	allowMissing bool,
) ([]byte, bool, error) {
	return readStableManagedRuntimeFile(
		path,
		label,
		allowMissing,
		hookRuntimeSidecarMaxBytes,
	)
}

// ReadManagedHookRuntimeFile reads an already-authorized target-owned runtime
// leaf through an identity-pinned, no-reparse, single-link handle. Callers
// provide a format-specific allocation ceiling; trust in the owning directory
// and DACL remains the caller's responsibility.
func ReadManagedHookRuntimeFile(path, label string, maxBytes int64) ([]byte, error) {
	data, _, err := readStableManagedRuntimeFile(path, label, false, maxBytes)
	return data, err
}

func readStableManagedRuntimeFile(
	path, label string,
	allowMissing bool,
	maxBytes int64,
) ([]byte, bool, error) {
	return readStableManagedRuntimeFileForOwner(
		path,
		label,
		allowMissing,
		maxBytes,
		"",
	)
}

func readStableManagedRuntimeFileForOwner(
	path, label string,
	allowMissing bool,
	maxBytes int64,
	expectedOwnerSID string,
) ([]byte, bool, error) {
	if maxBytes <= 0 {
		return nil, false, fmt.Errorf("%s has an invalid read limit", label)
	}
	expected, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular non-link file", label)
	}
	if expected.Size() < 0 || expected.Size() > maxBytes {
		return nil, false, fmt.Errorf(
			"%s exceeds %d-byte limit",
			label,
			maxBytes,
		)
	}
	file, err := openConnectorStateFileWithRetry(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() ||
		!os.SameFile(expected, opened) {
		return nil, false, fmt.Errorf("%s changed identity before open", label)
	}
	if err := validateHookRuntimeOpenedFile(file, label); err != nil {
		return nil, false, err
	}
	if err := validateManagedSharedHookOpenedFile(file, expectedOwnerSID); err != nil {
		return nil, false, err
	}
	readOnce := func() ([]byte, error) {
		data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBytes {
			return nil, fmt.Errorf(
				"%s exceeds %d-byte limit",
				label,
				maxBytes,
			)
		}
		return data, nil
	}
	first, err := readOnce()
	if err != nil {
		return nil, false, err
	}
	between, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, false, err
	}
	second, err := readOnce()
	if err != nil {
		return nil, false, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, false, fmt.Errorf("%s changed after open: %w", label, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(opened, current) ||
		opened.Size() != int64(len(first)) ||
		between.Size() != opened.Size() ||
		after.Size() != opened.Size() ||
		!between.ModTime().Equal(opened.ModTime()) ||
		!after.ModTime().Equal(opened.ModTime()) ||
		!bytes.Equal(first, second) {
		return nil, false, fmt.Errorf("%s changed during bounded read", label)
	}
	return first, true, nil
}

// ValidateHookRuntimeState performs the read-only connector-aware sidecar
// consistency check used when committing hook contracts. Enterprise guardian
// status/verify paths use the same parser so they cannot report a runtime as
// healthy when the JSON and flat sidecars disagree.
func ValidateHookRuntimeState(dataDir, connectorName, failMode string) error {
	return validateHookRuntimeStateForContract(dataDir, connectorName, failMode, false)
}

// ValidateManagedHookRuntimeState applies strict single-link identity and
// exact-schema parsing for enterprise guardian status and verification.
func ValidateManagedHookRuntimeState(dataDir, connectorName, failMode string) error {
	return validateHookRuntimeStateForContract(dataDir, connectorName, failMode, true)
}

func hookScriptNamesForConnector(opts SetupOpts, c Connector) []string {
	var extras []string
	if owner, ok := c.(HookScriptOwner); ok {
		extras = owner.HookScriptNames(opts)
	}
	return hookScriptNamesFromExtras(extras)
}

func hookScriptNamesFromExtras(extras []string) []string {
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
	return scripts
}

func hookScriptPathsForConnector(opts SetupOpts, c Connector) []string {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	names := hookScriptNamesForConnector(opts, c)
	hooks := make([]string, 0, len(names))
	for _, name := range names {
		hooks = append(hooks, filepath.Join(hookDir, name))
	}
	return hooks
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
	return writeHookScriptsCommonWithOptions(hookDir, apiAddr, token, defaultHookFailMode, extras, false, c.Name(), !IsProxyConnector(c.Name()))
}

// WriteHookScriptsForConnectorObjectWithOpts is the setup-time variant that
// has access to connector setup flags AND the operator's chosen hook failure
// mode (opts.HookFailMode).
//
// Per-user renders are closed, including Cursor observe mode and an old saved
// open. Managed standalone renders honor only the administrator's mode;
// an unset value is closed. A verified Secure Client render honors its
// explicit mode and defaults open (#1163), with its existing vendor limits.
//
// An open choice covers a confirmed gateway outage only: an answered,
// malformed or unanswered call blocks outside Secure Client.
// DEFENSECLAW_STRICT_AVAILABILITY=1 can only tighten this choice.
func WriteHookScriptsForConnectorObjectWithOpts(hookDir string, opts SetupOpts, c Connector) error {
	render := resolveConnectorHookRender(opts, c)
	return writeHookScriptsCommonWithTransport(hookDir, opts.APIAddr, render.token, render.failMode, render.failModeSource, render.extras, opts.ManagedEnterprise,
		c.Name(), render.scopedToken, render.socketTransport, render.foreignGuard, shellHookSecureClientProfile(opts),
		shellHookSecureClientDelivery(opts), render.hermesNativeHook)
}

// connectorHookRender is what WriteHookScriptsForConnectorObjectWithOpts
// renders a connector's hook scripts with.
type connectorHookRender struct {
	extras   []string
	failMode string
	// failModeSource records the resolved mode's provenance.
	failModeSource   string
	token            string
	scopedToken      bool
	socketTransport  string
	foreignGuard     string
	hermesNativeHook string
}

// Secure Client renders managed hooks into each user's home. The trusted
// install marker, not the process environment or hook path, selects it.
func shellHookSecureClientProfile(opts SetupOpts) bool {
	return opts.ManagedEnterprise && strings.TrimSpace(opts.ManagedHookSocket) == "" &&
		strings.TrimSpace(opts.ManagedHookBinary) == "" && SecureClientDeploymentVerified()
}

// shellHookSecureClientDelivery reports a Secure Client shell render whose
// hooks follow the Secure Client delivery contract (#1163): the profile the
// caller resolved is Secure Client (opts.SecureClientHookDelivery) and the
// host is an authenticated Secure Client deployment
// (SecureClientDeploymentVerified). Only such a hook follows the installed
// Secure Client mode on an unreachable gateway or a missing token.
func shellHookSecureClientDelivery(opts SetupOpts) bool {
	return shellHookSecureClientProfile(opts) && opts.SecureClientHookDelivery
}

func resolveConnectorHookRender(opts SetupOpts, c Connector) connectorHookRender {
	var render connectorHookRender
	if owner, ok := c.(HookScriptOwner); ok {
		render.extras = owner.HookScriptNames(opts)
	}
	render.failMode = renderedHookFailMode(opts, c)
	if render.failMode == OutageHookFailMode(opts, c) {
		render.failModeSource = HookFailModeSourceConfig
	}
	render.token = opts.HookAPIToken
	render.scopedToken = opts.HookAPITokenScoped
	if strings.TrimSpace(render.token) == "" {
		render.token = opts.APIToken
		// Backward-compatible direct callers predate HookAPIToken. Preserve
		// scoped sidecars for hook-native connectors, but never disguise a
		// proxy connector's master token as connector-scoped.
		render.scopedToken = !IsProxyConnector(c.Name())
	}
	// A managed standalone install on a unix host sends connector shell hooks
	// through the gateway's peer-authorized unix hook socket, as it already
	// does for in-agent plugins. Every other install (per-user, Secure
	// Client, Windows) has no socket here and keeps the TCP transport.
	// The standalone Hermes hook also runs the foreign-hook guard
	// (shellHookForeignGuardBinary, which needs the socket); no other hook or
	// install does. The guard runs inside the socket transport, before its
	// socket checks: a stopped gateway removes the socket, and the check must
	// still deny the guarded call under fail mode open (GAP-0354).
	if binary := shellHookForeignGuardBinary(opts, c.Name()); binary != "" {
		render.foreignGuard = shellHookForeignGuard(binary)
	}
	if socket, serviceUID := managedPluginHookSocket(opts); socket != "" {
		render.socketTransport = shellHookSocketTransport(socket, serviceUID, managedSessionFactsBinary(opts), render.foreignGuard)
		if normalizeConnectorName(c.Name()) == "hermes" {
			render.hermesNativeHook = managedSessionFactsBinary(opts)
		}
	}
	return render
}

// CapableHookFailMode is the mode a hook records. A lack of a vendor-level
// fail-closed contract cannot turn a per-user or managed standalone closed
// mode open; supported blocking events still use the hook's native denial.
// Secure Client keeps its existing vendor-capability limit.
func CapableHookFailMode(opts SetupOpts, conn Connector, mode string) string {
	if mode == "closed" && shellHookSecureClientProfile(opts) {
		if provider, ok := conn.(HookCapabilityProvider); ok && !provider.HookCapabilities(opts).SupportsFailClosed {
			return "open"
		}
	}
	return mode
}

// managedStandaloneRender reports a managed render outside the Secure Client
// profile (shellHookSecureClientProfile): a standalone install's hooks.
func managedStandaloneRender(opts SetupOpts) bool {
	return opts.ManagedEnterprise && !shellHookSecureClientProfile(opts)
}

// resolveHookFailMode picks the delivery/response fail mode for a hook render
// given the operator's setup opts and the connector identity.
//
// Under Secure Client (opts.SecureClientHookDelivery, #1163) the explicit
// string in opts.HookFailMode always wins and an empty value is open on an
// authenticated Secure Client deployment (setupHookFailMode): guardrail mode
// and enforcement flags do not change availability policy.
//
// On a per-user host, fail closed regardless of values carried over from an
// older config or provided by a direct render caller.
func resolveHookFailMode(opts SetupOpts, _ Connector) string {
	if managedStandaloneRender(opts) {
		// The administrator's config chose this mode (explicit open, or
		// closed by default); Cursor's observe boundary does not change it.
		return normalizeHookFailMode(opts.HookFailMode)
	}
	if opts.SecureClientHookDelivery {
		return setupHookFailMode(opts)
	}
	return defaultHookFailMode
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

// ResolveSubprocessPolicy determines the effective subprocess policy. The
// legacy openshell-sandbox tier is gone (its generated policy file was never
// enforced), so a sandbox preference resolves to shims on every platform.
func ResolveSubprocessPolicy(preferred SubprocessPolicy) SubprocessPolicy {
	if preferred == SubprocessSandbox {
		return SubprocessShims
	}
	return preferred
}

// shimConnectorNameRE is a connector name a shim can carry unquoted.
var shimConnectorNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// SetupSubprocessEnforcement wires the appropriate subprocess enforcement
// tier based on the resolved policy. connectorName is the installing
// connector, whose outage mode the shims follow.
func SetupSubprocessEnforcement(policy SubprocessPolicy, opts SetupOpts, connectorName string) error {
	switch ResolveSubprocessPolicy(policy) {
	case SubprocessShims:
		shimDir := filepath.Join(opts.DataDir, "shims")
		// F-2029 / F-3397: persist the gateway bearer token alongside
		// the shim scripts so every inspection call carries an
		// Authorization header. Pre-fix the shim had no auth token
		// available and silently downgraded a 401 to "allow".
		if err := writeShimScriptsWithMode(shimDir, opts.APIAddr, opts.APIToken, opts.HookFailMode, connectorName); err != nil {
			return fmt.Errorf("shim scripts: %w", err)
		}

	case SubprocessNone:
		// No enforcement to set up.
	}
	return nil
}

// TeardownSubprocessEnforcement removes shim scripts and any stale policy
// file an older release wrote for the removed openshell-sandbox tier. It
// deliberately does NOT touch the shared hooks/
// directory anymore: the previous implementation iterated the GLOBAL
// `hookScripts` slice (= every connector's *-hook.sh + every generic
// inspect-*.sh) and deleted them all from the shared dir. When called
// from one connector's Teardown — e.g. claudecode.Teardown during a
// claudecode → codex switch — that wiped scripts owned by the
// incoming connector AND the shared inspect-*.sh helpers. If the
// follow-up codex.Setup() then failed to re-write codex-hook.sh
// (silent partial install, mtime race, hostFS read miss, etc.), the
// agent ended up with an empty hooks/ dir and every hook invocation
// failed with exit 127 ("command not found").
//
// Per-connector hook lifecycle is now the responsibility of each
// Connector.Teardown via writeDisabledHookTombstone, which replaces
// the connector's own *-hook.sh in place with a v0 tombstone so
// long-lived host processes that cached the absolute hook path exit
// cleanly. The shared inspect-*.sh helpers are intentionally left
// untouched across connector switches — they're written by every
// connector's hookwriter and removing them here is what produced the
// original exit-127 bug during a claudecode → codex switch.
func TeardownSubprocessEnforcement(opts SetupOpts) error {
	shimDir := filepath.Join(opts.DataDir, "shims")
	_ = os.RemoveAll(shimDir)

	policyPath := filepath.Join(opts.DataDir, "policies", "defenseclaw-policy.yaml")
	_ = os.Remove(policyPath)

	return nil
}

// writeDisabledHookTombstone replaces <DataDir>/hooks/<scriptName>
// with a no-op POSIX shell stub so a long-lived host agent process
// that cached the absolute hook path exits cleanly (exit 0) instead
// of either:
//
//   - ENOENT → exit 127 if the file had been removed during a connector
//     switch, or
//   - hitting a transport-failure fail-closed path when the operator
//     has set DEFENSECLAW_STRICT_AVAILABILITY=1 and the gateway is
//     gone or no longer serves the connector's hook endpoint.
//
// vendorLabel is interpolated into the tombstone body so an operator
// reading the file later sees which connector tore down. Pass the
// connector's lowercase name (e.g. "codex", "hermes") or a
// human-friendly equivalent ("Claude Code") — both are fine.
//
// Format invariants — assert them in TestHookOwners_TeardownLeavesTombstone:
//
//   - Shebang is /bin/sh (not /bin/bash) so the tombstone runs on
//     minimal hosts where /bin/bash is absent (Alpine, distroless,
//     some BSDs). POSIX sh is enough. Devin's per-user cached path exits 2
//     after token revocation; the usual disabled body exits 0.
//   - Line 2 carries the v0 schema marker so scriptHasMarker /
//     isOwnedHook recognise the tombstone as DefenseClaw-owned.
//     v0 is the "older than any tagged version" sentinel; any
//     actively-installed *-hook.sh (currently v3+) beats it in
//     downgrade-safety comparisons.
//   - The write is atomic (CreateTemp + rename) so a concurrent
//     hook invocation either sees the prior content or the
//     tombstone, never an empty/partial file.
//   - The body never contains a /api/v1/.../hook URL — the
//     tombstone MUST NOT forward stale payloads.
//
// File mode is 0o700 (owner-only rwx) to match the live hook scripts.
func writeDisabledHookTombstone(opts SetupOpts, scriptName, vendorLabel string) error {
	if strings.TrimSpace(scriptName) == "" {
		return fmt.Errorf("tombstone: empty scriptName")
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("ensure hook dir: %w", err)
	}
	target := filepath.Join(hookDir, scriptName)
	// A teardown runs as the account. A hook folder that account cannot
	// search (a root-owned ~/.defenseclaw/hooks made by sudo with HOME kept)
	// holds no script its agents can run, so there is nothing to disable:
	// that is not a failure (GAP-1978, same class as GAP-1904). The
	// fail-closed rollback placeholder still reports the error.
	if runtime.GOOS != "windows" && !opts.FailedSetupFailClosed {
		if _, err := os.Lstat(target); errors.Is(err, os.ErrPermission) {
			return nil
		}
	}
	// A managed Windows hook folder holds only files with the managed runtime
	// DACL; the generic private descriptor made a later rollback refuse to
	// remove the tombstone, which left the deployment pending.
	body := disabledHookTombstone(vendorLabel)
	if vendorLabel == "devin" && !pluginSecureClientProfile(opts) {
		// A cached Devin process can still execute the old absolute hook path
		// after removal. Keep it blocked until that process exits; this path
		// cannot become an implicit allow when its credential is revoked.
		body = "#!/bin/sh\n" +
			"# defenseclaw-managed-hook v0 (disabled tombstone)\n" +
			"echo 'defenseclaw: Devin hook was removed; restart Devin before using it' >&2\n" +
			"exit 2\n"
	}
	if opts.FailedSetupFailClosed && failedSetupPlaceholderBlocks[scriptName] {
		body = failedSetupHookPlaceholder(vendorLabel)
	}
	return hookRuntimeFileWriter(opts.ManagedEnterprise)(target, []byte(body), 0o700)
}

// failedSetupPlaceholderBlocks lists the hook scripts whose agents treat
// exit 2 as a block and show its stderr to the user.
var failedSetupPlaceholderBlocks = map[string]bool{
	"claude-code-hook.sh": true,
	"codex-hook.sh":       true,
}

// failedSetupHookPlaceholder is the hook body a rollback leaves for a
// fail-closed connector whose setup failed at gateway start. It keeps the
// tombstone marker, so teardown and doctor still recognise it, but blocks
// every call and says why (GAP-0367).
func failedSetupHookPlaceholder(vendorLabel string) string {
	return "#!/bin/sh\n" +
		"# defenseclaw-managed-hook v0 (disabled tombstone)\n" +
		"# The gateway could not set up the fail-closed " + vendorLabel + " connector when it\n" +
		"# started. Block every call until a gateway start sets it up again.\n" +
		"echo \"defenseclaw: " + vendorLabel + " is not guarded: the gateway failed to set it up when it started, so this call is blocked (fail mode closed). Run defenseclaw-gateway status to see the error, fix it, then run defenseclaw-gateway start.\" >&2\n" +
		"exit 2\n"
}

// HookFailClosed reports whether conn blocks agent calls when its gateway is
// unavailable under opts.
func HookFailClosed(opts SetupOpts, conn Connector) bool {
	return renderedHookFailMode(opts, conn) == "closed"
}

// disabledHookTombstone is the body writeDisabledHookTombstone writes.
func disabledHookTombstone(vendorLabel string) string {
	if vendorLabel == "" {
		vendorLabel = "DefenseClaw connector"
	}
	return "#!/bin/sh\n" +
		"# defenseclaw-managed-hook v0 (disabled tombstone)\n" +
		"# " + vendorLabel + " connector was torn down. Existing host processes may\n" +
		"# keep this hook path cached until restart, so exit successfully\n" +
		"# without forwarding stale payloads.\n" +
		"exit 0\n"
}

// ManagedOutageClosed reports a render whose hooks block a gateway outage
// whatever FailMode says: a managed render outside the Secure Client profile
// (the Linux and macOS standalone hook socket, and the sandbox) of a
// connector in managedUnixOutageClosed (HookOutage). Only the templates of
// those connectors call it, so a render that names no connector keeps the
// closed side.
func (d templateData) ManagedOutageClosed() bool {
	if !d.Managed || d.SecureClient {
		return false
	}
	return d.ConnectorName == "" || managedUnixOutageClosed[d.ConnectorName]
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
