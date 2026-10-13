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
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// In-image Codex system policy. On Linux Codex reads both files from
// /etc/codex: requirements.toml constrains every other layer, and the legacy
// managed_config.toml layer beats user config and -c flags for the keys it
// sets.
const (
	CodexSandboxRequirementsPath  = "/etc/codex/requirements.toml"
	CodexSandboxManagedConfigPath = "/etc/codex/managed_config.toml"
	codexSandboxNotifyScript      = "codex-notify.sh"
	codexSandboxOtelEnvironment   = "openshell"
)

// codexSandboxDisabledFeatures are the Codex features whose background sync
// reaches chatgpt.com, GitHub or the update service. With them off (plus
// analytics and the update check) Codex makes no stray outbound calls.
var codexSandboxDisabledFeatures = []string{
	"apps",
	"in_app_updates",
	"plugin_sharing",
	"plugins",
	"remote_plugin",
	"tool_suggest",
}

// codexSandboxPinnedShellEnv are variables the managed config pins in
// shell_environment_policy.set, the environment Codex gives every command
// it runs (the shell tool, and the processes that command starts): a
// workload-written user config.toml, or a trusted project's, can set them
// there. BASH_ENV and ENV name a file each non-interactive shell sources
// before the command PreToolUse approved, and the loader variables act
// before the command's first line; "" is unset to both. PATH stays unpinned
// (projects set it legitimately); the hooks harden their own. The image's
// hook-fire probe plants all of them in its hostile user and project
// config.
var codexSandboxPinnedShellEnv = []string{"BASH_ENV", "ENV", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"}

// codexSandboxLauncherOnlyEnv are variables the DefenseClaw launcher sets
// for Codex itself that the commands Codex runs must not inherit, pinned to
// "" in shell_environment_policy.set as well: the OTLP header variables
// carry the binding token (an OpenTelemetry SDK in a command would send it
// to its own collector), and NODE_OPTIONS carries the launcher's
// --disable-warning for Codex's Node wrapper, which a Node release before
// 20.11 in a project would refuse to start with. The launcher drops a
// caller's NODE_OPTIONS either way.
var codexSandboxLauncherOnlyEnv = []string{
	"NODE_OPTIONS",
	"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
	"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
}

// codexSandboxShellPins are every variable the managed config pins to "" in
// shell_environment_policy.set.
func codexSandboxShellPins() []string {
	return append(append([]string{}, codexSandboxPinnedShellEnv...), codexSandboxLauncherOnlyEnv...)
}

// SandboxArtifacts renders the Codex overlay: sandbox hook scripts, the
// notify bridge, /etc/codex/requirements.toml (allow_managed_hooks_only,
// features.hooks pinned true and the contract-selected hook matrix) and
// /etc/codex/managed_config.toml (update check, analytics and network-syncing
// features off, notify, OTLP exporters to the ingress, the shell variables in
// codexSandboxShellPins pinned).
func (c *CodexConnector) SandboxArtifacts(target SandboxRenderTarget) (SandboxArtifacts, error) {
	rt, err := resolveSandboxTarget(c.Name(), target)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	hookFiles, err := renderSandboxHookFiles(c.Name(), rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	requirements, err := renderCodexSandboxRequirements(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	environment := strings.TrimSpace(target.OtelEnvironment)
	if environment == "" {
		environment = codexSandboxOtelEnvironment
	}
	managedConfig, err := renderCodexSandboxManagedConfig(rt, environment)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyCodexSandboxPolicy(requirements, managedConfig, rt, environment); err != nil {
		return SandboxArtifacts{}, err
	}
	notify := renderCodexSandboxNotifyBridge(rt.ingressAddr)

	files := append(hookFiles,
		SandboxFile{Path: path.Join(SandboxHookDir, codexSandboxNotifyScript), Mode: 0o755, Owner: SandboxOwnerRoot, Data: notify},
		SandboxFile{Path: CodexSandboxRequirementsPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: requirements},
		SandboxFile{Path: CodexSandboxManagedConfigPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: managedConfig},
	)
	binaries := append(sandboxHookRuntimeBinaries(), SandboxBinary{Name: "codex", Role: SandboxBinaryHarness})
	return finalizeSandboxArtifacts(SandboxArtifacts{
		Connector:    c.Name(),
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierManaged,
		Files:        files,
		Env:          map[string]string{},
		Binaries:     binaries,
	})
}

// codexSandboxRequirementsLayout is the Unix counterpart of the Windows
// machine layout: hooks.managed_dir instead of hooks.windows_managed_dir and
// a POSIX handler bound to one event and one contract.
func codexSandboxRequirementsLayout(rt resolvedSandboxTarget) (codexMachineRequirementsLayout, error) {
	groups, err := codexHookGroupsForSetup(rt.opts)
	if err != nil {
		return codexMachineRequirementsLayout{}, err
	}
	hookScript := path.Join(SandboxHookDir, "codex-hook.sh")
	contractID := rt.contract.ContractID
	return codexMachineRequirementsLayout{
		managedDirKey: "managed_dir",
		managedDir:    SandboxHookDir,
		samePath: func(left, right string) bool {
			return strings.TrimSpace(left) != "" && path.Clean(left) == path.Clean(right)
		},
		groups: groups,
		handler: func(group codexHookGroup) map[string]interface{} {
			return map[string]interface{}{
				"type":    "command",
				"command": codexHookCommandForPlatform("linux", group.eventType, contractID, hookScript),
				"timeout": group.timeout,
			}
		},
	}, nil
}

func renderCodexSandboxRequirements(rt resolvedSandboxTarget) ([]byte, error) {
	layout, err := codexSandboxRequirementsLayout(rt)
	if err != nil {
		return nil, err
	}
	cfg := map[string]interface{}{}
	if err := layout.reconcile(cfg); err != nil {
		return nil, fmt.Errorf("render Codex sandbox requirements: %w", err)
	}
	body, err := toml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal Codex sandbox requirements: %w", err)
	}
	header := "# DefenseClaw managed Codex requirements (OpenShell sandbox image, root-owned).\n" +
		"# Hook contract " + rt.contract.ContractID + "; regenerate with the image, never edit.\n"
	return append([]byte(header), body...), nil
}

func renderCodexSandboxManagedConfig(rt resolvedSandboxTarget, environment string) ([]byte, error) {
	// Reuse the connector's native OTLP spec with the ingress as endpoint and
	// no Authorization header: the placeholder is revision-scoped, so the
	// launcher adds it per session in OTEL_EXPORTER_OTLP_{LOGS,TRACES,
	// METRICS}_HEADERS, which Codex's exporters merge over the headers set
	// here (never on a command line every process could read).
	spec := (&CodexConnector{}).HookProfile(SetupOpts{APIAddr: rt.ingressAddr}).NativeOTLP
	if spec == nil {
		return nil, fmt.Errorf("codex: nil NativeOTLPSpec")
	}
	sandboxSpec := *spec
	headers := make(map[string]string, len(spec.Headers))
	for key, value := range spec.Headers {
		if strings.EqualFold(key, "authorization") {
			continue
		}
		headers[key] = value
	}
	sandboxSpec.Headers = headers
	otel, err := sandboxSpec.TOMLBlock()
	if err != nil {
		return nil, fmt.Errorf("render Codex sandbox OTLP block: %w", err)
	}
	otel["environment"] = environment

	features := make(map[string]interface{}, len(codexSandboxDisabledFeatures))
	for _, feature := range codexSandboxDisabledFeatures {
		features[feature] = false
	}
	pins := codexSandboxShellPins()
	pinnedShellEnv := make(map[string]interface{}, len(pins))
	for _, key := range pins {
		pinnedShellEnv[key] = ""
	}
	cfg := map[string]interface{}{
		"check_for_update_on_startup": false,
		"notify":                      []interface{}{path.Join(SandboxHookDir, codexSandboxNotifyScript)},
		"analytics":                   map[string]interface{}{"enabled": false},
		"features":                    features,
		"otel":                        otel,
		"shell_environment_policy":    map[string]interface{}{"set": pinnedShellEnv},
	}
	body, err := toml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal Codex sandbox managed config: %w", err)
	}
	header := "# DefenseClaw managed Codex config (OpenShell sandbox image, root-owned).\n" +
		"# Highest-precedence layer for the keys it sets; the OTLP Authorization header\n" +
		"# is added per session by the DefenseClaw launcher.\n"
	return append([]byte(header), body...), nil
}

// verifyCodexSandboxPolicy lays both documents out under a scratch root,
// reads requirements.toml back through the bounded system-requirements reader
// and runs the machine-layout and hook-matrix verifiers the host installers
// use, then checks the managed config keys this image depends on.
func verifyCodexSandboxPolicy(requirements, managedConfig []byte, rt resolvedSandboxTarget, environment string) error {
	root, err := os.MkdirTemp("", "defenseclaw-codex-managed-")
	if err != nil {
		return fmt.Errorf("stage Codex sandbox policy: %w", err)
	}
	defer os.RemoveAll(root)
	requirementsPath := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(CodexSandboxRequirementsPath, "/")))
	if err := os.MkdirAll(filepath.Dir(requirementsPath), 0o700); err != nil {
		return fmt.Errorf("stage Codex sandbox policy: %w", err)
	}
	if err := os.WriteFile(requirementsPath, requirements, 0o600); err != nil {
		return fmt.Errorf("stage Codex sandbox policy: %w", err)
	}
	raw, exists, err := readLegacyCodexSystemRequirements(requirementsPath)
	if err != nil || !exists {
		return fmt.Errorf("verify Codex sandbox requirements: read back failed (exists=%t): %v", exists, err)
	}
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return fmt.Errorf("verify Codex sandbox requirements: %w", err)
	}
	layout, err := codexSandboxRequirementsLayout(rt)
	if err != nil {
		return err
	}
	if err := layout.verify(cfg); err != nil {
		return fmt.Errorf("verify Codex sandbox requirements: %w", err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	matrix := make(map[string]interface{}, len(hooks))
	for key, value := range hooks {
		if key == layout.managedDirKey {
			continue
		}
		matrix[key] = value
	}
	if err := verifyManagedCodexHookMatrix(matrix, CodexSandboxRequirementsPath, SandboxHookDir, rt.opts); err != nil {
		return fmt.Errorf("verify Codex sandbox hook matrix: %w", err)
	}

	managed := map[string]interface{}{}
	if err := parseCodexTOML(managedConfig, &managed); err != nil {
		return fmt.Errorf("verify Codex sandbox managed config: %w", err)
	}
	if managed["check_for_update_on_startup"] != false {
		return fmt.Errorf("verify Codex sandbox managed config: update check is not disabled")
	}
	wantNotify := []interface{}{path.Join(SandboxHookDir, codexSandboxNotifyScript)}
	if !reflect.DeepEqual(managed["notify"], wantNotify) {
		return fmt.Errorf("verify Codex sandbox managed config: notify = %#v", managed["notify"])
	}
	if analytics, _ := managed["analytics"].(map[string]interface{}); analytics["enabled"] != false {
		return fmt.Errorf("verify Codex sandbox managed config: analytics is not disabled")
	}
	features, _ := managed["features"].(map[string]interface{})
	for _, feature := range codexSandboxDisabledFeatures {
		if features[feature] != false {
			return fmt.Errorf("verify Codex sandbox managed config: features.%s is not disabled", feature)
		}
	}
	shellPolicy, _ := managed["shell_environment_policy"].(map[string]interface{})
	shellSet, _ := shellPolicy["set"].(map[string]interface{})
	for _, key := range codexSandboxShellPins() {
		if got, ok := shellSet[key].(string); !ok || got != "" {
			return fmt.Errorf("verify Codex sandbox managed config: shell_environment_policy.set.%s is not pinned to \"\"", key)
		}
	}
	otel, _ := managed["otel"].(map[string]interface{})
	if otel["environment"] != environment {
		return fmt.Errorf("verify Codex sandbox managed config: otel.environment = %#v", otel["environment"])
	}
	for _, exporter := range codexOtelExporterKeys {
		table, _ := otel[exporter].(map[string]interface{})
		httpExporter, _ := table["otlp-http"].(map[string]interface{})
		endpoint, _ := httpExporter["endpoint"].(string)
		if !strings.HasPrefix(endpoint, "http://"+rt.ingressAddr+"/v1/") {
			return fmt.Errorf("verify Codex sandbox managed config: otel.%s endpoint %q is not the ingress", exporter, endpoint)
		}
		headers, _ := httpExporter["headers"].(map[string]interface{})
		if _, present := headers["authorization"]; present {
			return fmt.Errorf("verify Codex sandbox managed config: otel.%s must not pin an Authorization header", exporter)
		}
	}
	return nil
}

// renderCodexSandboxNotifyBridge renders the notify program Codex runs on
// agent-turn-complete with one JSON argument. Telemetry is best-effort: an
// unreachable ingress or a missing or malformed token exits 0 without
// output.
func renderCodexSandboxNotifyBridge(ingressAddr string) []byte {
	return []byte(`#!/bin/bash -p
# defenseclaw-managed-hook v1
# DefenseClaw Codex notify bridge (OpenShell sandbox images, root-owned).
# Forwards Codex's agent-turn-complete JSON to the DefenseClaw hook ingress
# with the per-sandbox binding token. Best-effort: never blocks or prints.
set -u
PATH=` + SandboxHookPATH + `
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV CURL_HOME
JSON="${1:-}"
TOKEN="${` + SandboxTokenEnv + `:-}"
unset ` + SandboxTokenEnv + `
[ -n "$JSON" ] && [ -n "$TOKEN" ] || exit 0
case "$TOKEN" in *[!A-Za-z0-9:._-]*) exit 0 ;; esac
# The bearer (with token_delivery: env the token itself) reaches curl as
# configuration on a descriptor, never on its command line, which every
# process in the sandbox can read.
printf '%s' "$JSON" | curl -q -s --noproxy '*' -o /dev/null \
  --connect-timeout 2 --max-time 5 \
  -X POST "http://` + ingressAddr + `/api/v1/codex/notify" \
  -H 'Content-Type: application/json' \
  -H 'X-DefenseClaw-Client: codex-notify/1.0' \
  -H 'x-defenseclaw-source: codex-notify' \
  --config /dev/fd/7 \
  --data-binary @- >/dev/null 2>&1 7< <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") || true
exit 0
`)
}
