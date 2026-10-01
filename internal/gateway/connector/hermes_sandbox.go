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
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// In-image Hermes managed scope. Hermes (>= 0.19) reads an administrator
// layer from /etc/hermes/config.yaml and deep-merges it over the user's
// ~/.hermes/config.yaml leaf by leaf, managed values winning. A hook list is
// one leaf, so a user or project setting can add hooks for other events but
// cannot drop or replace DefenseClaw's; hooks_auto_accept pinned true
// registers them without the first-use consent prompt; plugins.enabled
// pinned empty keeps the general in-process Python plugins (which could
// unregister hooks) from loading; terminal.backend pinned local keeps
// approved commands inside the sandbox rather than on a remote backend;
// agent.disabled_toolsets drops the code_execution toolset, whose
// execute_code tool runs model-written Python that DefenseClaw's command
// rules cannot judge (commands go through the terminal tool instead); and
// security.tirith_enabled pinned false keeps Hermes from downloading its
// Tirith scanner into the workload-writable ~/.hermes/bin at every start and
// running it on every command (DefenseClaw judges the commands);
// security.allow_lazy_installs pinned false stops runtime pip installs of
// optional backends, which download from PyPI outside the pin (and fail in
// the root-owned install anyway); and model_catalog.enabled pinned false
// stops the start-up fetch of Hermes' curated OpenRouter and Nous Portal
// model lists (hermes-agent.nousresearch.com, which redirects to
// nousresearch.github.io; Hermes falls back to the lists it ships), which
// no DefenseClaw provider uses.
//
// Hermes also applies /etc/hermes/.env last, over the user's ~/.hermes/.env
// and the process environment, per variable. The image pins there the
// variables that would switch the hooks off or re-enable Tirith; the one
// that moves the managed scope itself (HERMES_MANAGED_DIR) cannot be pinned
// from inside it, so the launcher refuses a user .env that names it. The
// harness's home stays workload-writable (plugins, .env, profiles), so the
// connector is user tier: the launcher's checks, not file ownership, keep
// the hooks in place.
//
// The layer also defines one named OpenAI-compatible provider, selected with
// `--provider defenseclaw`, whose endpoint and key come from the process
// environment at start (Hermes expands ${VAR} in the managed layer against
// the process environment only). DefenseClaw's credential profiles set the
// endpoint per sandbox and the launcher copies the profile's credential
// placeholder into the key variable; with neither set the provider is inert
// and Hermes resolves providers as usual.
const (
	HermesSandboxManagedDir        = "/etc/hermes"
	HermesSandboxManagedConfigPath = HermesSandboxManagedDir + "/config.yaml"
	// HermesSandboxManagedEnvPath is the managed environment layer.
	HermesSandboxManagedEnvPath    = HermesSandboxManagedDir + "/.env"
	hermesSandboxHookTimeoutSecond = 30

	// HermesSandboxProviderName is the managed provider's name.
	HermesSandboxProviderName = "defenseclaw"
	// HermesSandboxProviderBaseURLEnv carries its OpenAI-compatible base URL.
	HermesSandboxProviderBaseURLEnv = "HERMES_DEFENSECLAW_BASE_URL"
	// HermesSandboxProviderKeyEnv carries its API key (a credential
	// placeholder).
	HermesSandboxProviderKeyEnv = "HERMES_DEFENSECLAW_API_KEY"
)

// HermesSandboxUserConfigPath is the user configuration the image pre-seeds.
// Hermes refuses a non-interactive first run until some provider is
// configured; "auto" (its own default resolution) marks setup as done
// without choosing a provider. The file belongs to the workload.
const HermesSandboxUserConfigPath = SandboxHomeDir + "/.hermes/config.yaml"

const hermesSandboxUserPreseed = "# DefenseClaw sandbox first-run defaults. Yours to edit: DefenseClaw's hooks\n" +
	"# live in the managed layer (" + HermesSandboxManagedConfigPath + "), which wins over this file.\n" +
	"model:\n" +
	"  provider: auto\n"

// hermesSandboxProvider is the managed provider entry.
func hermesSandboxProvider() map[string]interface{} {
	return map[string]interface{}{
		"name":     "DefenseClaw sandbox provider",
		"base_url": "${" + HermesSandboxProviderBaseURLEnv + "}",
		"key_env":  HermesSandboxProviderKeyEnv,
		"api_mode": "chat_completions",
	}
}

// hermesSandboxManagedEnv are the variables the managed .env pins: safe
// mode and project plugins off (a user .env or shell export of either would
// otherwise switch the hooks off or load a repository's plugins), hook
// consent given, Tirith off (TIRITH_ENABLED overrides the config key) and
// runtime installs off.
var hermesSandboxManagedEnv = [][2]string{
	{"HERMES_SAFE_MODE", "0"},
	{"HERMES_ENABLE_PROJECT_PLUGINS", "0"},
	{"HERMES_ACCEPT_HOOKS", "1"},
	{"TIRITH_ENABLED", "0"},
	{"HERMES_DISABLE_LAZY_INSTALLS", "1"},
}

func renderHermesSandboxManagedEnv() []byte {
	var b strings.Builder
	b.WriteString("# DefenseClaw managed Hermes environment (OpenShell sandbox image, root-owned).\n" +
		"# Hermes applies it last, over ~/.hermes/.env and the process environment.\n")
	for _, kv := range hermesSandboxManagedEnv {
		b.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	return []byte(b.String())
}

func init() {
	registerHookOnlySandboxRenderer("hermes", renderHermesSandboxArtifacts)
}

func renderHermesSandboxArtifacts(c *hookOnlyConnector, rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	hookFiles, err := renderSandboxHookFiles(c.name, rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	managed, err := renderHermesSandboxManagedConfig(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyHermesSandboxManagedConfig(managed, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	files := append(hookFiles,
		SandboxFile{Path: HermesSandboxManagedConfigPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: managed},
		SandboxFile{Path: HermesSandboxManagedEnvPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: renderHermesSandboxManagedEnv()},
		SandboxFile{Path: HermesSandboxUserConfigPath, Mode: 0o600, Owner: SandboxOwnerUser, Data: []byte(hermesSandboxUserPreseed)},
	)
	return SandboxArtifacts{
		Connector:    c.name,
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierUser,
		Files:        files,
		Env:          map[string]string{},
		Binaries:     append(sandboxHookRuntimeBinaries(), SandboxBinary{Name: "hermes", Role: SandboxBinaryHarness}),
	}, nil
}

// hermesSandboxHookCommand is the registered command. Hermes splits it with
// shlex and runs it without a shell, so it must stay one plain path.
func hermesSandboxHookCommand() string {
	return path.Join(SandboxHookDir, "hermes-hook.sh")
}

// hermesSandboxHookEntries maps every event of the resolved contract to the
// one DefenseClaw handler, with the tool matcher Setup uses on the host.
func hermesSandboxHookEntries(rt resolvedSandboxTarget) (map[string]interface{}, error) {
	matchers := make(map[string]string, len(hermesRequiredHooks))
	for _, spec := range hermesRequiredHooks {
		matchers[spec.event] = spec.matcher
	}
	hooks := make(map[string]interface{}, len(rt.contract.Events))
	for _, event := range rt.contract.Events {
		matcher, known := matchers[event]
		if !known {
			return nil, fmt.Errorf("hermes contract %s event %s has no reviewed registration", rt.contract.ContractID, event)
		}
		entry := map[string]interface{}{
			"command": hermesSandboxHookCommand(),
			"timeout": hermesSandboxHookTimeoutSecond,
		}
		if matcher != "" {
			entry["matcher"] = matcher
		}
		hooks[event] = []interface{}{entry}
	}
	return hooks, nil
}

func renderHermesSandboxManagedConfig(rt resolvedSandboxTarget) ([]byte, error) {
	hooks, err := hermesSandboxHookEntries(rt)
	if err != nil {
		return nil, err
	}
	cfg := map[string]interface{}{
		"hooks":             hooks,
		"hooks_auto_accept": true,
		"plugins":           map[string]interface{}{"enabled": []interface{}{}},
		"providers":         map[string]interface{}{HermesSandboxProviderName: hermesSandboxProvider()},
		"terminal":          map[string]interface{}{"backend": "local"},
		"agent":             map[string]interface{}{"disabled_toolsets": []interface{}{"code_execution"}},
		"security":          map[string]interface{}{"tirith_enabled": false, "allow_lazy_installs": false},
		"model_catalog":     map[string]interface{}{"enabled": false},
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal Hermes sandbox managed config: %w", err)
	}
	header := "# DefenseClaw managed Hermes configuration (OpenShell sandbox image, root-owned).\n" +
		"# Hermes merges this layer over ~/.hermes/config.yaml and it wins per key.\n" +
		"# Hook contract " + rt.contract.ContractID + "; regenerate with the image, never edit.\n"
	return append([]byte(header), body...), nil
}

// verifyHermesSandboxManagedConfig reads the managed layer back and checks
// every key the image depends on, so a rendering change can never ship a
// managed layer that drops a hook or a pin.
func verifyHermesSandboxManagedConfig(data []byte, rt resolvedSandboxTarget) error {
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("verify Hermes sandbox managed config: %w", err)
	}
	if cfg["hooks_auto_accept"] != true {
		return fmt.Errorf("verify Hermes sandbox managed config: hooks_auto_accept is not pinned true")
	}
	plugins, _ := cfg["plugins"].(map[string]interface{})
	if enabled, ok := plugins["enabled"].([]interface{}); !ok || len(enabled) != 0 {
		return fmt.Errorf("verify Hermes sandbox managed config: plugins.enabled is not pinned empty")
	}
	terminal, _ := cfg["terminal"].(map[string]interface{})
	if terminal["backend"] != "local" {
		return fmt.Errorf("verify Hermes sandbox managed config: terminal.backend is not pinned local")
	}
	agent, _ := cfg["agent"].(map[string]interface{})
	if disabled, _ := agent["disabled_toolsets"].([]interface{}); !reflect.DeepEqual(disabled, []interface{}{"code_execution"}) {
		return fmt.Errorf("verify Hermes sandbox managed config: agent.disabled_toolsets is not pinned to code_execution")
	}
	security, _ := cfg["security"].(map[string]interface{})
	if security["tirith_enabled"] != false || security["allow_lazy_installs"] != false {
		return fmt.Errorf("verify Hermes sandbox managed config: security.tirith_enabled and allow_lazy_installs are not pinned false")
	}
	catalog, _ := cfg["model_catalog"].(map[string]interface{})
	if catalog["enabled"] != false {
		return fmt.Errorf("verify Hermes sandbox managed config: model_catalog.enabled is not pinned false")
	}
	providers, _ := cfg["providers"].(map[string]interface{})
	if !reflect.DeepEqual(providers, map[string]interface{}{HermesSandboxProviderName: hermesSandboxProvider()}) {
		return fmt.Errorf("verify Hermes sandbox managed config: providers = %v, want only the %s provider", providers, HermesSandboxProviderName)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	want, err := hermesSandboxHookEntries(rt)
	if err != nil {
		return err
	}
	if len(hooks) != len(want) {
		return fmt.Errorf("verify Hermes sandbox managed config: %d hook events registered, contract %s has %d", len(hooks), rt.contract.ContractID, len(want))
	}
	events := make([]string, 0, len(want))
	for event := range want {
		events = append(events, event)
	}
	sort.Strings(events)
	for _, event := range events {
		got, _ := hooks[event].([]interface{})
		if len(got) != 1 {
			return fmt.Errorf("verify Hermes sandbox managed config: event %s has %d handlers, want 1", event, len(got))
		}
		entry, _ := got[0].(map[string]interface{})
		wantEntry := want[event].([]interface{})[0].(map[string]interface{})
		if !reflect.DeepEqual(entry, wantEntry) {
			return fmt.Errorf("verify Hermes sandbox managed config: event %s handler = %v, want %v", event, entry, wantEntry)
		}
	}
	return nil
}
