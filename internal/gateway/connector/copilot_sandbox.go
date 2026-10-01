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
	"reflect"
	"sort"
)

// In-image GitHub Copilot CLI system policy (measured on Copilot CLI 1.0.88,
// Linux). Copilot loads hook documents from /etc/github-copilot/policy.d
// whatever COPILOT_HOME or the user's settings say, and runs them even when
// user settings set disableAllHooks. The device managed-settings file turns
// allowManagedHooksOnly on, which drops every user and repository hook, so a
// hook the agent adds to ~/.copilot/hooks or .github/hooks never runs.
const (
	CopilotSandboxPolicyPath          = "/etc/github-copilot/policy.d/50-defenseclaw.json"
	CopilotSandboxManagedSettingsPath = "/etc/github-copilot/managed-settings.json"
	// copilotSandboxConfigPath pre-seeds the first-run state in the image HOME.
	copilotSandboxConfigPath = SandboxHomeDir + "/.copilot/config.json"
)

// copilotSandboxStartupEnv must be real process environment (OpenShell does
// not propagate image ENV). With auto-update off, Copilot also ignores any
// newer package the workload could plant in a user-writable package cache
// and runs the version its binary bundles.
var copilotSandboxStartupEnv = map[string]string{
	"COPILOT_AUTO_UPDATE": "false",
}

func init() {
	registerHookOnlySandboxRenderer("copilot", renderCopilotSandboxArtifacts)
}

// renderCopilotSandboxArtifacts renders the Copilot overlay: the sandbox hook
// scripts, the root-owned policy.d hook document for every event of the
// resolved contract, the managed settings that admit only managed hooks, and
// a pre-seeded ~/.copilot/config.json that trusts /work and HOME.
func renderCopilotSandboxArtifacts(c *hookOnlyConnector, rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	hookFiles, err := renderSandboxHookFiles("copilot", rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	policy, err := renderCopilotSandboxPolicy(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyCopilotSandboxPolicy(policy, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	managed, err := json.MarshalIndent(map[string]interface{}{"allowManagedHooksOnly": true}, "", "  ")
	if err != nil {
		return SandboxArtifacts{}, fmt.Errorf("marshal Copilot sandbox managed settings: %w", err)
	}
	preseed, err := renderCopilotSandboxPreseed()
	if err != nil {
		return SandboxArtifacts{}, err
	}
	files := append(hookFiles,
		SandboxFile{Path: CopilotSandboxPolicyPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: policy},
		SandboxFile{Path: CopilotSandboxManagedSettingsPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: append(managed, '\n')},
		SandboxFile{Path: copilotSandboxConfigPath, Mode: 0o600, Owner: SandboxOwnerUser, Data: preseed},
	)
	env := make(map[string]string, len(copilotSandboxStartupEnv))
	for key, value := range copilotSandboxStartupEnv {
		env[key] = value
	}
	return SandboxArtifacts{
		Connector:    "copilot",
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierManaged,
		Files:        files,
		Env:          env,
		Binaries:     append(sandboxHookRuntimeBinaries(), harnessBinary("copilot")),
	}, nil
}

// copilotSandboxHookScript is the in-image Copilot hook.
func copilotSandboxHookScript() string {
	return path.Join(SandboxHookDir, "copilot-hook.sh")
}

// copilotSandboxEvents are the resolved contract's events, each validated.
func copilotSandboxEvents(rt resolvedSandboxTarget) ([]string, error) {
	events := append([]string(nil), rt.contract.Events...)
	if len(events) == 0 {
		return nil, fmt.Errorf("copilot hook contract %s lists no events", rt.contract.ContractID)
	}
	for _, event := range events {
		if !ValidCopilotHookEvent(event) {
			return nil, fmt.Errorf("copilot: unsupported hook event %q in contract %s", event, rt.contract.ContractID)
		}
	}
	return events, nil
}

// renderCopilotSandboxPolicy renders the policy.d document: the same flat
// per-event registration setup writes on the host, pointing at the in-image
// hook.
func renderCopilotSandboxPolicy(rt resolvedSandboxTarget) ([]byte, error) {
	events, err := copilotSandboxEvents(rt)
	if err != nil {
		return nil, err
	}
	hooks := make(map[string]interface{}, len(events))
	for _, event := range events {
		hooks[event] = []interface{}{copilotHookRegistration("linux", event, copilotSandboxHookScript())}
	}
	body, err := json.MarshalIndent(map[string]interface{}{"version": 1, "hooks": hooks}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Copilot sandbox hook policy: %w", err)
	}
	return append(body, '\n'), nil
}

// verifyCopilotSandboxPolicy reads the policy document back and requires
// exactly one DefenseClaw registration for every contract event, and nothing
// else.
func verifyCopilotSandboxPolicy(body []byte, rt resolvedSandboxTarget) error {
	var doc struct {
		Version int                          `json:"version"`
		Hooks   map[string][]json.RawMessage `json:"hooks"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("verify Copilot sandbox hook policy: %w", err)
	}
	if doc.Version != 1 {
		return fmt.Errorf("verify Copilot sandbox hook policy: version %d", doc.Version)
	}
	events, err := copilotSandboxEvents(rt)
	if err != nil {
		return err
	}
	if len(doc.Hooks) != len(events) {
		got := make([]string, 0, len(doc.Hooks))
		for event := range doc.Hooks {
			got = append(got, event)
		}
		sort.Strings(got)
		return fmt.Errorf("verify Copilot sandbox hook policy: events %v, want the %d of %s", got, len(events), rt.contract.ContractID)
	}
	for _, event := range events {
		entries := doc.Hooks[event]
		if len(entries) != 1 {
			return fmt.Errorf("verify Copilot sandbox hook policy: %s has %d handlers, want 1", event, len(entries))
		}
		var got map[string]interface{}
		if err := json.Unmarshal(entries[0], &got); err != nil {
			return fmt.Errorf("verify Copilot sandbox hook policy: %s: %w", event, err)
		}
		want := map[string]interface{}{}
		raw, _ := json.Marshal(copilotHookRegistration("linux", event, copilotSandboxHookScript()))
		_ = json.Unmarshal(raw, &want)
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("verify Copilot sandbox hook policy: %s handler %v, want %v", event, got, want)
		}
	}
	return nil
}

// renderCopilotSandboxPreseed skips Copilot's first-run prompts: the banner,
// the startup tips and the folder-trust dialog for /work (every mounted
// project lives below it) and HOME. The launcher adds the exact working
// directory on every start as well.
func renderCopilotSandboxPreseed() ([]byte, error) {
	body, err := json.MarshalIndent(map[string]interface{}{
		"banner":            "never",
		"showTipsOnStartup": false,
		"autoUpdate":        false,
		"trustedFolders":    []string{"/work", SandboxHomeDir},
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Copilot sandbox preseed: %w", err)
	}
	return append(body, '\n'), nil
}
