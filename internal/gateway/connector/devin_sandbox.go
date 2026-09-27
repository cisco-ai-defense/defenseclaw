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

// In-image Devin CLI layout. The reviewed devin-hooks-v1 contract reads hooks
// from the user config.json (or a project .devin/hooks.v1.json); Devin
// 3000.4.25 has no system hook tier, so the registration is user scope
// (tamper tier user). The launcher puts the DefenseClaw hooks back from the
// root-owned template on every start.
const (
	// DevinSandboxConfigPath is the Devin CLI user configuration in the
	// image HOME.
	DevinSandboxConfigPath = SandboxHomeDir + "/.config/devin/config.json"
	// DevinSandboxConfigTemplatePath is the root-owned copy whose hooks the
	// launcher restores into DevinSandboxConfigPath.
	DevinSandboxConfigTemplatePath = SandboxLibDir + "/devin/config.json"
)

// devinSandboxHookTimeoutSeconds bounds one Devin hook run. It covers the
// sandbox transport (two attempts through the OpenShell relay); Devin fails
// open when a hook times out, so the host's 10 seconds would turn a slow
// relay into an allow.
const devinSandboxHookTimeoutSeconds = 30

// devinSandboxHookScript is the in-image Devin hook.
func devinSandboxHookScript() string {
	return path.Join(SandboxHookDir, "devin-hook.sh")
}

// renderDevinSandboxArtifacts renders the Devin CLI overlay: the sandbox hook
// scripts and a user config.json that registers the hook for every event of
// the resolved contract, with its root-owned template.
func renderDevinSandboxArtifacts(rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	hookFiles, err := renderSandboxHookFiles("devin", rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	config, err := renderDevinSandboxConfig(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyDevinSandboxConfig(config, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	files := append(hookFiles,
		SandboxFile{Path: DevinSandboxConfigTemplatePath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: config},
		SandboxFile{Path: DevinSandboxConfigPath, Mode: 0o600, Owner: SandboxOwnerUser, Data: config},
	)
	return finalizeSandboxArtifacts(SandboxArtifacts{
		Connector:    "devin",
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierUser,
		Files:        files,
		Env:          map[string]string{},
		Binaries:     append(sandboxHookRuntimeBinaries(), harnessBinary("devin")),
	})
}

// devinSandboxEvents are the resolved contract's events, each one the
// connector registers on the host.
func devinSandboxEvents(rt resolvedSandboxTarget) ([]string, error) {
	events := append([]string(nil), rt.contract.Events...)
	if len(events) == 0 {
		return nil, fmt.Errorf("devin hook contract %s lists no events", rt.contract.ContractID)
	}
	known := make(map[string]bool, len(devinHookEvents))
	for _, event := range devinHookEvents {
		known[event] = true
	}
	for _, event := range events {
		if !known[event] {
			return nil, fmt.Errorf("devin: unsupported hook event %q in contract %s", event, rt.contract.ContractID)
		}
	}
	return events, nil
}

// devinSandboxHookGroup is the host's matcher group with the in-image hook
// and the sandbox timeout.
func devinSandboxHookGroup() map[string]interface{} {
	return map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": devinSandboxHookScript(),
				"timeout": devinSandboxHookTimeoutSeconds,
			},
		},
	}
}

func renderDevinSandboxConfig(rt resolvedSandboxTarget) ([]byte, error) {
	events, err := devinSandboxEvents(rt)
	if err != nil {
		return nil, err
	}
	hooks := make(map[string]interface{}, len(events))
	for _, event := range events {
		hooks[event] = []interface{}{devinSandboxHookGroup()}
	}
	body, err := json.MarshalIndent(map[string]interface{}{"hooks": hooks}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Devin sandbox config: %w", err)
	}
	return append(body, '\n'), nil
}

// verifyDevinSandboxConfig reads the config back and requires exactly one
// DefenseClaw hook group per contract event, and nothing else.
func verifyDevinSandboxConfig(body []byte, rt resolvedSandboxTarget) error {
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string      `json:"type"`
				Command string      `json:"command"`
				Timeout json.Number `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("verify Devin sandbox config: %w", err)
	}
	events, err := devinSandboxEvents(rt)
	if err != nil {
		return err
	}
	if len(doc.Hooks) != len(events) {
		return fmt.Errorf("verify Devin sandbox config: %d hook events, want the %d of %s", len(doc.Hooks), len(events), rt.contract.ContractID)
	}
	for _, event := range events {
		groups := doc.Hooks[event]
		if len(groups) != 1 || groups[0].Matcher != "" || len(groups[0].Hooks) != 1 {
			return fmt.Errorf("verify Devin sandbox config: %s does not carry exactly one DefenseClaw hook group", event)
		}
		hook := groups[0].Hooks[0]
		if hook.Type != "command" || hook.Command != devinSandboxHookScript() || hook.Timeout.String() != fmt.Sprint(devinSandboxHookTimeoutSeconds) {
			return fmt.Errorf("verify Devin sandbox config: %s hook %+v is not the DefenseClaw hook", event, hook)
		}
	}
	return nil
}
