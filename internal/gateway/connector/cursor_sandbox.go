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

// CursorSandboxHooksPath is Cursor's enterprise hooks file on Linux. The
// pinned Agent CLI (2026.07.23-e383d2b) reads it before the team, user and
// project hooks.json files, runs every matching hook and lets the enterprise
// response win a conflict, so a user or project hook cannot answer allow
// over a DefenseClaw deny (tamper tier managed).
const CursorSandboxHooksPath = "/etc/cursor/hooks.json"

// cursorSandboxHookScript is the in-image Cursor hook.
func cursorSandboxHookScript() string {
	return path.Join(SandboxHookDir, "cursor-hook.sh")
}

// renderCursorSandboxArtifacts renders the Cursor Agent overlay: the sandbox
// hook scripts and the root-owned enterprise hooks.json that registers the
// hook for every event of the resolved contract with failClosed, so a hook
// that fails, times out or prints no valid object denies the action.
func renderCursorSandboxArtifacts(rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	hookFiles, err := renderSandboxHookFiles("cursor", rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	hooks, err := renderCursorSandboxHooks(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyCursorSandboxHooks(hooks, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	files := append(hookFiles,
		SandboxFile{Path: CursorSandboxHooksPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: hooks},
	)
	return finalizeSandboxArtifacts(SandboxArtifacts{
		Connector:    "cursor",
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierManaged,
		Files:        files,
		Env:          map[string]string{},
		Binaries:     append(sandboxHookRuntimeBinaries(), harnessBinary("cursor-agent")),
	})
}

// cursorSandboxEvents are the resolved contract's events; the host setup
// registers the same roster.
func cursorSandboxEvents(rt resolvedSandboxTarget) ([]string, error) {
	events := append([]string(nil), rt.contract.Events...)
	if len(events) == 0 {
		return nil, fmt.Errorf("cursor hook contract %s lists no events", rt.contract.ContractID)
	}
	known := make(map[string]bool, len(cursorHookEvents))
	for _, event := range cursorHookEvents {
		known[event] = true
	}
	for _, event := range events {
		if !known[event] {
			return nil, fmt.Errorf("cursor: unsupported hook event %q in contract %s", event, rt.contract.ContractID)
		}
	}
	return events, nil
}

// cursorSandboxHookEntry is the entry the host setup writes in action mode:
// the quoted hook path, Cursor's 30-second envelope and failClosed.
func cursorSandboxHookEntry() map[string]interface{} {
	return map[string]interface{}{
		"type":       "command",
		"command":    shellWord(cursorSandboxHookScript()),
		"timeout":    windowsCursorEnterpriseHookTimeoutSeconds,
		"failClosed": true,
	}
}

func renderCursorSandboxHooks(rt resolvedSandboxTarget) ([]byte, error) {
	events, err := cursorSandboxEvents(rt)
	if err != nil {
		return nil, err
	}
	hooks := make(map[string]interface{}, len(events))
	for _, event := range events {
		hooks[event] = []interface{}{cursorSandboxHookEntry()}
	}
	body, err := json.MarshalIndent(map[string]interface{}{"version": 1, "hooks": hooks}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Cursor sandbox hooks: %w", err)
	}
	return append(body, '\n'), nil
}

// verifyCursorSandboxHooks reads the document back through the verifier the
// host setup gates on (one current entry per event, the exact type, timeout
// and failClosed), and additionally refuses any event the contract does not
// list.
func verifyCursorSandboxHooks(body []byte, rt resolvedSandboxTarget) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var cfg map[string]interface{}
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("verify Cursor sandbox hooks: %w", err)
	}
	if len(cfg) != 2 {
		return fmt.Errorf("verify Cursor sandbox hooks: unexpected top-level keys")
	}
	if version, ok := cfg["version"].(json.Number); !ok || version.String() != "1" {
		return fmt.Errorf("verify Cursor sandbox hooks: version %v", cfg["version"])
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("verify Cursor sandbox hooks: no hooks object")
	}
	events, err := cursorSandboxEvents(rt)
	if err != nil {
		return err
	}
	if len(hooks) != len(events) {
		return fmt.Errorf("verify Cursor sandbox hooks: %d events, want the %d of %s", len(hooks), len(events), rt.contract.ContractID)
	}
	command := shellWord(cursorSandboxHookScript())
	if !cursorHookContractPresent(hooks, command, newCursorHookCommandMatcher([]string{cursorSandboxHookScript()}), true) {
		return fmt.Errorf("verify Cursor sandbox hooks: the hook contract %s is incomplete", rt.contract.ContractID)
	}
	return nil
}
