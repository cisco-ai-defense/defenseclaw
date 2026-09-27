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
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// In-image Antigravity (agy) hook configuration. agy reads global hooks from
// ~/.gemini/config/hooks.json and adds workspace hooks from
// <workspace>/.agents/hooks.json; no system or managed tier is documented or
// present in the reviewed 1.2.x binary. The reviewed file is therefore user
// tier: seeded in the sandbox HOME and restored from the root-owned canonical
// copy by the launcher before every start, and the launcher refuses a
// workspace hooks file that reuses one of DefenseClaw's hook keys.
const (
	AntigravitySandboxHooksPath = SandboxHomeDir + "/.gemini/config/hooks.json"
	antigravitySandboxHooksName = "hooks.json"
	// AntigravitySandboxHookKeyPrefix names every DefenseClaw-owned
	// top-level key in hooks.json.
	AntigravitySandboxHookKeyPrefix = "defenseclaw-antigravity-"
	antigravitySandboxHookTimeout   = 30
)

// AntigravitySandboxCanonicalHooksPath is the root-owned reference copy.
var AntigravitySandboxCanonicalHooksPath = path.Join(SandboxCanonicalDir("antigravity"), antigravitySandboxHooksName)

func init() {
	registerHookOnlySandboxRenderer("antigravity", renderAntigravitySandboxArtifacts)
}

func renderAntigravitySandboxArtifacts(c *hookOnlyConnector, rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	hookFiles, err := renderSandboxHookFiles(c.name, rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	hooks, err := renderAntigravitySandboxHooks(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyAntigravitySandboxHooks(hooks, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	files := append(hookFiles, userTierHookFiles(c.name, antigravitySandboxHooksName, AntigravitySandboxHooksPath, hooks)...)
	return SandboxArtifacts{
		Connector:    c.name,
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierUser,
		Files:        files,
		Env:          map[string]string{},
		Binaries:     append(sandboxHookRuntimeBinaries(), SandboxBinary{Name: "agy", Role: SandboxBinaryHarness}),
	}, nil
}

// antigravitySandboxHookDocument mirrors patchAntigravityHooks: one
// DefenseClaw-owned key per contract event, matcher groups for the tool
// events and direct handler lists for the rest, each handler bound to its
// event through argv.
func antigravitySandboxHookDocument(rt resolvedSandboxTarget) (map[string]interface{}, error) {
	script := path.Join(SandboxHookDir, "antigravity-hook.sh")
	doc := make(map[string]interface{}, len(rt.contract.Events))
	for _, event := range rt.contract.Events {
		if !validAntigravitySandboxEvent(event) {
			return nil, fmt.Errorf("antigravity contract %s event %s has no reviewed registration", rt.contract.ContractID, event)
		}
		handler := map[string]interface{}{
			"type":    "command",
			"command": antigravityHookInvocationCommandForEvent("linux", event, script),
			"timeout": antigravitySandboxHookTimeout,
		}
		var handlers []interface{}
		if event == "PreToolUse" || event == "PostToolUse" {
			handlers = []interface{}{map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler}}}
		} else {
			handlers = []interface{}{handler}
		}
		doc[AntigravitySandboxHookKeyPrefix+strings.ToLower(event)] = map[string]interface{}{event: handlers}
	}
	return doc, nil
}

func validAntigravitySandboxEvent(event string) bool {
	for _, known := range antigravityLifecycleEvents {
		if event == known {
			return true
		}
	}
	return false
}

func renderAntigravitySandboxHooks(rt resolvedSandboxTarget) ([]byte, error) {
	doc, err := antigravitySandboxHookDocument(rt)
	if err != nil {
		return nil, err
	}
	body, err := marshalSandboxJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal Antigravity sandbox hooks: %w", err)
	}
	return body, nil
}

// verifyAntigravitySandboxHooks reads the rendered file back: every contract
// event must be registered under its DefenseClaw key with exactly one
// handler that runs the sandbox hook for that event, and nothing else.
func verifyAntigravitySandboxHooks(data []byte, rt resolvedSandboxTarget) error {
	var doc map[string]map[string][]map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("verify Antigravity sandbox hooks: %w", err)
	}
	if len(doc) != len(rt.contract.Events) {
		return fmt.Errorf("verify Antigravity sandbox hooks: %d keys, contract %s has %d events", len(doc), rt.contract.ContractID, len(rt.contract.Events))
	}
	script := path.Join(SandboxHookDir, "antigravity-hook.sh")
	for _, event := range rt.contract.Events {
		entry, ok := doc[AntigravitySandboxHookKeyPrefix+strings.ToLower(event)]
		if !ok || len(entry) != 1 || len(entry[event]) != 1 {
			return fmt.Errorf("verify Antigravity sandbox hooks: event %s is not registered once", event)
		}
		handler := entry[event][0]
		if event == "PreToolUse" || event == "PostToolUse" {
			if handler["matcher"] != "*" {
				return fmt.Errorf("verify Antigravity sandbox hooks: %s matcher = %v", event, handler["matcher"])
			}
			nested, _ := handler["hooks"].([]interface{})
			if len(nested) != 1 {
				return fmt.Errorf("verify Antigravity sandbox hooks: %s has %d handlers", event, len(nested))
			}
			handler, _ = nested[0].(map[string]interface{})
		}
		if handler["type"] != "command" || handler["command"] != script+" "+event {
			return fmt.Errorf("verify Antigravity sandbox hooks: %s handler = %v", event, handler)
		}
	}
	return nil
}
