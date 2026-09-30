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
	"reflect"
)

// In-image OpenHands hook configuration. OpenHands CLI (>= 1.12) has no
// system or managed hook tier: it loads the first of
// <workdir>/.openhands/hooks.json and ~/.openhands/hooks.json that exists,
// once per conversation. The reviewed file is therefore user tier: seeded in
// the sandbox HOME, restored from the root-owned canonical copy by the
// launcher before every start, and the launcher refuses a working directory
// whose own .openhands/hooks.json would replace it.
const (
	OpenHandsSandboxHooksPath    = SandboxHomeDir + "/.openhands/hooks.json"
	openHandsSandboxHooksName    = "hooks.json"
	openHandsSandboxHookTimeout  = 60
	openHandsSandboxHookFileName = "openhands-hook.sh"
)

// OpenHandsSandboxCanonicalHooksPath is the root-owned reference copy.
var OpenHandsSandboxCanonicalHooksPath = path.Join(SandboxCanonicalDir("openhands"), openHandsSandboxHooksName)

// openHandsSandboxStartupEnv must be real process environment (OpenShell
// does not propagate image ENV).
var openHandsSandboxStartupEnv = map[string]string{
	"OPENHANDS_SUPPRESS_BANNER": "1",
}

func init() {
	registerHookOnlySandboxRenderer("openhands", renderOpenHandsSandboxArtifacts)
}

func renderOpenHandsSandboxArtifacts(c *hookOnlyConnector, rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	hookFiles, err := renderSandboxHookFiles(c.name, rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	hooks, err := renderOpenHandsSandboxHooks(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyOpenHandsSandboxHooks(hooks, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	env := make(map[string]string, len(openHandsSandboxStartupEnv))
	for key, value := range openHandsSandboxStartupEnv {
		env[key] = value
	}
	files := append(hookFiles, userTierHookFiles(c.name, openHandsSandboxHooksName, OpenHandsSandboxHooksPath, hooks)...)
	return SandboxArtifacts{
		Connector:    c.name,
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierUser,
		Files:        files,
		Env:          env,
		Binaries:     append(sandboxHookRuntimeBinaries(), SandboxBinary{Name: "openhands", Role: SandboxBinaryHarness}),
	}, nil
}

// openHandsSandboxHookGroups registers the one DefenseClaw handler for every
// event of the resolved contract, in the matcher-group shape Setup writes on
// the host. OpenHands runs hook commands through a shell; the command is one
// plain root-owned path.
func openHandsSandboxHookGroups(rt resolvedSandboxTarget) map[string]interface{} {
	groups := make(map[string]interface{}, len(rt.contract.Events))
	for _, event := range rt.contract.Events {
		groups[event] = []interface{}{map[string]interface{}{
			"matcher": "*",
			"hooks": []interface{}{map[string]interface{}{
				"type":    "command",
				"command": path.Join(SandboxHookDir, openHandsSandboxHookFileName),
				"timeout": openHandsSandboxHookTimeout,
			}},
		}}
	}
	return groups
}

func renderOpenHandsSandboxHooks(rt resolvedSandboxTarget) ([]byte, error) {
	body, err := marshalSandboxJSON(openHandsSandboxHookGroups(rt))
	if err != nil {
		return nil, fmt.Errorf("marshal OpenHands sandbox hooks: %w", err)
	}
	return body, nil
}

// verifyOpenHandsSandboxHooks reads the rendered file back and requires
// exactly the contract's events, each bound to the DefenseClaw handler only.
func verifyOpenHandsSandboxHooks(data []byte, rt resolvedSandboxTarget) error {
	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		return fmt.Errorf("verify OpenHands sandbox hooks: %w", err)
	}
	wantRaw, err := json.Marshal(openHandsSandboxHookGroups(rt))
	if err != nil {
		return err
	}
	var want map[string]interface{}
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("verify OpenHands sandbox hooks: registrations differ from contract %s", rt.contract.ContractID)
	}
	return nil
}
