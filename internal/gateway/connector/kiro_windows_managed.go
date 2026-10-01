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
	"runtime"
	"strings"
)

// Managed Windows enrolls Kiro per user through hooks. Per-user Kiro hooks
// stay not version-gated; the managed footprint is gated by the two reviewed
// contracts below, one per Kiro product, because the kiro-cli and Kiro IDE
// version lines overlap.
const (
	// KiroWindowsManagedCLIContractID covers kiro-cli on managed Windows.
	KiroWindowsManagedCLIContractID = "kiro-cli-windows-managed-hooks-v1"
	// KiroWindowsManagedIDEContractID covers the Kiro IDE on managed Windows.
	KiroWindowsManagedIDEContractID = "kiro-ide-windows-managed-hooks-v1"
	// KiroIDEVersionSuffix marks a discovered version as the Kiro IDE's
	// rather than kiro-cli's.
	KiroIDEVersionSuffix = "+kiro-ide"
	// KiroWindowsManagedCLIFloor is the lowest kiro-cli build verified on
	// Windows: `kiro-cli chat --help` lists --v3 and --agent-engine v3, the
	// engine that reads ~/.kiro/hooks and vetoes UserPromptSubmit.
	KiroWindowsManagedCLIFloor = "2.24.1"
	// KiroWindowsManagedIDEFloor is the first Kiro IDE that reads the global
	// ~/.kiro/hooks file (kiro.dev/changelog/ide/1-0-182); older builds read
	// only a project's .kiro/hooks, which the managed footprint never writes.
	KiroWindowsManagedIDEFloor = "1.0.182"
)

// kiroWindowsManagedHookEvents are the events the managed footprint
// registers: the v3 hook file's (UserPromptSubmit, PreToolUse, PostToolUse,
// Stop) and the CLI 2.x agent's (preToolUse, postToolUse, stop).
var kiroWindowsManagedHookEvents = []string{
	"UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
	"preToolUse", "postToolUse", "stop",
}

// kiroWindowsManagedHookContracts is the reviewed hook surface of the managed
// Windows Kiro footprint. Capabilities leave Scope and ConfigPath empty so
// the profile keeps the paths Kiro's connector resolves for the target user.
func kiroWindowsManagedHookContracts() []HookContract {
	shared := func(id, floor string, notes ...string) HookContract {
		return HookContract{
			Connector:         "kiro",
			ContractID:        id,
			MinAgentVersion:   floor,
			HookScriptVersion: "v1",
			HookConfigPathTemplates: []string{
				"~/.kiro/hooks/" + kiroManagedHooksName,
				"~/.kiro/agents/" + kiroManagedAgentName + ".json",
			},
			Events:      append([]string(nil), kiroWindowsManagedHookEvents...),
			AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
			Capabilities: HookCapability{
				CanBlock:           true,
				SupportsFailClosed: true,
				// The v3 file's veto surface; requests from the CLI 2.x
				// agent are narrowed per request by KiroBlockEventsForSurface.
				BlockEvents: KiroBlockEventsForSurface(KiroHookSurfaceV3),
			},
			SupportsTraceparent: true,
			Notes: append([]string{
				"Managed Windows writes, under the target user's token, ~/.kiro/hooks/defenseclaw.json (v3: DefenseClaw blocks on UserPromptSubmit and PreToolUse, and kiro-cli --v3 records a prompt block without vetoing it; PostToolUse and Stop are audit only) and the CLI 2.x agent ~/.kiro/agents/defenseclaw.json (preToolUse is the only veto), selected as the default agent in ~/.kiro/settings/cli.json.",
				"Each hook command runs cmd.exe into a PowerShell bridge that executes the standalone defenseclaw-hook.exe, which serves the enterprise-managed runtime; Kiro hooks cannot rewrite tool input, so no foreign-hook rewrite guard applies.",
			}, notes...),
		}
	}
	return []HookContract{
		shared(KiroWindowsManagedCLIContractID, KiroWindowsManagedCLIFloor,
			"kiro-cli reads the v3 file with --v3 (or --agent-engine v3) and the agent file otherwise; 2.24.1 is the lowest build verified on Windows."),
		shared(KiroWindowsManagedIDEContractID, KiroWindowsManagedIDEFloor,
			"The Kiro IDE reads the global ~/.kiro/hooks file from 1.0.182; the discovered IDE version carries the +kiro-ide suffix."),
	}
}

// kiroWindowsManagedHookContractID reports whether id is one of the managed
// Windows Kiro contracts.
func kiroWindowsManagedHookContractID(id string) bool {
	id = strings.TrimSpace(id)
	return id == KiroWindowsManagedCLIContractID || id == KiroWindowsManagedIDEContractID
}

// ResolveWindowsManagedKiroHookContract resolves a discovered Kiro version
// against the managed Windows contracts: a version with KiroIDEVersionSuffix
// against the IDE contract, any other against the kiro-cli one.
func ResolveWindowsManagedKiroHookContract(rawVersion string) HookContractResolution {
	raw := strings.TrimSpace(rawVersion)
	contracts := kiroWindowsManagedHookContracts()
	product, version, contract := "kiro-cli", raw, contracts[0]
	if strings.HasSuffix(raw, KiroIDEVersionSuffix) {
		product, version, contract = "Kiro IDE", strings.TrimSpace(strings.TrimSuffix(raw, KiroIDEVersionSuffix)), contracts[1]
	}
	resolution := resolveHookContractAgainst("kiro", version, []HookContract{contract})
	resolution.RawVersion = raw
	if resolution.Status == HookCompatibilityUnknown && resolution.NormalizedVersion != "" &&
		compareVersion(resolution.NormalizedVersion, contract.MinAgentVersion) < 0 {
		resolution.Reason = fmt.Sprintf("%s %s is below the certified minimum %s", product, resolution.NormalizedVersion, contract.MinAgentVersion)
	}
	return resolution
}

// ResolveManagedHookContract resolves an agent version for the standalone
// enterprise profile on this host: managed Windows Kiro against its reviewed
// contracts, every other connector as ResolveHookContract does.
func ResolveManagedHookContract(connectorName, rawVersion string) HookContractResolution {
	if managedKiroOnOS(connectorName, runtime.GOOS) {
		return ResolveWindowsManagedKiroHookContract(rawVersion)
	}
	return ResolveHookContract(connectorName, rawVersion)
}

// HookContractRegistered reports whether contractID is a hook contract this
// host can pin for connectorName, the managed Windows Kiro contracts included.
func HookContractRegistered(connectorName, contractID string) bool {
	_, ok := hookContractByID(connectorName, contractID)
	return ok
}

func managedKiroOnOS(connectorName, goos string) bool {
	return goos == "windows" && normalizeConnectorName(connectorName) == "kiro"
}
