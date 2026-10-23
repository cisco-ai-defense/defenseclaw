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

package enterprisehooks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// standaloneNotGatedAgentFloors are the lowest agent versions the standalone
// profile certifies for connectors whose hook contract is not version-gated
// (connector.HookCompatibilityNotGated). Kiro's CLI floor also applies to
// per-user setup and every guardrail mode. The standalone guardian follows
// an agent upgrade at or above the floor (a not-gated connector has no
// known contract to follow).
//
// Kiro: connector.KiroCLIHookFloor (2.27.1). Before it a non-interactive
// `kiro-cli chat --v3` run loads no hooks, so that kiro-cli has a surface
// whose tool calls never reach DefenseClaw (rel-1-0-4 GAP-0227).
var standaloneNotGatedAgentFloors = map[string]string{
	"kiro": connector.KiroCLIHookFloor,
}

// Kiro IDE rows. The Kiro IDE reads the global ~/.kiro/hooks file from
// 1.0.182 (kiro.dev/changelog/ide/1-0-182); older builds read only the
// project's .kiro/hooks. A user with the IDE and no readable kiro-cli
// version is enrolled at the IDE's version, recorded with
// KiroIDEVersionSuffix so the floor below is the IDE's, not kiro-cli's (the
// two version lines overlap). KiroIDEDiscoveryKey carries the IDE version
// from the per-user discovery worker next to the kiro-cli one.
const (
	KiroIDEGlobalHooksFloor = "1.0.182"
	KiroIDEVersionSuffix    = connector.KiroIDEVersionSuffix
	KiroIDEDiscoveryKey     = "kiro-ide"
)

// standaloneNotGatedAgentFloor returns the connector's standalone floor, or
// "" when it has none.
func standaloneNotGatedAgentFloor(connectorName string) string {
	return standaloneNotGatedAgentFloors[strings.ToLower(strings.TrimSpace(connectorName))]
}

// standaloneNotGatedVersionAdmitted reports whether a not-gated
// resolution's agent version is at or above the connector's standalone
// floor, and why not (JudgeKiroForm). A connector without a floor is not
// admitted: callers keep their earlier behavior for it.
func standaloneNotGatedVersionAdmitted(resolution connector.HookContractResolution) (bool, string) {
	if standaloneNotGatedAgentFloor(resolution.Connector) == "" || resolution.Status != connector.HookCompatibilityNotGated {
		return false, ""
	}
	verdict := JudgeKiroForm(kiroFormFromRowVersion(resolution.RawVersion))
	switch {
	case verdict.Protected:
		return true, ""
	case verdict.Unknown() && verdict.Form.IDE():
		return false, fmt.Sprintf("its version could not be read; the standalone profile certifies Kiro IDE %s and later", KiroIDEGlobalHooksFloor)
	case verdict.Unknown():
		return false, fmt.Sprintf("its version could not be read; the standalone profile certifies kiro %s and later", connector.KiroCLIHookFloor)
	case verdict.Form.IDE():
		return false, fmt.Sprintf("Kiro IDE version %s is below the certified minimum %s", verdict.Normalized, KiroIDEGlobalHooksFloor)
	default:
		return false, verdict.Reason
	}
}

// kiroCLIFloorRefusal applies the same CLI floor under every profile and
// compatibility status. The Windows managed contract still recognizes
// earlier enrolled builds so their interactive hooks can be repaired.
func kiroCLIFloorRefusal(resolution connector.HookContractResolution) string {
	if resolution.Connector != "kiro" {
		return ""
	}
	verdict := JudgeKiroForm(kiroFormFromRowVersion(resolution.RawVersion))
	if verdict.Form.IDE() || !verdict.BelowFloor() {
		return ""
	}
	return verdict.Reason
}

// kiroHookFloorRefusal also gates IDE builds that cannot read the global
// hooks file. The CLI and IDE share one connector but have separate floors
// (JudgeKiroForm). A kiro-cli version that could not be read is refused in
// action mode by kiroActionVersionRefusal.
func kiroHookFloorRefusal(resolution connector.HookContractResolution) string {
	if resolution.Connector != "kiro" {
		return ""
	}
	verdict := JudgeKiroForm(kiroFormFromRowVersion(resolution.RawVersion))
	if !verdict.Form.IDE() {
		return kiroCLIFloorRefusal(resolution)
	}
	switch {
	case verdict.Protected:
		return ""
	case verdict.Unknown():
		return fmt.Sprintf("Kiro IDE version could not be read; global hooks require %s or later", KiroIDEGlobalHooksFloor)
	default:
		return fmt.Sprintf("Kiro IDE version %s is below the certified minimum %s", verdict.Normalized, KiroIDEGlobalHooksFloor)
	}
}

// kiroActionVersionRefusal refuses action-mode Kiro hooks for an agent
// version that could not be read (rel-1-0-4 GAP-0895): Kiro's hooks are not
// version-gated, so without this an unknown kiro-cli resolved as not gated
// and was installed and verified as if it were at its floor. Unknown is not
// protected. Observe mode still installs, and status reports the agent.
func kiroActionVersionRefusal(resolution connector.HookContractResolution) string {
	if resolution.Connector != "kiro" || resolution.Status != connector.HookCompatibilityNotGated {
		return ""
	}
	if verdict := JudgeKiroForm(kiroFormFromRowVersion(resolution.RawVersion)); verdict.Unknown() {
		return verdict.Reason
	}
	return ""
}

// kiroCLIVersionBannerRE matches the banner `kiro-cli --version` prints
// (Python's _KIRO_CLI_VERSION_RE in connector_contracts.py).
var kiroCLIVersionBannerRE = regexp.MustCompile(`(?i)^kiro-cli\s+v?[0-9]`)

// cachedSetupAgentVersion is the agent version an install or verify uses
// when its caller named none: the one per-user discovery recorded in
// agent_discovery.json. That cache is written by Python discovery, which
// records a kiro-cli as its `kiro-cli X` banner and the Kiro IDE as a bare
// X, while Go enumeration records a kiro-cli as a bare X and the IDE with
// KiroIDEVersionSuffix. A cached IDE version is therefore marked with the
// suffix, so the IDE's floor, not kiro-cli's, applies to it.
func cachedSetupAgentVersion(dataDir, connectorName string) string {
	cached := strings.TrimSpace(connector.LoadCachedAgentVersion(dataDir, connectorName))
	if strings.ToLower(strings.TrimSpace(connectorName)) != "kiro" {
		return cached
	}
	return kiroDiscoveryCacheVersion(cached)
}

// kiroDiscoveryCacheVersion maps a Kiro version in discovery-cache form to
// the form the hook floors read: a kiro-cli banner stays as it is, and any
// other version is the IDE's.
func kiroDiscoveryCacheVersion(cached string) string {
	cached = strings.TrimSpace(cached)
	if cached == "" || strings.HasSuffix(cached, KiroIDEVersionSuffix) || kiroCLIVersionBannerRE.MatchString(cached) {
		return cached
	}
	return cached + KiroIDEVersionSuffix
}

// kiroIDEMarkerAdded reports whether the only difference between a Kiro
// contract lock and the entry an install would now record is the IDE marker
// added to the same build: an earlier release installed from the discovery
// cache and recorded the IDE's bare version. Unix Kiro renders one hooks file
// for the CLI and the IDE under one contract, so this is no agent change. A
// marker removed (an IDE row now read as a kiro-cli) is still drift.
func kiroIDEMarkerAdded(previous, current connector.HookContractLockEntry) bool {
	if strings.ToLower(strings.TrimSpace(previous.Connector)) != "kiro" ||
		strings.TrimSpace(previous.ContractID) != strings.TrimSpace(current.ContractID) {
		return false
	}
	before, after := strings.TrimSpace(previous.RawAgentVersion), strings.TrimSpace(current.RawAgentVersion)
	return before != "" && !strings.HasSuffix(before, KiroIDEVersionSuffix) && after == before+KiroIDEVersionSuffix
}

// standaloneAgentFloorRefusal explains why resolution's version is below
// its connector's standalone floor, not-gated (Unix Kiro) or under the
// managed Windows Kiro contract; empty when it is not.
func standaloneAgentFloorRefusal(resolution connector.HookContractResolution) string {
	if resolution.Status == connector.HookCompatibilityNotGated {
		_, reason := standaloneNotGatedVersionAdmitted(resolution)
		return reason
	}
	return kiroCLIFloorRefusal(resolution)
}

// compareStandaloneFloorVersion compares two normalized major.minor.patch
// versions numerically (missing parts count as 0).
func compareStandaloneFloorVersion(left, right string) int {
	l := strings.Split(left, ".")
	r := strings.Split(right, ".")
	for i := 0; i < 3; i++ {
		a, b := 0, 0
		if i < len(l) {
			a, _ = strconv.Atoi(l[i])
		}
		if i < len(r) {
			b, _ = strconv.Atoi(r[i])
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	return 0
}
