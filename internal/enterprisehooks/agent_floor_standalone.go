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
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// standaloneNotGatedAgentFloors are the lowest agent versions the standalone
// profile certifies for connectors whose hook contract is not version-gated
// (connector.HookCompatibilityNotGated). Per-user installs stay not-gated;
// only the standalone guardian applies these floors. In action mode it
// refuses to install below the floor, and it follows an agent upgrade at or
// above it (a not-gated connector has no known contract to follow).
//
// Kiro: kiro-cli 2.24.1 is the lowest build verified on Windows, Linux and
// macOS. Its `kiro-cli chat --help` lists
// --v3 and --agent-engine v1|v2|v3, the engine that reads the user's global
// ~/.kiro/hooks file and vetoes UserPromptSubmit. kiro.dev documents --v3
// from 2.21.4; builds between 2.21.4 and 2.24.1 are not certified here.
var standaloneNotGatedAgentFloors = map[string]string{
	"kiro": "2.24.1",
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
// floor, and why not. A connector without a floor is not admitted: callers
// keep their earlier behavior for it.
func standaloneNotGatedVersionAdmitted(resolution connector.HookContractResolution) (bool, string) {
	floor := standaloneNotGatedAgentFloor(resolution.Connector)
	if floor == "" || resolution.Status != connector.HookCompatibilityNotGated {
		return false, ""
	}
	product, subject := resolution.Connector, "version"
	if product == "kiro" && strings.HasSuffix(strings.TrimSpace(resolution.RawVersion), KiroIDEVersionSuffix) {
		product, subject, floor = "Kiro IDE", "Kiro IDE version", KiroIDEGlobalHooksFloor
	}
	normalized := strings.TrimSpace(resolution.NormalizedVersion)
	if normalized == "" {
		return false, fmt.Sprintf("its version could not be read; the standalone profile certifies %s %s and later", product, floor)
	}
	if compareStandaloneFloorVersion(normalized, floor) < 0 {
		return false, fmt.Sprintf("%s %s is below the certified minimum %s", subject, normalized, floor)
	}
	return true, ""
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
