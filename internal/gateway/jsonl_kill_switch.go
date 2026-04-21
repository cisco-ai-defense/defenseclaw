// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "strings"

// jsonlKillSwitchEnabled returns true when the operator has requested
// the gateway.jsonl file tier be disabled at startup. Accepts the usual
// truthy-string vocabulary so operators do not have to remember whether
// the switch takes 1/true/yes/on — every DevOps muscle-memory value
// works. Leading/trailing whitespace is tolerated because container
// orchestrators (systemd, docker-compose, Kubernetes ConfigMaps) are
// notorious for trailing newlines in environment exports.
//
// A dedicated helper (rather than inlining strconv.ParseBool) lets us:
//
//   - accept "yes"/"no" which ParseBool rejects
//   - treat unrecognised values as "off" rather than an error, so a
//     fat-fingered DEFENSECLAW_JSONL_DISABLE=maybe never silently
//     kills observability in production
//   - unit-test the exact matrix of inputs we document in
//     docs/OBSERVABILITY.md
func jsonlKillSwitchEnabled(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true
	default:
		return false
	}
}
