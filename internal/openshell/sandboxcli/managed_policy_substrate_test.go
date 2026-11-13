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

//go:build !windows

package sandboxcli

import (
	"strings"
	"testing"
	"time"
)

// E26: a floor with runtimes [substrate] says the required agents run on
// Agent Substrate and names the launcher command; both runtimes keep the
// sandbox text.
func TestManagedExplainOfASubstrateOnlyFloor(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	rows := func(runtimes ...string) string {
		m := managedExplainFixture() // requires claudecode and codex
		m.HostRunGate = "refused"
		m.Runtimes = runtimes
		var b strings.Builder
		for _, r := range managedExplainRows(m, now) {
			b.WriteString(r.label + " | " + r.text + "\n")
		}
		return b.String()
	}
	only := rows("substrate")
	has(t, only, "Required | claude and codex run only on Agent Substrate, not on this computer: start one with defenseclaw substrate run claude")
	lacks(t, only, "run only in a sandbox on this computer")
	has(t, rows("openshell", "substrate"), "Required | claude and codex run only in a sandbox on this computer")
	has(t, rows(), "Required | claude and codex run only in a sandbox on this computer")
}
