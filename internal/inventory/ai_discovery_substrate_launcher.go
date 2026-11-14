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

package inventory

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/launcherpresence"
)

// SubstrateLauncherSignatureID names the DefenseClaw Agent Substrate
// launcher in discovery (PLAN E26): `defenseclaw substrate run|connect|logs`
// puts a coding agent that runs in the organization's cluster on this
// terminal. It is DefenseClaw itself, guarded by the cluster, so discovery
// labels it instead of listing an unknown AI process. The signature is
// built in, not in the catalog file: no process name selects it (every
// DefenseClaw command has the same name), only the launcher's own record
// (internal/substrate/launcherpresence).
const SubstrateLauncherSignatureID = "defenseclaw-substrate-launcher"

var substrateLauncherSignature = AISignature{
	ID:       SubstrateLauncherSignatureID,
	Name:     "DefenseClaw Agent Substrate launcher",
	Vendor:   "Cisco",
	Category: SignalAICLI,
}

// substrateLauncherBinary reports a process named like the DefenseClaw
// binary (the launcher is a subcommand of it).
func substrateLauncherBinary(p processInfo) bool {
	for _, n := range []string{p.Comm, p.Argv0, p.Argv0Target} {
		n = strings.TrimSuffix(strings.ToLower(filepath.Base(strings.TrimSpace(n))), ".exe")
		if n == "defenseclaw" || n == "defenseclaw-gateway" {
			return true
		}
	}
	return false
}

// substrateLauncherDataDirs are the DefenseClaw data directories whose
// launcher records are read: each scanned home's ~/.defenseclaw, and this
// process's own data directory (DEFENSECLAW_HOME may move it).
func (s *ContinuousDiscoveryService) substrateLauncherDataDirs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if d = filepath.Clean(d); d != "." && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, h := range s.homesToScan() {
		add(filepath.Join(h, ".defenseclaw"))
	}
	if len(s.opts.HomeDirs) == 0 {
		add(config.DefaultDataPath())
	}
	return out
}

// detectSubstrateLaunchers labels the running launchers among procs: a
// process named defenseclaw whose PID and start time match a launcher
// record. One signal, the newest launcher first; the rest are its
// OtherInstances.
func (s *ContinuousDiscoveryService) detectSubstrateLaunchers(procs []processInfo, now time.Time) []AISignal {
	var found []processInfo
	dirs := s.substrateLauncherDataDirs()
	for _, p := range procs {
		if p.PID <= 0 || !substrateLauncherBinary(p) {
			continue
		}
		for _, d := range dirs {
			b, err := readBoundedRegularFileNoFollow(launcherpresence.Path(d, p.PID), launcherpresence.MaxRecordBytes)
			if err != nil {
				continue
			}
			if r, ok := launcherpresence.Parse(b, p.PID); ok && r.Matches(p.StartedAt) {
				found = append(found, p)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].StartedAt.After(found[j].StartedAt) })
	signal := s.signalFromProcess(substrateLauncherSignature, found[0], now, MatchKindExact, 1.0)
	for _, other := range found[1:] {
		if len(signal.Runtime.OtherInstances) >= maxProcessOtherInstances {
			break
		}
		signal.Runtime.OtherInstances = append(signal.Runtime.OtherInstances, *newProcessRuntime(other, now))
	}
	return []AISignal{signal}
}
