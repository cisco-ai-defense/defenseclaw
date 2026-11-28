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

package gateway

import "testing"

// GAP-1914: a panic in a reading past the dispatch (here: injected at the
// start of every lane) is the evaluation fault, a block in every pack and
// mode, never the hook's fail-mode answer; it is counted and logged.
func TestGAP1914LanePanicBlocksOnEveryRoute(t *testing.T) {
	trustedToolLaneFaultHook = func(trustedActionRequest) { panic("gap1914 injected lane fault") }
	t.Cleanup(func() { trustedToolLaneFaultHook = nil })
	for _, p := range gap0437Packs {
		for _, mode := range gap0437Modes {
			t.Run(p.name+"/"+mode, func(t *testing.T) {
				a := gap0437Server(t, p, "claudecode", mode)
				before := evaluatorFaults.Load()
				gap0437AssertBlock(t, "hook", p, mode, gap0437Hook(t, a, t.TempDir(), "lane-"+p.name+mode, "ls"))
				a = gap0437Server(t, p, "openclaw", mode)
				gap0437AssertModeBlock(t, "inspect/tool", p, mode, gap0437Inspect(t, a, t.TempDir(), "ls"))
				if evaluatorFaults.Load() == before {
					t.Errorf("%s: the injected lane faults were not counted", p.name)
				}
			})
		}
	}
}
