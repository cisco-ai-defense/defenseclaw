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

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1936: a DefenseClaw control reader fault is the evaluation fault of the
// call: a block in every pack and mode, the fail-closed profiles (strict,
// managed) included, whether or not the text spells DefenseClaw. Before the
// fix the reader's own recovery answered "ls" with no fact and the call was
// allowed.
func TestGAP1936ControlReaderFaultBlocksInEveryPackAndMode(t *testing.T) {
	defenseClawControlReader = func(facts actionfacts.Facts, text string) []actionfacts.DefenseClawControlFact {
		return append(actionfacts.DefenseClawControl(facts, text), actionfacts.DefenseClawControlFact{
			Kind: actionfacts.DefenseClawControlFault, Fault: "gap1936 injected control fault",
		})
	}
	t.Cleanup(func() { defenseClawControlReader = actionfacts.DefenseClawControl })
	for _, p := range gap0437Packs {
		for _, mode := range gap0437Modes {
			t.Run(p.name+"/"+mode, func(t *testing.T) {
				for _, command := range []string{"ls", "defenseclaw-gateway stop"} {
					before := evaluatorFaults.Load()
					a := gap0437Server(t, p, "claudecode", mode)
					out := gap0437Hook(t, a, t.TempDir(), "c1936-"+p.name+mode+command, command)
					gap0437AssertBlock(t, "hook "+command, p, mode, out)
					if raw, _ := json.Marshal(out); !strings.Contains(string(raw), evaluatorFaultTitle) {
						t.Errorf("hook %q: the answer does not name the evaluator fault: %s", command, raw)
					}
					a = gap0437Server(t, p, "openclaw", mode)
					gap0437AssertModeBlock(t, "inspect/tool "+command, p, mode, gap0437Inspect(t, a, t.TempDir(), command))
					if evaluatorFaults.Load() == before {
						t.Errorf("%s %q: the control reader fault was not counted", p.name, command)
					}
				}
			})
		}
	}
}
