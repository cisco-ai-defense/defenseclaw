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

// GAP-0493: the shell keys of the table are the ones actionfacts reads as
// shell. Each key gets a value of the shape actionfacts expects there and must
// project a command; a key the table lacks must not (so the table is not stale
// on either side).
func TestIntentScopeGAP0493KeysMatchActionfacts(t *testing.T) {
	project := func(key string) int {
		var value any = "ls"
		switch scopeKeys[key] {
		case scopeKeyArgs:
			value = []string{"ls"}
		}
		if strings.Contains(key, "argv") && scopeKeys[key] == scopeKeyShell {
			value = []string{"ls"}
		}
		switch key {
		case "input", "parameters", "request":
			value = map[string]string{"command": "ls"}
		}
		b, _ := json.Marshal(map[string]any{key: value})
		return len(actionfacts.Analyze(actionfacts.Input{Tool: "run", Args: b}).Commands)
	}
	for key, kind := range scopeKeys {
		if key == "" || key == "code" || (kind != scopeKeyShell && kind != scopeKeyArgs) {
			continue
		}
		if project(key) == 0 {
			t.Errorf("shell key %q projects no command in actionfacts: drop it from the table, or add it to actionfacts", key)
		}
	}
	for _, key := range []string{"pad", "payload_text", "shell", "run"} {
		if _, in := scopeKeys[key]; !in && project(key) != 0 {
			t.Errorf("actionfacts reads key %q as shell and the table does not", key)
		}
	}
}

// GAP-0494: the precheck and the walk read one table: a call with any key of the
// table, past the precheck size, is read.
func TestIntentScopeGAP0494PrecheckReadsEveryTableKey(t *testing.T) {
	pad := strings.Repeat("p", scopeKeyPrecheckBytes+1)
	for key := range scopeKeys {
		b, _ := json.Marshal(map[string]string{key: "x", "pad": pad})
		if !scopeMayHaveDestination(string(b)) {
			t.Errorf("the precheck skips a call with the key %q the walk reads", key)
		}
	}
	if scopeMayHaveDestination(`{"pad":"` + pad + `"}`) {
		t.Error("the precheck must still skip a large call with no table key")
	}
}
