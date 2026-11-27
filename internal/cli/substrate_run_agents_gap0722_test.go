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

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// GAP-0722: run with no agent name used to list 7 of the supported agents
// from a hand-written sentence. The list now comes from the harness table,
// so a connector added there is named without a second edit.
func TestSubstrateRunNoAgentNamesEveryHarness(t *testing.T) {
	cmd := newSubstrateRunCmd()
	err := cmd.Args(cmd, nil)
	if err == nil {
		t.Fatal("run with no agent name must be refused")
	}
	msg := err.Error()
	names := harness.Names()
	if len(names) == 0 {
		t.Fatal("harness table is empty")
	}
	for _, n := range names {
		spec, _ := harness.Get(n)
		arg := sandboxcli.HarnessArg(spec)
		if !strings.Contains(msg, arg) {
			t.Errorf("no-agent message %q does not name %q (%s)", msg, arg, n)
		}
	}
	// The help text names the same agents.
	for _, n := range names {
		spec, _ := harness.Get(n)
		if arg := sandboxcli.HarnessArg(spec); !strings.Contains(cmd.Long, arg) {
			t.Errorf("run help does not name %q", arg)
		}
	}
}
