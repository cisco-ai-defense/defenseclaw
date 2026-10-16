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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// es-demo:GAP-0013: with only a Codex sandbox running, a bare managed
// `policy explain` showed the profile of a new run of the default agent
// (engineering, for Claude Code) while `status` named the Codex sandbox's
// profile (engineering-codex-locked), and nothing said which one explain
// had answered for. It says so now and names the running sandboxes to ask
// about; a flag that chooses what to explain needs no note.
func TestManagedExplainSaysWhatABareExplainAnswersFor(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Managed = managedExplainFixture()
	ta.daemon.sandboxes = map[string]*sandboxapi.Sandbox{
		"bob-codex":  {Name: "bob-codex", Harness: "codex", Phase: "ready"},
		"old-claude": {Name: "old-claude", Harness: "claudecode", Phase: "stopped"},
	}
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{}))
	has(t, ta.output(), "this is the policy of a new run of the default agent", "--harness NAME",
		"policy explain --sandbox NAME (running: bob-codex (codex))")
	lacks(t, ta.output(), "old-claude")

	ta.fresh()
	ta.ok(t, ta.PolicyShow(bg, PolicyOptions{}))
	has(t, ta.output(), "this is the policy of a new run of the default agent")

	for _, o := range []PolicyOptions{{Sandbox: "bob-codex"}, {Harness: "codex"}} {
		ta.fresh()
		ta.ok(t, ta.PolicyExplain(bg, o))
		lacks(t, ta.output(), "new run of the default agent")
	}
}
