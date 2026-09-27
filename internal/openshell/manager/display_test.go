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

package manager

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// esc is an inert terminal control marker: an escape sequence introducer
// and a bell, which a terminal must never receive from sandbox text.
const esc = "\x1b[0mDCMARK\x07"

func holdsControl(t *testing.T, what string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// JSON escapes control characters; their escapes must not appear.
	if s := string(data); strings.Contains(s, `\u001b`) || strings.Contains(s, `\u0007`) {
		t.Fatalf("%s carries control characters: %s", what, s)
	}
}

// TestSandboxTextIsSafeToPrint pins that text a sandbox controls (a
// directory it creates, a hook's tool name, a proposal's binary and
// notes) reaches the feed and the API without terminal control
// characters.
func TestSandboxTextIsSafeToPrint(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "textbox"})
	e.watch.waitStarted(t, sb.Name)

	// A planted repository in a directory named with control characters.
	opts := e.guard.waitActive(t, e.project, true)
	opts.OnDetect(nestguard.Detection{Kind: nestguard.KindRepository, Dir: "src/" + esc, Quarantined: "src/" + esc + "/.git.q",
		At: time.Now()})
	// A blocked tool call whose name carries them.
	binding, _ := e.store.Lookup(sb.Name)
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", Tool: "Bash" + esc,
		Action: "block", Reason: "blocked " + esc})
	// A proposal whose binary and advisor notes carry them.
	c := chunk("allow_host_openshell_internal_5432", "host.openshell.internal", 5432)
	c.Binary = "/usr/bin/" + esc
	c.SecurityNotes = "notes " + esc
	c.Rationale = "why " + esc
	addChunk(e, sb.Name, c)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)

	holdsControl(t, "the activity feed", e.m.ActivitySince(0, sb.Name))
	holdsControl(t, "the approvals", asks)
	got, err := e.m.Get(ctx, sb.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NestedRepos) != 1 || !strings.Contains(got.NestedRepos[0].Path, "DCMARK") {
		t.Fatalf("nested repos = %+v", got.NestedRepos)
	}
	holdsControl(t, "the sandbox view", got)
}
