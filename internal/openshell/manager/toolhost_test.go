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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestARefusedToolHostSaysWhatItBreaks (GAP-0234, GAP-0263): under
// balanced, Claude Code's WebFetch failed for every site, because it asks
// api.anthropic.com about each URL and balanced refuses that host; the
// agent told the user the sites were blocked. The feed says once what the
// refusal breaks, and so does the agent's refusal note.
func TestARefusedToolHostSaysWhatItBreaks(t *testing.T) {
	e := liveEnv(t, "toolbox", nil)
	id := e.binding("toolbox").ID
	for range 2 {
		ev := egress.Event{Kind: egress.EventBlocked, Time: time.Now(), BindingID: id, SandboxName: "toolbox",
			Method: "CONNECT", Host: "api.anthropic.com", Port: 443, Category: egress.CategoryNotAllowlisted, Unblockable: true}
		// The sink remembers the refusal for the agent, then records it.
		e.m.refusals.note(ev, ev.Time)
		e.m.egressEvent(t.Context(), ev, 0)
	}
	got := e.events("toolbox", sandboxapi.ActivityFinding, sandboxapi.ReasonToolHostRefused)
	if len(got) != 1 || got[0].Severity != "INFO" || !strings.Contains(got[0].Message, "WebFetch fails for every site while it is refused") ||
		!strings.Contains(got[0].Message, "`defenseclaw sandbox unblock api.anthropic.com --sandbox toolbox`") {
		t.Fatalf("feed = %+v, want one tool-host line", got)
	}
	refused := e.m.EgressRefusals(id, "toolbox")
	if len(refused) == 0 || !strings.Contains(refused[0].What, "WebFetch asks it whether each URL is safe") {
		t.Fatalf("agent note = %+v", refused)
	}
}
