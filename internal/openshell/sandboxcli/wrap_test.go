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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fitsWidth fails for an output line wider than width columns.
func fitsWidth(t *testing.T, out string, width int) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if n := visibleLen(l); n > width {
			t.Errorf("line of %d columns in a %d-column terminal: %q", n, width, l)
		}
	}
}

func TestWrapWordsBreaksAtSpacesOnly(t *testing.T) {
	text := "  ⚠ blocked by your organization's DefenseClaw policy: sandbox — your organization does not let you run sandboxes (openshell.admin.allowed)"
	lines := wrapWords(text, 60, "    ")
	if len(lines) < 3 {
		t.Fatalf("not wrapped: %q", lines)
	}
	for _, l := range lines {
		if visibleLen(l) > 60 {
			t.Errorf("line too wide: %q", l)
		}
	}
	if got, want := strings.Fields(strings.Join(lines, " ")), strings.Fields(text); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("words changed:\n%q\n%q", got, want)
	}
	// A word longer than the line stays whole.
	long := strings.Repeat("a", 80)
	if got := wrapWords("see "+long+" now", 60, ""); len(got) != 3 || got[1] != long {
		t.Fatalf("long word: %q", got)
	}
}

// Output wraps at the terminal's width only when there is one.
func TestWarnWrapsAtTheTerminalWidth(t *testing.T) {
	ta := newTestApp(t, "")
	msg := "blocked by your organization's DefenseClaw policy: sandbox — your organization does not let you run sandboxes (openshell.admin.allowed)"
	ta.warn(msg)
	if got := strings.Count(ta.output(), "\n"); got != 1 {
		t.Fatalf("without a width the line was split into %d:\n%s", got, ta.output())
	}
	ta.fresh()
	ta.IO.Width = 60
	ta.warn(msg)
	out := ta.output()
	fitsWidth(t, out, 60)
	has(t, out, "sandbox —", "(openshell.admin.allowed)")
	lacks(t, out, "sandb\nox", "opens\nhell")
}

// `policy explain --sources` on a managed computer at 60 columns: no row
// runs past the terminal, a source tag is never cut, and the tag moves to a
// line of its own when it does not fit after the text (GAP-0321).
func TestManagedExplainSourcesFitSixtyColumns(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.Width = 60
	m := &sandboxapi.ManagedExplain{
		Profile: "contractors", Match: "group", Allowed: true,
		RequiredFor: []string{"claudecode", "codex"}, WhenUnavailable: "alert",
		EgressAllowOnly: []string{"api.example.com", "registry.example.org"}, UserApprovals: "session",
		Sources: map[string]string{
			"required_for": sandboxapi.ExplainSourceOrganization, "when_unavailable": sandboxapi.ExplainSourceProfile,
			"egress_allow_only": sandboxapi.ExplainSourceOrganization, "user_approvals": sandboxapi.ExplainSourceProfile,
		},
	}
	ta.printManagedExplainFor(m, nil, "", true)
	out := ta.output()
	fitsWidth(t, out, 60)
	// A tag that does not fit after its row starts a line of its own and breaks only between words.
	has(t, strings.Join(strings.Fields(out), " "), "[from your organization (everyone)]",
		"[from your organization (everyone), your organization profile]", "[from your organization profile]")
	// Without a width the rows are as they were: one line each.
	ta.fresh()
	ta.IO.Width = 0
	ta.printManagedExplainFor(m, nil, "", true)
	for _, l := range strings.Split(strings.TrimRight(ta.output(), "\n"), "\n")[1:] {
		if strings.HasPrefix(l, "      ") {
			t.Errorf("a row wrapped without a terminal width: %q", l)
		}
	}
}

// A table wider than the terminal prints a block per row; a narrow one is
// unchanged.
func TestWideTablePrintsBlocksOnANarrowTerminal(t *testing.T) {
	header := []string{"SETTING", "VALUE", "SOURCE", "ORIGIN"}
	rows := [][]string{
		{"workdir.masks", ".env, .env.* (+22 more; -o json lists all)", "pack", "pack open + defenseclaw review floor"},
		{"learn", "false", "default", "defenseclaw default"},
	}
	ta := newTestApp(t, "")
	ta.table(header, rows)
	has(t, ta.output(), "SETTING", "workdir.masks")
	ta.fresh()
	ta.IO.Width = 60
	ta.table(header, rows)
	out := ta.output()
	fitsWidth(t, out, 60)
	has(t, out, "workdir.masks", "value", "source  pack", "origin  pack open + defenseclaw review floor", "learn")
	lacks(t, out, "SETTING")
}
