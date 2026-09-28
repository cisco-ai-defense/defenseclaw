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

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// The agent names the files, branches and commands that reach the review:
// control characters in them must not reach the terminal as escape
// sequences, carriage returns or direction overrides.
func TestSessionReviewIsTerminalSafe(t *testing.T) {
	ta := newTestApp(t, "d\ny\n")
	evil := "notes\x1b[2J\x1b]0;DCMARKER\x07\rx\u202etxt.sh"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{FilesChanged: 1, Insertions: 1,
		BranchBefore: "main", BranchAfter: "main",
		Flags: []workspace.Flag{{Path: evil, Label: evil, Kind: workspace.RiskExecutable, Severity: workspace.SeverityHigh, Detail: "new executable"}}}}
	ta.term.during = func() {
		ta.daemon.mu.Lock()
		sb := ta.daemon.sandboxes["dc-claude-proj-1a2b"]
		sb.Hooks = sandboxapi.HookCoverage{ToolCalls: 2, ToolBlocked: 1, LastBlocked: "rm\x1b[1A marker"}
		ta.daemon.mu.Unlock()
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if strings.ContainsAny(out, "\x1b\x07\r\u202e") {
		t.Fatalf("control characters reached the terminal: %q", out)
	}
	if !strings.Contains(out, "notes\ufffd[2J") || !strings.Contains(out, "+changed") {
		t.Fatalf("the review lost its text: %q", out)
	}
}

func TestTerminalText(t *testing.T) {
	for in, want := range map[string]string{
		"plain text\n\tindented":                   "plain text\n\tindented",
		ansiYellow + "⚠ risk" + ansiReset + " → x": ansiYellow + "⚠ risk" + ansiReset + " → x",
		"a\x1b[2Jb":            "a\ufffd[2Jb",
		"a\x1b]0;title\x07b":   "a\ufffd]0;title\ufffdb",
		"line\roverwrite":      "line overwrite",
		"x\u202ey\u0085z\xffw": "x\ufffdy\ufffdz\ufffdw",
	} {
		if got := terminalText(in); got != want {
			t.Errorf("terminalText(%q) = %q, want %q", in, got, want)
		}
	}
	// The palette's own codes pass through the helpers.
	ta := newTestApp(t, "")
	ta.IO.Color = true
	ta.warn("x\x1b[2Jy")
	if out := ta.output(); !strings.Contains(out, ansiYellow+ansiBold+"⚠"+ansiReset+" x\ufffd[2Jy") {
		t.Fatalf("warn = %q", out)
	}
}
