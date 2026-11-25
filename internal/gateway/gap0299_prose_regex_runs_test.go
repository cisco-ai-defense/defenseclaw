// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

// gap0299ProseHereDocument is a here-document of 1,000,000 bytes (under the
// 1 MiB command cap) of one line of prose
// over and over: each sentence ends in a period before a newline, the shape
// of TestGAP0299LargeHeredocCostStaysBounded's text rows.
func gap0299ProseHereDocument() string {
	line := "Meeting notes: the team reviewed the plan and agreed on the next steps.\n"
	return fmt.Sprintf("cat > notes.txt <<'EOF'\nrow %d\n", time.Now().UnixNano()) +
		strings.Repeat(line, 1000000/len(line)) + "EOF\n"
}

// TestGAP0299ProseHereDocumentRegexRuns bounds the regex runs over the large
// text of one cold hook call on a 1 MiB here-document of prose, Claude Code
// Bash route, default pack (rel-1-0-10:GAP-0299). A period before a space passed
// the literal pre-check of the glob-options gate, and its expression (no
// literal prefix) ran the regexp NFA over the whole call once per reader
// that asked, about 60% of the decision; the gate is a linear scan now
// (globOptionsChangeScan) and runs no expression.
func TestGAP0299ProseHereDocumentRegexRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the counts are of the POSIX readers")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	if action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, "echo warm", true, false); action != "allow" {
		t.Fatalf("warm-up call: action %q, want allow", action)
	}
	command := gap0299ProseHereDocument()
	before := workcount.Take()
	action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
	regexes := before.Since(workcount.RegexRun)
	t.Logf("COUNTED regexes=%d action=%s", regexes, action)
	if action != "alert" {
		t.Errorf("benign 1 MiB here-document: action %q, want alert (over the evaluation limit, as on rel)", action)
	}
	if regexes > gap0299MaxProseRegexRuns {
		t.Errorf("regex runs over the 1 MiB prose text in one call = %d, bound %d", regexes, gap0299MaxProseRegexRuns)
	}
}

// gap0299MaxProseRegexRuns is the bound of one cold prose call: the rule
// regexes only. At befff79e53 it was 16 with the gate expression counted at
// its lines (6 runs of it over the 1 MiB text).
const gap0299MaxProseRegexRuns = 10
