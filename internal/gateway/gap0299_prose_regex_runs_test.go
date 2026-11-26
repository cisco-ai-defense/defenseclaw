// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	return fmt.Sprintf("cat > notes.txt <<'EOF'\nrow %s\n", gap0299RowMark()) +
		strings.Repeat(line, 1000000/len(line)) + "EOF\n"
}

// gap0299RowMark makes each call's text new (no answer kept from an earlier
// call serves it) without digits: the clock's nanoseconds spelled in ten
// consonants. A digit mark made the count depend on the clock: a run of 19
// digits passes the card number pre-checks (ENT-CC-VISA and others) for
// some values and not for others, so the same tree counted 8, 10 or 12
// regex runs (rel-1-0-10:GAP-2220). A run of these letters spells no
// command or rule keyword.
func gap0299RowMark() string {
	const letters = "bdfghjklmq"
	mark := []byte(strconv.FormatInt(time.Now().UnixNano(), 10))
	for i, c := range mark {
		mark[i] = letters[c-'0']
	}
	return string(mark)
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

// gap0299MaxProseRegexRuns is the bound of one cold prose call. The text
// has no digit (gap0299RowMark), so no rule regex passes its pre-check: 0
// runs at 0859b551d4 in 24 of 24 runs. At befff79e53 the gate expression
// ran 6 times over the 1 MiB text; were it back, the bound fails. (With
// the old digit mark the rule regexes the digits woke made it 8, 10 or 12,
// bound 10, rel-1-0-10:GAP-2220.)
const gap0299MaxProseRegexRuns = 2
