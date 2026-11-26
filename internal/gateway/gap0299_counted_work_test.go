// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

// gap0299HereDocument is the 1 MiB benign here-document of GAP-0299.
func gap0299HereDocument() string {
	var big strings.Builder
	big.WriteString("cat > notes.txt <<'EOF'\n")
	for i := 0; big.Len() < 1<<20-64; i++ {
		fmt.Fprintf(&big, "benign note line %d: nothing to see here\n", i)
	}
	big.WriteString("EOF\n")
	return big.String()
}

// TestGAP0299CountedWorkPerCall bounds the counted work of one cold hook
// call (a command no earlier call sent) on the 1 MiB here-document, OpenClaw
// exec route, default pack (rel-1-0-10:GAP-0299). The counts are work, not
// time: full parses of the large command, decodes of the large request
// arguments, lower-cased copies of the large text, memo key builds per memo
// walk and file lookups per walk.
func TestGAP0299CountedWorkPerCall(t *testing.T) {
	a := gap0437Server(t, gap0437Packs[0], "openclaw", "action")
	a.inspectToolScanTimeout = time.Minute
	dir := t.TempDir()
	body := gap0299HereDocument()
	call := func(seq int) string {
		raw, err := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": fmt.Sprintf("%s# gap0299 counted call %d %d\n", body, seq, time.Now().UnixNano()), "workdir": dir}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.handleInspectTool(rec, req)
		return rec.Body.String()
	}
	call(0) // warm the process: rule packs, compiled tables
	before := workcount.Take()
	verdict := call(1)
	got := map[string]int64{
		"parses":  before.Since(workcount.LargeParse),
		"decodes": before.Since(workcount.ArgsDecode),
		"lowers":  before.Since(workcount.TextLower),
		"walks":   before.Since(workcount.MemoWalk),
		"keys":    before.Since(workcount.WalkKey),
		"lookups": before.Since(workcount.WordLookup),
		"regexes": before.Since(workcount.RegexRun),
	}
	t.Logf("COUNTED %v verdict=%.160s", got, verdict)
	if strings.Contains(verdict, `"action":"block"`) {
		t.Fatalf("benign here-document verdict = %.300s", verdict)
	}
	if got["parses"] > gap0299MaxLargeParses {
		t.Errorf("full parses of the 1 MiB command in one call = %d, bound %d", got["parses"], gap0299MaxLargeParses)
	}
	if got["decodes"] > gap0299MaxArgsDecodes {
		t.Errorf("decodes of the 1 MiB arguments in one call = %d, bound %d", got["decodes"], gap0299MaxArgsDecodes)
	}
	if got["lowers"] > gap0299MaxTextLowers {
		t.Errorf("lower-cased copies of the 1 MiB text in one call = %d, bound %d", got["lowers"], gap0299MaxTextLowers)
	}
	if got["walks"] > gap0299MaxMemoWalks {
		t.Errorf("write-target walks in one call = %d, bound %d (one per distinct word)", got["walks"], gap0299MaxMemoWalks)
	}
	if got["lookups"] > gap0299MaxWordLookups {
		t.Errorf("file lookups of resolved words in one call = %d, bound %d (one per distinct word)", got["lookups"], gap0299MaxWordLookups)
	}
	if got["regexes"] > gap0299MaxRegexRuns {
		t.Errorf("rule regex runs over a large text in one call = %d, bound %d", got["regexes"], gap0299MaxRegexRuns)
	}
	if got["walks"] > 0 && got["keys"] > 2*got["walks"] {
		t.Errorf("memo key builds = %d for %d memo walks, bound 2 per walk", got["keys"], got["walks"])
	}
}

// The bounds of one cold call; each count was above it at a64bfdb931
// (memo key builds: 14 per walk).
const (
	gap0299MaxLargeParses = 2 // 7 at a64bfdb931
	gap0299MaxArgsDecodes = 7 // 11 at a64bfdb931
	gap0299MaxTextLowers  = 2 // 24 at a64bfdb931
	// The here-document has 24,099 distinct words; each is walked and read
	// once per call (two evaluations walked each, the state scan read each
	// again).
	gap0299MaxMemoWalks   = 25000 // 48,238 at a64bfdb931
	gap0299MaxWordLookups = 25000
	gap0299MaxRegexRuns   = 26 // 31 at a64bfdb931
)
