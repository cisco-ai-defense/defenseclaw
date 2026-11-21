// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// listPrefixHookPost sends command as the tool call tool of connector's hook route
// and returns the action and the rule IDs of the answer.
func listPrefixHookPost(t *testing.T, a *APIServer, connector, tool, command string, managedPeer bool) (string, string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0348", "cwd": `C:\work`,
		"tool_name": tool, "tool_use_id": "tu-gap0348", "tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", "PreToolUse", raw))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managedPeer {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: `C:\Users\alice`}))
	}
	w := httptest.NewRecorder()
	a.handleAgentHook(connector).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s: status %d: %s", connector, tool, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: answer %q: %v", connector, w.Body.String(), err)
	}
	action, _ := out["action"].(string)
	return action, w.Body.String()
}

// listPrefixFindingRules are the rule IDs of a hook answer's findings.
func listPrefixFindingRules(t *testing.T, raw string) []string {
	t.Helper()
	var out struct {
		Findings []string `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	rules := make([]string, 0, len(out.Findings))
	for _, finding := range out.Findings {
		rule, _, _ := strings.Cut(finding, ":")
		rules = append(rules, rule)
	}
	return rules
}

// listPrefixActionRank orders hook actions by strength.
func listPrefixActionRank(action string) int {
	switch action {
	case "block", "deny":
		return 2
	case "alert", "warn", "ask":
		return 1
	}
	return 0
}

// TestGAP0348TrailingStatementKeepsTheVerdictFiveTiers pins
// rel-1-0-10:GAP-0348. On a Windows hook the dialect selection places
// `<attack> ; echo done` in no dialect: its POSIX reading is complete but
// places no .git/config under a Windows folder, and its PowerShell reading is
// partial with no readable-statements reading, so a trailing benign statement
// hid the git read writing .git/config (and the fork bomb on Claude Code's
// Git Bash tool). The list cut before each later statement is read as the
// hook reads that call (windowsListPrefixTwinRequests): the wrapped call gets
// the verdict of the attack alone, in the five tiers, on the Codex shell and
// Claude Code's Bash tool, behind one trailer or a run of them
// (rel-1-0-10:GAP-1569), and for a native Windows program whose own POSIX
// reading is partial (the GAP-1561 fixtures). Benign lists a developer runs
// keep their verdict (no new finding in default and permissive), a
// here-document list included (rel-1-0-10:GAP-1570).
func TestGAP0348TrailingStatementKeepsTheVerdictFiveTiers(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	type row struct{ connector, tool, attack, wrapped string }
	attacks := []row{
		{"codex", "Bash", "git show --output=.git/config HEAD", "git show --output=.git/config HEAD ; echo done"},
		{"codex", "Bash", "git show --output=.git/config HEAD", "git show --output=.git/config HEAD\necho done"},
		{"codex", "Bash", "git show --output=.git/config HEAD", "git show --output=.git/config HEAD && echo ok"},
		{"codex", "Bash", "git -C project show --output=.git/config HEAD", "git -C project show --output=.git/config HEAD ; echo done"},
		{"codex", "Bash", ":(){ :|:& };:", ":(){ :|:& };: ; echo done"},
		// A Bash call Git Bash reads alone is placed in POSIX on a Windows
		// host (hookpaths.GitBashReadsAlone) and keeps the POSIX reading, as
		// on Linux and macOS (rel-1-0-10:GAP-1561); a PowerShell spelling in
		// the trailer keeps the call in no dialect.
		{"claudecode", "Bash", ":(){ :|:& };:", ":(){ :|:& };: ; Write-Output done"},
		{"codex", "Bash", ":(){ :|:& };:", ":(){ :|:& };: ; echo a ; echo b"},
		{"claudecode", "Bash", ":(){ :|:& };:", ":(){ :|:& };: ; Write-Output a ; Write-Output b"},
	}
	// Native Windows programs whose own POSIX reading is partial (a Windows
	// path or quoting the POSIX model cannot place): by corpus id.
	nativePartial := map[string]bool{"windows-procdump-lsass": true, "windows-usn-journal-delete-powershell": true,
		"windows-recursive-everyone-full-control": true}
	for _, c := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if nativePartial[c.ID] {
			delete(nativePartial, c.ID)
			attacks = append(attacks, row{"codex", "Bash", c.Command, c.Command + " ; echo done"},
				row{"codex", "Bash", c.Command, c.Command + " ; echo a ; echo b"})
		}
	}
	if len(nativePartial) != 0 {
		t.Fatalf("corpus fixtures missing: %v", nativePartial)
	}
	benign := []string{
		"git status; echo done",
		"git log -1 ; echo done",
		"make build && make test",
		"cd x && ls; pwd",
		"npm test || echo failed",
		"git diff --stat HEAD; git status",
		"git fetch; git status; git log -1",
		"npm ci && npm run build && npm test",
		"cat <<EOF > notes.txt ; echo done\nhello\nEOF",
	}
	for _, p := range gap0437Packs {
		for _, connector := range []string{"codex", "claudecode"} {
			a := gap0437Server(t, p, connector, "action")
			for _, r := range attacks {
				if r.connector != connector {
					continue
				}
				bare, bareRaw := listPrefixHookPost(t, a, connector, r.tool, r.attack, p.managed)
				bareRules := listPrefixFindingRules(t, bareRaw)
				if len(bareRules) == 0 {
					t.Fatalf("%s %s %q: the attack alone is %q with no finding, the row proves nothing: %.300s", p.name, connector, r.attack, bare, bareRaw)
				}
				wrapped, raw := listPrefixHookPost(t, a, connector, r.tool, r.wrapped, p.managed)
				wrappedRules := listPrefixFindingRules(t, raw)
				if listPrefixActionRank(wrapped) < listPrefixActionRank(bare) {
					t.Errorf("%s %s %q: %q, want %q as alone: %.400s", p.name, connector, r.wrapped, wrapped, bare, raw)
				}
				for _, rule := range bareRules {
					if !slices.Contains(wrappedRules, rule) {
						t.Errorf("%s %s %q: no %s finding, which the attack alone has: %.400s", p.name, connector, r.wrapped, rule, raw)
					}
				}
			}
			if p.name != "default" && p.name != "permissive" {
				continue
			}
			for _, command := range benign {
				if action, raw := listPrefixHookPost(t, a, connector, "Bash", command, p.managed); listPrefixActionRank(action) != 0 ||
					len(listPrefixFindingRules(t, raw)) != 0 {
					t.Errorf("%s %s benign %q: %q: %.400s", p.name, connector, command, action, raw)
				}
			}
		}
	}
}

// TestGAP0348ListPrefixReadingBound: the list-prefix readings are those of a
// Windows hook call placed in no dialect whose POSIX list has two or more
// statements, one per cut before a later statement, at most
// windowsListPrefixMaxReadings and truncated past them; never a reading
// twin's, a single statement's, a cut inside a here-document, a call placed
// in a dialect, or a Linux or macOS hook call (no Windows readings).
func TestGAP0348ListPrefixReadingBound(t *testing.T) {
	for _, c := range []struct {
		command  string
		prefixes []string
	}{
		{"a ; b", []string{"a"}},
		{"a\nb", []string{"a"}},
		{"a && b", []string{"a"}},
		{"a || b", []string{"a"}},
		{"a; b && c", []string{"a; b", "a"}},
		{"a && b; c", []string{"a && b", "a"}},
		{"a && b && c", []string{"a && b", "a"}},
		{"a ; b ; c", []string{"a ; b", "a"}},
		{":(){ :|:& };: ; echo done", []string{":(){ :|:& };:", ":(){ :|:& }"}},
		{"a & b", []string{"a &"}},
		{"a", nil},
		{"a | b", nil},
		{"! a && b", []string{"! a"}},
		{"! (a && b)", nil},
		{"(a; b)", nil},
		{"{ a; b; }", nil},
		{"if a; then b; fi", nil},
		{"a 'b", nil},
		{"cat <<EOF > f ; echo done\nhi\nEOF", nil},
		{"cat <<EOF > f\nhi\nEOF\necho done", []string{"cat <<EOF > f\nhi\nEOF"}},
	} {
		if got := posixListPrefixes(c.command); !slices.Equal(got, c.prefixes) {
			t.Errorf("posixListPrefixes(%q) = %q; want %q", c.command, got, c.prefixes)
		}
	}
	list := func(n int) string {
		statements := make([]string, n)
		for i := range statements {
			statements[i] = fmt.Sprintf("echo %d", i)
		}
		return strings.Join(statements, " ; ")
	}
	if got := posixListPrefixes(list(200)); len(got) != 199 || got[0] != list(199) || got[198] != list(1) {
		t.Errorf("200 statements: %d prefixes", len(got))
	}
	request := func(command string) trustedActionRequest {
		args, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		return trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Args: args, CWD: `C:\work`}}
	}
	call := request("git show --output=.git/config HEAD ; echo done")
	if twins, cut := windowsListPrefixTwinRequests(call, actionfacts.Analyze(call.Input)); len(twins) != 0 || cut.Any() {
		t.Error("a call with no Windows readings (a Linux or macOS hook) has a list-prefix reading")
	}
	withWindowsShellDialect(&call, true)
	twins, cut := windowsListPrefixTwinRequests(call, actionfacts.Analyze(call.Input))
	if len(twins) != 1 || cut.Any() || twins[0].Input.Command != "git show --output=.git/config HEAD" || !twins[0].readingTwin ||
		twins[0].Input.DialectHint != actionfacts.DialectPowerShell {
		t.Fatalf("Windows hook call: %d twins, cut %v: %+v", len(twins), cut.Any(), twins)
	}
	if again, _ := windowsListPrefixTwinRequests(twins[0], actionfacts.Analyze(twins[0].Input)); len(again) != 0 {
		t.Error("a reading twin makes a list-prefix reading of its own")
	}
	placed := call
	placed.Input.DialectHint = actionfacts.DialectPOSIX
	if again, _ := windowsListPrefixTwinRequests(placed, actionfacts.Analyze(placed.Input)); len(again) != 0 {
		t.Error("a call placed in a dialect has a list-prefix reading")
	}
	// A benign list of any length within the statement budget is read at
	// the ends of its key runs, never truncated (rel-1-0-10:GAP-1587); a
	// call over the budget is refused whole and has none.
	for _, n := range []int{10, 64, 128} {
		long := request(list(n))
		withWindowsShellDialect(&long, true)
		if twins, cut := windowsListPrefixTwinRequests(long, actionfacts.Analyze(long.Input)); len(twins) > 2 || cut.Any() {
			t.Errorf("a benign list of %d statements: %d twins, cut %v", n, len(twins), cut.Any())
		}
	}
	over := request(list(200))
	withWindowsShellDialect(&over, true)
	if twins, cut := windowsListPrefixTwinRequests(over, actionfacts.Analyze(over.Input)); len(twins) != 0 || cut.Any() {
		t.Errorf("a call over the statement budget: %d twins, cut %v", len(twins), cut.Any())
	}
}

// TestGAP1587ListPrefixRunEnds: windowsListPrefixRunEnds returns the last
// prefix of every run of one key except the run ending at the call, found by
// sampling and bisection, and caps (ONE BOUND RULE) when the key budget stops
// the search.
func TestGAP1587ListPrefixRunEnds(t *testing.T) {
	keyOf := func(pattern string) func(int) windowsListPrefixKey {
		return func(index int) windowsListPrefixKey {
			return windowsListPrefixKey{dialect: actionfacts.Dialect(pattern[index : index+1])}
		}
	}
	whole := func(pattern string) windowsListPrefixKey {
		return windowsListPrefixKey{dialect: actionfacts.Dialect(pattern[len(pattern)-1:])}
	}
	for _, c := range []struct {
		pattern string // keys of prefixes 0..count-1, then the call
		ends    []int
	}{
		{"ab", []int{0}},
		{"aa", nil},
		{"abbbbbbbbb", []int{0}},
		{"aaaaaaaaab", []int{8}},
		{"aaaaabbbbb", []int{4}},
		{"abbbbbbbbbbbbbbbbbbbbbbbbbbbbbba", []int{30, 0}},
		{"aaabbbccca", []int{8, 5, 2}},
	} {
		count := len(c.pattern) - 1
		computed := 0
		key := keyOf(c.pattern)
		ends, capped := windowsListPrefixRunEnds(count, whole(c.pattern), func(i int) windowsListPrefixKey { computed++; return key(i) }, windowsListPrefixMaxKeys)
		if !slices.Equal(ends, c.ends) || capped {
			t.Errorf("%s: ends %v capped %v; want %v", c.pattern, ends, capped, c.ends)
		}
		if computed > 2*listPrefixBits(count)+8 {
			t.Errorf("%s: %d keys", c.pattern, computed)
		}
	}
	if ends, capped := windowsListPrefixRunEnds(9, whole("aaabbbccca"), keyOf("aaabbbccca"), 7); !capped || len(ends) == 0 {
		t.Errorf("a search stopped by the key budget: ends %v, capped %v; want the items cap", ends, capped)
	}
}

func listPrefixBits(n int) int {
	b := 0
	for ; n > 0; n >>= 1 {
		b++
	}
	return b
}
