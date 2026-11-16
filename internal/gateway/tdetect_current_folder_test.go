// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// tdCurrentFolderHeads are the spellings of the current folder before a
// slash ($PWD, ${PWD}, "$PWD", $(pwd), `pwd`, "$(pwd)", ~+), built from
// their parts (rel-1-0-10:GAP-1023, GAP-1024).
func tdCurrentFolderHeads() []string {
	param, subst := "$"+"PWD", "$("+"pwd)"
	return []string{param, "${" + "PWD}", `"` + param + `"`, subst, "`" + "pwd`", `"` + subst + `"`, "~" + "+"}
}

// tdCurrentFolderVerdict is the verdict of command through the Claude Code
// hook handler in cwd, and whether the answer names the items cap.
func tdCurrentFolderVerdict(t *testing.T, a *APIServer, session, cwd, command string) (string, bool) {
	t.Helper()
	out := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
		"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd,
		"tool_name": "Bash", "tool_use_id": "tu-" + command, "tool_input": map[string]any{"command": command},
	})
	raw, _ := json.Marshal(out)
	action, _ := out["action"].(string)
	return map[string]string{"allow": "A", "alert": "L", "block": "B"}[action],
		strings.Contains(string(raw), bounded.ReasonCode+" cap="+bounded.Items.String())
}

// TestUnresolvedFolderCurrentFolderSpellingIsThePlainOne is
// rel-1-0-10:GAP-1023 (cells of the s7-td327r3rev2 probe TestTD3RV2Pfx).
// After a cd to a folder the call does not give (an unset variable,
// $(mktemp -d)), and in a call with no folder from the agent at all, an
// operand spelled from the current folder ($PWD/, ${PWD}/,
// "$PWD"/, $(pwd)/, `pwd`/, "$(pwd)"/, ~+/) is the operand of the GAP-0960,
// GAP-0961 and GAP-1003 tables in that folder: in each of the 5 packs it
// gets the verdict of its plain spelling (the unknown tier for a key, a
// key pattern, the AWS credentials file and a DefenseClaw state write), and
// a wide pattern names the cap exactly when its plain spelling does. A
// listing stays the plain listing (allowed). A DefenseClaw state write so
// spelled is never below its plain spelling: the reading of the whole call
// blocks a state write spelled from a variable outside strict, where the
// plain one is the unknown tier (the same at 1f15b84781 and rel
// 4269debe92). The plain verdict is the oracle, read at run time; the rows
// below pin that it is the tier. One test per pack: the five take 556 s
// under -race together, more than one CI shard's budget can hold.
func TestUnresolvedFolderCurrentFolderSpellingIsThePlainOneDefault(t *testing.T) {
	tdCurrentFolderSpellingIsThePlainOne(t, "default")
}

func TestUnresolvedFolderCurrentFolderSpellingIsThePlainOneStrict(t *testing.T) {
	tdCurrentFolderSpellingIsThePlainOne(t, "strict")
}

func TestUnresolvedFolderCurrentFolderSpellingIsThePlainOnePermissive(t *testing.T) {
	tdCurrentFolderSpellingIsThePlainOne(t, "permissive")
}

func TestUnresolvedFolderCurrentFolderSpellingIsThePlainOneManaged(t *testing.T) {
	tdCurrentFolderSpellingIsThePlainOne(t, "managed")
}

func TestUnresolvedFolderCurrentFolderSpellingIsThePlainOneManagedStrict(t *testing.T) {
	tdCurrentFolderSpellingIsThePlainOne(t, "managed-strict")
}

// tdCurrentFolderSpellingIsThePlainOne runs the cells of
// TestUnresolvedFolderCurrentFolderSpellingIsThePlainOne* in one pack.
func tdCurrentFolderSpellingIsThePlainOne(t *testing.T, pack string) {
	_, project := cdFirstFixture(t)
	dot := "."
	reads := []string{dot + "ssh/id_rsa", dot + "aws/credentials", dot + "ssh/*", dot + "ssh/id_*", dot + "aws/cred*",
		dot + "*/*", dot + "[a-z]*/*", dot + "ssh/./id_rsa"}
	verbs := []string{"cat %s", "base64 %s", "mv %s /tmp/staged", "rm -f %s", "ls -d %s"}
	writes := []string{"echo x >> %s", "echo x > %s"}
	state := []string{dot + "defenseclaw/config.yaml", dot + "defenseclaw/hooks/h.sh"}
	type cell struct {
		cwd, plain, spelled string
		floorOnly           bool // a state write: at least the plain verdict
	}
	var cells []cell
	for _, cd := range []string{"cd \"$TD327_UNSET\" && ", "cd -- \"$(mktemp -d)\" && ", ""} {
		cwd := project
		if cd == "" {
			cwd = "" // no folder from the agent
		}
		add := func(verb, operand string) {
			for _, head := range tdCurrentFolderHeads() {
				cells = append(cells, cell{cwd, cd + strings.Replace(verb, "%s", operand, 1),
					cd + strings.Replace(verb, "%s", head+"/"+operand, 1), strings.HasPrefix(verb, "echo ")})
			}
		}
		for _, operand := range reads {
			for _, verb := range verbs {
				add(verb, operand)
			}
		}
		for _, operand := range state {
			for _, verb := range writes {
				add(verb, operand)
			}
		}
	}
	judged := false
	for _, p := range gap0437Packs {
		if p.name != pack {
			continue
		}
		judged = true
		a := gap0437Server(t, p, "claudecode", "action")
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		session := "td-cur-" + p.name
		plain := map[string][2]any{}
		for _, c := range cells {
			key := c.cwd + "|" + c.plain
			if _, ok := plain[key]; !ok {
				got, capped := tdCurrentFolderVerdict(t, a, session, c.cwd, c.plain)
				plain[key] = [2]any{got, capped}
			}
			want := plain[key]
			got, capped := tdCurrentFolderVerdict(t, a, session, c.cwd, c.spelled)
			if got != want[0] && (!c.floorOnly || cdFirstRank[got] < cdFirstRank[want[0].(string)]) || capped != want[1] {
				t.Errorf("%s: %q (cwd %q) is %s (cap named %v), the plain %q is %s (cap named %v)",
					p.name, c.spelled, c.cwd, got, capped, c.plain, want[0], want[1])
			}
		}
		// The oracle is the tier for the protected operands, and a wide
		// pattern names the cap (GAP-0960, GAP-0961, GAP-1003).
		for _, operand := range []string{dot + "ssh/id_rsa", dot + "aws/credentials", dot + "ssh/id_*", dot + "*/*"} {
			for _, key := range []string{project + "|cd \"$TD327_UNSET\" && cat " + operand, "|cat " + operand} {
				if got := plain[key][0]; cdFirstRank[got.(string)] < cdFirstRank[tier] {
					t.Errorf("%s: the plain %q is %s, want at least %s", p.name, key, got, tier)
				}
			}
		}
		if capped := plain[project+"|cd \"$TD327_UNSET\" && cat "+dot+"*/*"][1]; capped != true {
			t.Errorf("%s: the plain wide pattern does not name the cap", p.name)
		}
	}
	if !judged {
		t.Fatalf("no pack %q", pack)
	}
}

// TestKnownFolderPwdSpellingIsThePlainOne is rel-1-0-10:GAP-1024 (cells of
// TestTD3RV2Pfx): after cd .. from the project into the home, $(pwd)/,
// `pwd`/ and "$(pwd)"/ before a protected file are that folder, as $PWD/ is:
// the key file, the AWS credentials file and a DefenseClaw config write get
// at least the verdict of the $PWD/ spelling and of the plain spelling in
// each of the 5 packs (rel read the substitution as no folder and allowed),
// and the verdict of the $PWD/ spelling for every read and write. A copy of
// the credentials file so spelled is a block where the $PWD/ spelling
// alerts: the reading of the whole call (the same at 1f15b84781 and rel).
func TestKnownFolderPwdSpellingIsThePlainOne(t *testing.T) {
	home, project := cdFirstFixture(t)
	if err := os.MkdirAll(filepath.Join(home, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	dot := "."
	commands := []string{"cat %s", "base64 %s", "cp %s /tmp/staged"}
	operands := []string{dot + "ssh/id_rsa", "./" + dot + "ssh/id_rsa", "x/../" + dot + "ssh/id_rsa", dot + "aws/credentials"}
	type cell struct{ plain, param, spelled string }
	var cells []cell
	param := tdCurrentFolderHeads()[0]
	add := func(head, verb, operand string) {
		cells = append(cells, cell{"cd .. && " + strings.Replace(verb, "%s", operand, 1),
			"cd .. && " + strings.Replace(verb, "%s", param+"/"+operand, 1),
			"cd .. && " + strings.Replace(verb, "%s", head+"/"+operand, 1)})
	}
	for _, head := range tdCurrentFolderHeads()[3:6] {
		for _, operand := range operands {
			for _, verb := range commands {
				add(head, verb, operand)
			}
		}
		for _, verb := range []string{"echo x >> %s", "rm -f %s"} {
			add(head, verb, dot+"defenseclaw/config.yaml")
		}
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		session := "td-pwd-" + p.name
		blocked := 0
		for _, c := range cells {
			plain, _ := tdCurrentFolderVerdict(t, a, session, project, c.plain)
			want, _ := tdCurrentFolderVerdict(t, a, session, project, c.param)
			got, _ := tdCurrentFolderVerdict(t, a, session, project, c.spelled)
			copied := strings.Contains(c.spelled, " cp ")
			if got != want && !copied || cdFirstRank[got] < cdFirstRank[want] || cdFirstRank[got] < cdFirstRank[plain] {
				t.Errorf("%s: %q is %s, the %s spelling %q is %s, the plain %q is %s", p.name, c.spelled, got, param, c.param, want, c.plain, plain)
			}
			if plain != "A" {
				blocked++
			}
		}
		if blocked == 0 {
			t.Errorf("%s: every plain spelling is allowed; the oracle names nothing", p.name)
		}
	}
}
