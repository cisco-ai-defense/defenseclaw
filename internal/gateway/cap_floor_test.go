// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The cap floor (cap_floor.go). The writes are existing fixtures, loaded by
// case id: the state write of the bound-rule shell lanes (boundedShellSeen),
// the tool-call corpus case authorized-keys-command-home-relative, and the
// ACP parity case gap/p0-round_GAP-1024/087. The fillers that put a call past
// a cap are generated.

// capFloorCorpusCommand is the command of a tool-call corpus case.
func capFloorCorpusCommand(t *testing.T, id string) string {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "security_suite", "toolcall", "corpus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for scanner.Scan() {
		var row struct{ ID, Command string }
		if json.Unmarshal(scanner.Bytes(), &row) == nil && row.ID == id {
			return row.Command
		}
	}
	t.Fatalf("tool-call corpus case %s not found", id)
	return ""
}

// capFloorParityCommand is the shell command of an ACP parity case.
func capFloorParityCommand(t *testing.T, id string) string {
	t.Helper()
	for _, c := range loadACPParityCases(t) {
		if c.ID != id {
			continue
		}
		var args struct{ Command string }
		if err := json.Unmarshal(c.Args, &args); err != nil || args.Command == "" {
			t.Fatalf("parity case %s has no command", id)
		}
		return args.Command
	}
	t.Fatalf("parity case %s not found", id)
	return ""
}

// capFloorFillers put a call past one cap each: nesting (subshells, command
// substitutions, brace groups, also inside a double-quoted string and after
// an escaped blank), the reading budget (chain operators, tokens), the
// statement budget and the syntax depth bound of the action analysis
// (rel-1-0-10:GAP-0547: 30 to 512 nested subshells, no finding on rel).
var capFloorFillers = []struct {
	name  string
	build func(inner string) string
}{
	{"nest-paren/513", func(in string) string { return strings.Repeat("(", 513) + in + strings.Repeat(")", 513) }},
	{"nest-subst/513", func(in string) string { return "echo " + strings.Repeat("$(", 513) + in + strings.Repeat(")", 513) }},
	{"nest-brace/513", func(in string) string { return strings.Repeat("{ ", 513) + in + strings.Repeat("; }", 513) }},
	{"pipe/513", func(string) string { return strings.Repeat("a|", 513) + "a" }},
	{"pipe/129", func(string) string { return strings.Repeat("a|", 129) + "a" }},
	{"words/131073", func(string) string { return "echo " + strings.Repeat("a ", 131073) }},
	{"nest-dq-subst/600", func(in string) string {
		return "echo \"a " + strings.Repeat("$(", 600) + in + strings.Repeat(")", 600) + "\""
	}},
	{"nest-escaped-blank/600", func(in string) string {
		return "echo a\\ #" + strings.Repeat("$(", 600) + in + strings.Repeat(")", 600)
	}},
}

func init() {
	// GAP-0547: the analysis depth bound, under the shell nesting budget.
	for _, n := range []int{30, 64, 128, 256, 512} {
		capFloorFillers = append(capFloorFillers, struct {
			name  string
			build func(inner string) string
		}{fmt.Sprintf("nest-paren/%d", n), func(in string) string {
			return strings.Repeat("(", n) + in + strings.Repeat(")", n)
		}})
	}
}

// The analysis depth bound is a lane of the bound rule (rel-1-0-10:GAP-0547,
// GAP-0688) for every call: its plain input is a write to a home file named at
// run time inside the nest (alone it is an ordinary write, allowed; past the
// bound the readers no longer see it). Its limit is the deepest subshell nest
// the action analysis still reads.
func init() {
	fill := func(size int) string {
		return strings.Repeat("(", size) + `printf done > "$HOME/$OUT"` + strings.Repeat(")", size)
	}
	registerBoundedLane(boundedLaneCap{lane: "shell analysis depth", cap: bounded.Depth, limit: capFloorAnalysisDepthLimit(fill),
		gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
			if shape.nested || shape.multi {
				return boundedLaneCall{}, false
			}
			return boundedShellLane(fill, fill)(size, shape)
		},
		seen: boundedShellSeenCall})
}

// capFloorAnalysisDepthLimit is the largest n for which the action analysis
// reads fill(n).
func capFloorAnalysisDepthLimit(fill func(int) string) int {
	for n := 1; n < shellparse.MaxNestingDepth; n++ {
		input := actionfacts.Input{Tool: "Bash", Command: fill(n)}
		if capFloorAnalysisCaps(input, actionfacts.Analyze(input)).Any() {
			return n - 1
		}
	}
	return shellparse.MaxNestingDepth
}

// capFloorShellBodies put the write inside the script of a shell, behind a
// pipe chain of n stages.
var capFloorShellBodies = []struct {
	name  string
	build func(n int, inner string) string
}{
	{"bash-heredoc", func(n int, in string) string {
		return "bash <<'EOF'\n" + strings.Repeat("a|", n) + "a\n" + in + "\nEOF"
	}},
	{"sudo-bash-heredoc", func(n int, in string) string {
		return "sudo bash <<'EOF'\n" + strings.Repeat("a|", n) + "a\n" + in + "\nEOF"
	}},
	{"bash-c", func(n int, in string) string {
		return "bash -c '" + strings.Repeat("a|", n) + "a; " + strings.ReplaceAll(in, "'", `'\''`) + "'"
	}},
	{"sudo-bash-c", func(n int, in string) string {
		return "sudo bash -c '" + strings.Repeat("a|", n) + "a; " + strings.ReplaceAll(in, "'", `'\''`) + "'"
	}},
}

// TestCapFloorKeepsProvenBlocks: a write proven on its own keeps its block,
// with its rule id, in every tier when a nesting, reading or statement cap is
// hit before it, after it or around it, or when it sits in the script of a
// shell (rel-1-0-10:GAP-0312, GAP-0360, GAP-0435, GAP-0381, GAP-0532).
func TestCapFloorKeepsProvenBlocks(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	writes := []struct{ name, command string }{
		{"state", boundedShellSeen},
		{"keys", capFloorCorpusCommand(t, "authorized-keys-command-home-relative")},
	}
	type row struct{ id, command, write string }
	var rows []row
	for _, w := range writes {
		for _, f := range capFloorFillers {
			rows = append(rows,
				row{f.name + "/" + w.name + "/before", w.command + "; " + f.build("true"), w.name},
				row{f.name + "/" + w.name + "/after", f.build("true") + "; " + w.command, w.name})
			if strings.HasPrefix(f.name, "nest-") {
				rows = append(rows, row{f.name + "/" + w.name + "/inside", f.build(w.command), w.name})
			}
		}
		for _, b := range capFloorShellBodies {
			for _, n := range []int{0, 511, 600, 2100} {
				rows = append(rows, row{fmt.Sprintf("%s/%d/%s/inside", b.name, n, w.name), b.build(n, w.command), w.name})
			}
		}
	}
	// GAP-0381: the keys write of fixture 087 with a trailing comment, as the
	// ACP guard keeps the command (cut to 8 KiB), and longer.
	fixture := capFloorParityCommand(t, "gap/p0-round_GAP-1024/087")
	for _, size := range []int{4096, 8192, 16384, 70000} {
		command := fixture + "\n# " + strings.Repeat("x", size)
		if size == 8192 {
			command = command[:8<<10]
		}
		rows = append(rows, row{fmt.Sprintf("fixture-087/comment-%d", size), command, "087"})
	}
	seen := map[string]string{"state": writes[0].command, "keys": writes[1].command, "087": fixture}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		alone := map[string]bounded.Action{}
		aloneRules := map[string][]string{}
		for name, command := range seen {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			wantAlone := bounded.Block
			if name == "state" {
				wantAlone = gap0747StateWriteAction(tier.tier)
			}
			if alone[name] = boundedParse(action); alone[name] != wantAlone {
				t.Fatalf("%s: the %s write alone is %s, want %s", tier.name, name, action, wantAlone)
			}
			aloneRules[name] = capFloorRuleIDs(findings)
		}
		for _, r := range rows {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(r.command))
			if got := boundedParse(action); got < alone[r.write] {
				t.Errorf("%s %s: action=%s, want %s (the write alone); findings=%v", tier.name, r.id, action, alone[r.write], findings)
				continue
			}
			rules := capFloorRuleIDs(findings)
			for _, id := range aloneRules[r.write] {
				if id != evaluationLimitRuleID && !slices.Contains(rules, id) {
					t.Errorf("%s %s: the block lost rule %s of the write alone: %v", tier.name, r.id, id, findings)
				}
			}
		}
	}
}

// TestCapFloorObserveKeepsTheStateBlock: observe mode allows every finding
// but a proven write to the DefenseClaw state, which blocks in every mode; a
// cap around the write or a shell script it sits in does not change that
// (GAP-0360, GAP-0532).
func TestCapFloorObserveKeepsTheStateBlock(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "observe", "HIGH", "default")
	commands := map[string]string{"alone": boundedShellSeen}
	for _, f := range capFloorFillers {
		commands[f.name+"/after"] = f.build("true") + "; " + boundedShellSeen
	}
	for _, b := range capFloorShellBodies {
		for _, n := range []int{0, 600, 2100} {
			commands[fmt.Sprintf("%s/%d/inside", b.name, n)] = b.build(n, boundedShellSeen)
		}
	}
	for id, command := range commands {
		if action := gap0568HookAction(t, api, "claudecode", env.home, env.cwd, command, true, false); action != "block" {
			t.Errorf("observe %s: action=%s, want block", id, action)
		}
	}
}

// TestCapFloorCapAloneKeepsItsVerdict: a call past a cap that names no
// protected target or state keeps the unknown tier of its pack and no more
// (an alert outside strict), a shell script that writes none is not
// blocked, and reads of a protected folder beside a cap are not blocks.
func TestCapFloorCapAloneKeepsItsVerdict(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	commands := map[string]string{}
	for _, f := range capFloorFillers {
		commands[f.name] = f.build("true")
		commands[f.name+"/listing"] = strings.Repeat("ls ~/.ssh; ", 17) + f.build("true")
	}
	plain := map[string]string{}
	for _, b := range capFloorShellBodies {
		plain[b.name] = b.build(2, "echo done")
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, f := range capFloorFillers {
			for _, id := range []string{f.name, f.name + "/listing"} {
				// Every cap, the analysis depth bound included, is the unknown
				// tier of the pack for a call that names no target, and a read
				// beside it is not a block (GAP-0688).
				want := bounded.Unknown(tier.tier)
				action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(commands[id]))
				if got := boundedParse(action); got != want {
					t.Errorf("%s %s: action=%s, want %s; findings=%v", tier.name, id, action, want, findings)
				}
			}
		}
		if tier.tier == bounded.TierStrict {
			continue
		}
		for id, command := range plain {
			if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); boundedParse(action) == bounded.Block {
				t.Errorf("%s %s: a script that writes no protected target blocks; findings=%v", tier.name, id, findings)
			}
		}
	}
}

// capFloorRuleIDs are the rule ids of hook findings ("RULE:title").
func capFloorRuleIDs(findings []string) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		id, _, _ := strings.Cut(strings.TrimPrefix(finding, "codeguard:"), ":")
		ids = append(ids, id)
	}
	return ids
}

// TestCapFloorPieces: the cut of a call into statements and shell scripts.
func TestCapFloorPieces(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string // statements; a shell script is prefixed "body:", one fed on standard input "fed:"
	}{
		{"a; b && c || d | e & f", []string{"a", "b", "c", "d", "d | e", "e", "f"}},
		{"( ( x ) ); { y; }", []string{"x", "y"}},
		{"echo $(y $(z))", []string{"echo", "y", "z"}},
		{"echo `y`", []string{"echo", "y"}},
		{"x 2>&1 | y &> z", []string{"x 2>&1", "x 2>&1 | y &> z", "y &> z"}},
		{"echo ${HOME}/a a{b,c}", []string{"echo ${HOME}/a a{b,c}"}},
		{"echo 'a; b' \"c; d\"", []string{"echo 'a; b' \"c; d\""}},
		{"a # b; c\nd", []string{"a", "d"}},
		{"if x; then y; fi", []string{"x", "y"}},
		{"echo \"a $(b; c) d\" e", []string{"echo \"a", "b", "c", "d\" e"}},
		{"echo a\\ #$(b)", []string{"echo a\\ #", "b"}},
		{"echo a \\\n#b; c\nd", []string{"echo a \\", "d"}},
		{"bash -c 'p; q'", []string{"bash -c 'p; q'", "body:p; q"}},
		{"sudo -n bash -lc 'p'\\''s; q'", []string{"sudo -n bash -lc 'p'\\''s; q'", "body:p's; q"}},
		{"echo -c 'p; q'", []string{"echo -c 'p; q'"}},
		{"bash <<'EOF'\np\nq\nEOF\nr", []string{"bash <<'EOF'", "fed:p\nq", "r"}},
		{"sudo bash -s <<-EOF\n\tp\n\tEOF\nr", []string{"sudo bash -s <<-EOF", "fed:p", "r"}},
		{"cat <<EOF > notes\np; q\nEOF\nr", []string{"cat <<EOF > notes", "r"}},
		{"bash script.sh <<EOF\np\nEOF", []string{"bash script.sh <<EOF"}},
		{"cat <<< 'p; q'", []string{"cat <<< 'p; q'"}},
		// A -c option or a shell name built of joined quotes is read when
		// its word is complete (GAP-0984 keeps a reading only for a word that
		// cannot become one).
		{"bash -'c' 'p; q'", []string{"bash -'c' 'p; q'", "body:p; q"}},
		{"bash -'l''c' 'p'", []string{"bash -'l''c' 'p'", "body:p"}},
		{"ba'sh' -c 'p; q'", []string{"ba'sh' -c 'p; q'", "body:p; q"}},
		{"echo 'a'\"'\"'b' -'c' 'p'", []string{"echo 'a'\"'\"'b' -'c' 'p'"}},
	} {
		var got []string
		head, _, _ := capFloorPieces(tc.command, "")
		for _, piece := range head {
			text := piece.text(tc.command)
			switch {
			case piece.fedBody:
				text = "fed:" + text
			case piece.isBody():
				text = "body:" + text
			case text == "":
				continue
			}
			got = append(got, text)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("capFloorPieces(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}
