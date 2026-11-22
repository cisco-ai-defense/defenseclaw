// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The commands below are ordinary ones: the twin is a text transformation of
// the call, not a reading of what the commands do.
func TestAwkCommandTwin(t *testing.T) {
	cases := []struct {
		name, command, text string
		bodies              []string
	}{
		{"system", `awk 'BEGIN{system("touch a")}'`, "touch a", []string{"touch a"}},
		{"print pipe", `awk '{print $1 | "sort -u"}' f`, "sort -u", []string{"sort -u"}},
		{"getline", `awk 'BEGIN{"date" | getline d}'`, "date", []string{"date"}},
		{"in a pipeline", `echo x | awk '{print | "sort"}' | cat`, "echo x | { sort\n} | cat", []string{"sort"}},
		{"in a list", `cd d && awk 'BEGIN{system("touch a")}' f`, "cd d && { touch a\n}", []string{"touch a"}},
		{"redirect stays on the group", `awk 'BEGIN{system("echo a")}' > out`, "{ echo a\n} > out", []string{"echo a"}},
		{"two commands are subshells", `awk 'BEGIN{system("cd d"); system("touch a")}'`, "{ ( cd d\n)\n( touch a\n)\n}", []string{"( cd d\n)\n( touch a\n)"}},
		{"computed operand is not program text", `awk 'BEGIN{system("touch a")}' "$f"`, "touch a", []string{"touch a"}},
		{"prefix wrapper stays", `nohup awk 'BEGIN{system("touch a")}'`, "nohup sh -c 'touch a'", []string{"touch a"}},
		{"assignment stays", `A=1 awk 'BEGIN{system("touch a")}'`, "A=1 sh -c 'touch a'", []string{"touch a"}},
		{"env directory stays", `env -C d awk 'BEGIN{system("touch a")}'`, "env -C d sh -c 'touch a'", []string{"touch a"}},
		{"in a shell string", `bash -c "awk 'BEGIN{system(\"touch a\")}'"`, "bash -c 'touch a'", []string{"touch a"}},
		{"quotes in the command", `awk 'BEGIN{system("echo \"a b\"")}'`, "echo \"a b\"", []string{`echo "a b"`}},
		{"two awk calls", `awk 'BEGIN{system("a")}'; gawk 'BEGIN{system("b")}'`, "{ a\n}; { b\n}", []string{"a", "b"}},
		// A print redirect into a literal file is the shell redirect that
		// writes it (rel-1-0-10:GAP-1239).
		{"print to a file", `awk '{print $1 > "out"}' f`, ": > 'out'", []string{": > 'out'"}},
		{"print appends behind env", `env awk '{print >> "log"}' f`, "env sh -c ': >> '\\''log'\\'''", []string{": >> 'log'"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			twin := AwkCommandTwin(tc.command)
			if twin.Text != tc.text {
				t.Fatalf("text %q, want %q", twin.Text, tc.text)
			}
			if strings.Join(twin.Bodies, "|") != strings.Join(tc.bodies, "|") {
				t.Fatalf("bodies %q, want %q", twin.Bodies, tc.bodies)
			}
			if twin.Truncated.Any() {
				t.Fatalf("truncated: %s", twin.Truncated.Reason())
			}
		})
	}
}

// An awk call with no command it can read is not rewritten: the commands built
// at run time are the gateway's unknown tier, and a program with no command
// channel is read as before.
func TestAwkCommandTwinLeavesOtherCalls(t *testing.T) {
	for name, command := range map[string]string{
		"columns":             `awk '{print $1, $2}' f`,
		"print to a field":    `awk '{print $2 > $1}' f`,
		"match with a pipe":   `awk '/a|b/ {print}' f`,
		"command from field":  `awk '{system($1)}' f`,
		"command from var":    `awk 'BEGIN{print | cmd}'`,
		"command is data":     `awk -v 'x=system("a")' '{print x}' f`,
		"program from a file": `awk -f prog.awk f`,
		"not awk":             `echo 'system("a")'`,
		"unparsable":          `awk 'BEGIN{system("a")}' )`,
		"awk in an argument":  `grep awk f`,
	} {
		if twin := AwkCommandTwin(command); twin.Text != "" || len(twin.Bodies) != 0 || twin.Truncated.Any() {
			t.Errorf("%s: rewritten as %q (%v)", name, twin.Text, twin.Bodies)
		}
	}
}

// Shell STRINGs nested past maxNestedShellStrings are not read: an awk
// program inside is truncated at the depth cap (the bound rule), one inside
// the cap is read.
func TestAwkCommandTwinDepthCap(t *testing.T) {
	nest := func(levels int) string {
		command := `awk 'BEGIN{system("touch a")}'`
		for i := 0; i < levels; i++ {
			command = "bash -c " + posixSingleQuoted(command)
		}
		return command
	}
	for levels := 1; levels <= maxNestedShellStrings; levels++ {
		twin := AwkCommandTwin(nest(levels))
		if twin.Text == "" || twin.Truncated.Any() {
			t.Errorf("%d levels: text %q truncated %q", levels, twin.Text, twin.Truncated.Reason())
		}
	}
	for _, levels := range []int{maxNestedShellStrings + 1, 2 * maxNestedShellStrings} {
		twin := AwkCommandTwin(nest(levels))
		if !twin.Truncated.Has(bounded.Depth) {
			t.Errorf("%d levels: not truncated at the depth cap (%q)", levels, twin.Truncated.Reason())
		}
	}
	// A shell string with no awk in it is not an awk reading at any depth.
	plain := "touch a"
	for i := 0; i < 2*maxNestedShellStrings; i++ {
		plain = "bash -c " + posixSingleQuoted(plain)
	}
	if twin := AwkCommandTwin(plain); twin.Truncated.Any() {
		t.Errorf("a deep shell string with no awk is truncated: %q", twin.Truncated.Reason())
	}
}
