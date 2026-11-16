package gateway

import (
	"slices"
	"testing"
)

// TestAgentHookConfigEnvGrammar reads env calls through the one GNU env
// grammar: every option, in any order and abbreviation, is consumed before the
// command is judged, so the agent after the options is judged as if it were
// run directly.
func TestAgentHookConfigEnvGrammar(t *testing.T) {
	h := newGAP0048Home(t)
	off := `--settings '{"disableAllHooks":true}'`
	rows := []hookConfigShellRow{
		{"debug then unset home", "env --debug --unset HOME claude -p hi", "block"},
		{"list signals then unset home", "env --list-signal-handling --unset HOME claude -p hi", "block"},
		{"block signal then unset home", "env --block-signal=PIPE --unset HOME claude -p hi", "block"},
		{"default signal then unset home", "env --default-signal=PIPE --unset HOME claude -p hi", "block"},
		{"bare ignore signal then unset home", "env --ignore-signal -u HOME claude -p hi", "block"},
		{"abbreviated list signals then unset home", "env --list-s --uns HOME claude -p hi", "block"},
		{"null and debug cluster then unset home", "env -0v -u HOME claude -p hi", "block"},
		{"argv0 then unset home", "env -a other -u HOME claude -p hi", "block"},
		{"long argv0 then unset home", "env --argv0=other -u HOME claude -p hi", "block"},
		{"list signals then change directory and disable hooks", "env --list-signal-handling --chdir " + h.project + " claude " + off + " -p hi", "block"},
		{"cluster change directory then disable hooks", "env -iC " + h.project + " claude " + off + " -p hi", "block"},
		{"split string unset home", "env -S '-u HOME claude -p hi'", "block"},
		{"split string unset home attached", "env -S'-u HOME' claude -p hi", "block"},
		{"long split string unset home", "env --split-string='--unset=HOME claude -p hi'", "block"},
		{"split string then option then command", "env -S'--debug' -u HOME claude -p hi", "block"},
		{"split string quoted disable hooks", "env -S 'claude --settings \"{\\\"disableAllHooks\\\":true}\" -p hi'", "block"},
		{"split string clears environment", "env -S '-i claude -p hi'", "block"},
		{"split string agent home override", "env -S 'CLAUDE_CONFIG_DIR=/tmp/x claude -p hi'", "block"},
		{"list signals then unset other name", "env --list-signal-handling --unset LC_ALL claude -p hi", "allow"},
		{"split string unset other name", "env -S '-u LC_ALL claude -p hi'", "allow"},
		{"split string assignment of other name", "env -S 'LC_ALL=C claude -p hi'", "allow"},
		{"split string ordinary command", "env -S 'ls -l'", "allow"},
		{"split string comment", "env -S 'claude -p hi # -u HOME'", "allow"},
		{"argv0 then ordinary", "env -a other claude -p hi", "allow"},
		{"cluster change directory ordinary", "env -0C " + h.project + " claude -p hi", "allow"},
	}
	checkHookConfigShellRows(t, h, rows)
}

func TestAgentHookConfigEnvChildWords(t *testing.T) {
	for _, row := range []struct {
		name      string
		argv      []string
		child     []string
		directory string
		unset     []string
		ok        bool
	}{
		{"plain command", []string{"env", "claude", "-p"}, []string{"claude", "-p"}, "", nil, true},
		{"signal option neighbours", []string{"env", "--list-signal-handling", "--block-signal=PIPE", "-u", "HOME", "A=1", "claude"}, []string{"A=1", "claude"}, "", []string{"HOME"}, true},
		{"split string spliced", []string{"env", "-S", "-i -C /x B=2 claude -p", "--", "tail"}, []string{"B=2", "claude", "-p", "--", "tail"}, "/x", []string{"*"}, true},
		{"end of options", []string{"env", "-i", "--", "-u", "HOME", "claude"}, []string{"-u", "HOME", "claude"}, "", []string{"*"}, true},
		{"missing operand", []string{"env", "-u"}, nil, "", nil, false},
		{"unknown short", []string{"env", "-x", "claude"}, nil, "", nil, false},
		{"unknown long", []string{"env", "--frobnicate", "claude"}, nil, "", nil, false},
		{"ambiguous long", []string{"env", "--d", "claude"}, nil, "", nil, false},
		{"version runs nothing", []string{"env", "--version"}, nil, "", nil, false},
		{"environment in split string", []string{"env", "-S", "${X} claude"}, nil, "", nil, false},
		{"unterminated quote", []string{"env", "-S", "'claude"}, nil, "", nil, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			child, directory, unset, ok := agentHookConfigEnvChild(row.argv)
			if ok != row.ok || directory != row.directory || !slices.Equal(child, row.child) || !slices.Equal(unset, row.unset) {
				t.Errorf("got %q %q %q %v, want %q %q %q %v", child, directory, unset, ok, row.child, row.directory, row.unset, row.ok)
			}
		})
	}
}

func TestAgentHookConfigSplitString(t *testing.T) {
	for _, row := range []struct {
		text string
		want []string
		ok   bool
	}{
		{"a b  c", []string{"a", "b", "c"}, true},
		{`a 'b c' d`, []string{"a", "b c", "d"}, true},
		{`a "b\" c" d`, []string{"a", `b" c`, "d"}, true},
		{`a\_b`, []string{"a", "b"}, true},
		{`a\tb`, []string{"a\tb"}, true},
		{`a\cb c`, []string{"a"}, true},
		{`a #b c`, []string{"a"}, true},
		{`a#b c`, []string{"a#b", "c"}, true},
		{`a\#b`, []string{"a#b"}, true},
		{`''`, []string{""}, true},
		{"", nil, true},
		{`a "b\_c" d`, []string{"a", "b c", "d"}, true},
		{`a "\_"b`, []string{"a", " b"}, true},
		{`a "b\#c" d`, []string{"a", "b#c", "d"}, true},
		{`a "b\'c" d`, []string{"a", "b'c", "d"}, true},
		{`a 'b\nc' d`, []string{"a", `b\nc`, "d"}, true},
		{`a 'b\\c'`, []string{"a", `b\c`}, true},
		{`a 'b\'c'`, []string{"a", "b'c"}, true},
		{`a "b\cc"`, nil, false},
		{`a $X`, nil, false},
		{`a$`, nil, false},
		{`a ${X}`, nil, false},
		{`"a ${X}"`, nil, false},
		{`a\xb`, nil, false},
		{`"a`, nil, false},
		{`a\`, nil, false},
	} {
		got, ok := agentHookConfigSplitString(row.text)
		if ok != row.ok || !slices.Equal(got, row.want) {
			t.Errorf("%q: got %q %v, want %q %v", row.text, got, ok, row.want, row.ok)
		}
	}
}
