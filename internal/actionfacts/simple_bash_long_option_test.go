package actionfacts

import (
	"path/filepath"
	"slices"
	"testing"
)

// The split reads the long options bash reads before its short ones
// (simpleBashLongOption) to the -c body they leave, as Analyze does; before,
// bash --norc -c BODY was a gap of the split (substrate-1:GAP-0685
// follow-up). A long option that names startup input, or one after a short
// option (bash reads none there), stays a gap.
func TestSplitReadsBashLongOptionsBeforeTheBody(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, row := range []struct {
		command string
		read    bool
	}{
		{`bash --norc -c "cp a.txt b.txt"`, true},
		{`bash --noprofile --norc -c "cp a.txt b.txt"`, true},
		{`bash --posix -c "cp a.txt b.txt"`, true},
		{`bash --login -c "cp a.txt b.txt"`, true},
		{`env -C ` + home + ` bash --norc -c "cp a.txt b.txt"`, true},
		{`cd ` + home + ` && bash --noediting -c "cp a.txt b.txt"`, true},
		{`bash --rcfile x.rc -c "cp a.txt b.txt"`, false},
		{`bash --debugger -c "cp a.txt b.txt"`, false},
		{`bash -e --norc -c "cp a.txt b.txt"`, false},
		{`sh --norc -c "cp a.txt b.txt"`, false},
	} {
		input := Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home}
		commands := SimpleCommands(input, Analyze(input))
		gap := slices.ContainsFunc(commands, func(simple SimpleCommand) bool { return simple.EvaluationFailure == "parse" })
		body := slices.ContainsFunc(commands, func(simple SimpleCommand) bool { return simple.Text == "cp a.txt b.txt" })
		if read := !gap && body; read != row.read {
			t.Errorf("%q: read = %t, want %t (commands %+v)", row.command, read, row.read, commands)
		}
	}
}
