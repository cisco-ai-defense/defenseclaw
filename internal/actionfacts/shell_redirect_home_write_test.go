package actionfacts

import (
	"slices"
	"testing"
)

// GAP-2328 (RV16-1, RV17-1): only a statement that sets HOME, USER or
// LOGNAME to another literal value in the shell that opens the redirect
// leaves a target that expands that name unresolved. The name as a
// positional word of other code, an option value, text that only reads it,
// a value the shell reads or computes (read, mapfile, printf -v, getopts),
// unset (bash then expands ~ to the passwd home), a prefix assignment of
// another command (the shell opens the target first), the active value
// itself and a statement in a subshell, pipeline, background job or a
// branch that may not run leave the target judged as the active home, with
// or without builtin or command before it.
func TestShellRedirectTargetsHomeNameOnlyWrittenKeepsTheSkip(t *testing.T) {
	const home = "/home/dev"
	const state = home + "/.defenseclaw/config.yaml"
	resolved := []string{
		"source ./env.sh HOME; ",
		"$CMD HOME; ",
		"$CMD USER LOGNAME; ",
		"eval ': HOME'; ",
		"eval 'echo $HOME'; ",
		`eval "echo $HOME"; `,
		"eval true && ",
		"read -p HOME v < in.txt; ",
		"read -r v < in.txt; ",
		"printf -v v %s HOME; ",
		"printf %s HOME; ",
		"trap ': HOME' EXIT; ",
		"builtin source ./env.sh HOME; ",
		"mapfile -t a < in.txt; ",
		"export USERNAME=dev; ",
		"unset HOMEDIR; ",
		// RV17-1: a value the shell reads or computes, and unset.
		"read HOME < in.txt; ",
		"read -r -a USER < in.txt; ",
		"read -ra LOGNAME < in.txt; ",
		"printf -v HOME %s /tmp/h; ",
		"printf -vUSER %s x; ",
		"mapfile -t HOME < in.txt; ",
		"getopts ab HOME; ",
		"unset HOME; ",
		"command unset HOME; ",
		"builtin unset HOME; ",
		"command read HOME < in.txt; ",
		"builtin read HOME < in.txt; ",
		"eval read HOME; ",
		"eval 'unset HOME'; ",
		"eval \"builtin printf -v LOGNAME %s x\"; ",
		"export HOME=$(mktemp -d); ",
		"HOME=$X; ",
		"export HOME; ",
		"declare -n r=HOME; ",
		"declare -l HOME=/TMP/H; ",
		"local HOME=/tmp/h; ",
		": ${HOME:=/tmp/h}; ",
		"eval ': ${HOME:=/tmp/h}'; ",
		"echo $((HOME)); ",
		// The shell opens the target before a prefix assignment applies.
		"HOME=/tmp/h ",
		"env HOME=/tmp/h ",
		// Another process, or a branch that may not run.
		"(HOME=/tmp/h); ",
		"HOME=/tmp/h | ",
		"HOME=/tmp/h & ",
		"false && HOME=/tmp/h; ",
		"true || HOME=/tmp/h; ",
		"if false; then HOME=/tmp/h; fi; ",
		"trap 'HOME=/tmp/h' EXIT; ",
		// The active value, and a name the spelling does not expand.
		"HOME=/home/dev; ",
		"HOME=/home/dev/; ",
		"export HOME=/home/dev; ",
		"USER=x; ",
		"eval 'export USER=x'; ",
		"LOGNAME=x; ",
	}
	kept := []string{
		"HOME=/tmp/h; ",
		"HOME=/tmp/h && ",
		"HOME=/tmp/h || ",
		"{ HOME=/tmp/h; }; ",
		"HOME+=x; ",
		"export HOME=/tmp/h; ",
		"declare -x HOME=/tmp/h; ",
		"readonly HOME=/tmp/h; ",
		"command export HOME=/tmp/h; ",
		"builtin export HOME=/tmp/h; ",
		"eval 'HOME=/tmp/h'; ",
		"eval 'export HOME=/tmp/h'; ",
		"eval 'for HOME in /tmp; do :; done'; ",
		"for HOME in /tmp; do :; done; ",
		"trap 'HOME=/tmp/h' DEBUG; ",
		"(( HOME=1 )); ",
		"let HOME=1; ",
	}
	for _, spelling := range []string{"~/", "$HOME/"} {
		for _, prefix := range resolved {
			for _, program := range []string{"make", "echo $X"} {
				command := prefix + program + " > " + spelling + ".defenseclaw/config.yaml"
				targets, ok := ShellRedirectTargets(command, home)
				if !ok || !slices.Contains(targets, state) {
					t.Errorf("%q: targets %v (ok=%v), want %s", command, targets, ok, state)
				}
			}
		}
		for _, prefix := range kept {
			command := prefix + "make > " + spelling + ".defenseclaw/config.yaml"
			if targets, _ := ShellRedirectTargets(command, home); slices.Contains(targets, state) {
				t.Errorf("%q: targets %v, want the home spelling left unresolved", command, targets)
			}
		}
	}
	// A user-name spelling follows USER or LOGNAME, not HOME.
	for _, tc := range []struct {
		command string
		judged  bool
	}{
		{"USER=x; make > /home/$USER/.defenseclaw/config.yaml", false},
		{"LOGNAME=x; make > /home/$LOGNAME/.defenseclaw/config.yaml", false},
		{"HOME=/tmp/h; make > /home/$USER/.defenseclaw/config.yaml", true},
		{"LOGNAME=x; make > /home/$USER/.defenseclaw/config.yaml", true},
		{"USER=dev; make > /home/$USER/.defenseclaw/config.yaml", true},
		{"command unset USER; make > /home/$USER/.defenseclaw/config.yaml", true},
	} {
		targets, _ := ShellRedirectTargets(tc.command, home)
		if judged := slices.Contains(targets, state); judged != tc.judged {
			t.Errorf("%q: targets %v, judged=%v, want %v", tc.command, targets, judged, tc.judged)
		}
	}
	// A Windows home (Git Bash): the MSYS and drive spellings of the active
	// home are the active value.
	const winHome = "C:/Users/dev"
	const winState = winHome + "/.defenseclaw/config.yaml"
	for _, tc := range []struct {
		prefix string
		judged bool
	}{
		{"HOME=/c/Users/dev; ", true},
		{"HOME='C:\\Users\\dev'; ", true},
		{"command unset HOME; ", true},
		{"HOME=/tmp/h; ", false},
	} {
		command := tc.prefix + "make > ~/.defenseclaw/config.yaml"
		targets, _ := ShellRedirectTargets(command, winHome)
		if judged := slices.Contains(targets, winState); judged != tc.judged {
			t.Errorf("%q: targets %v, judged=%v, want %v", command, targets, judged, tc.judged)
		}
	}
}
