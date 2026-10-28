package actionfacts

import (
	"slices"
	"testing"
)

// GAP-2328 (RV16-1): only words that write HOME, USER or LOGNAME before a
// home-spelled redirect target keep it unresolved; the name as a positional
// word of other code, an option value or text that only reads the variable
// leaves the target judged as the active home.
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
	}
	kept := []string{
		"HOME=/tmp/h; ",
		"read HOME < in.txt; ",
		"read -r -a USER < in.txt; ",
		"read -ra LOGNAME < in.txt; ",
		"printf -v HOME %s /tmp/h; ",
		"printf -vUSER %s x; ",
		"mapfile -t HOME < in.txt; ",
		"getopts ab HOME; ",
		"unset HOME; ",
		"builtin read HOME < in.txt; ",
		"command export HOME=/tmp/h; ",
		"eval 'HOME=/tmp/h'; ",
		"eval 'export USER=x'; ",
		"eval read HOME; ",
		"eval 'for HOME in /tmp; do :; done'; ",
		"eval ': ${HOME:=/tmp/h}'; ",
		"trap 'HOME=/tmp/h' DEBUG; ",
		"eval \"builtin printf -v LOGNAME %s x\"; ",
	}
	for _, spelling := range []string{"~/", "$HOME/"} {
		for _, prefix := range resolved {
			command := prefix + "make > " + spelling + ".defenseclaw/config.yaml"
			targets, ok := ShellRedirectTargets(command, home)
			if !ok || !slices.Contains(targets, state) {
				t.Errorf("%q: targets %v (ok=%v), want %s", command, targets, ok, state)
			}
		}
		for _, prefix := range kept {
			command := prefix + "make > " + spelling + ".defenseclaw/config.yaml"
			if targets, _ := ShellRedirectTargets(command, home); slices.Contains(targets, state) {
				t.Errorf("%q: targets %v, want the home spelling left unresolved", command, targets)
			}
		}
	}
}
