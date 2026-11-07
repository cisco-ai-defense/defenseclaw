package connector

import (
	"path/filepath"
	"strings"
	"testing"
)

// A program word the shell leaves literal is an ordinary program, whatever
// brace text its name holds. Bash expands only a list or a sequence whose two
// ends are both whole numbers or both single letters; "{1..a}" stays as it is,
// so a program named with it that sits beside managed hook path text is the
// user's file, under every prefix.
func TestGAP0625MixedBraceEndpointsStayOrdinary(t *testing.T) {
	for _, braces := range []string{"{1..a}", "{a..1}", "{1..a..2}", "{ab..cd}", "{1..2..x}", "{}", "{a}"} {
		for _, prefix := range []string{"", "env ", "command "} {
			t.Run(strings.TrimSpace(prefix)+"|"+braces, func(t *testing.T) {
				commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
					owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
					program := gap0625WriteExecutable(t, filepath.Join(home, "ordinary"+braces+"; "+owned))
					word := strings.NewReplacer(";", "\\;", " ", "\\ ").Replace(program)
					command := prefix + word + " --event pre_tool_call"
					gap0625RunsInBash(t, command)
					return command
				})
				gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
			})
		}
	}
}

// Near variant of the same word that Bash does expand: a sequence of two
// numbers or two letters, or a list, makes several words, so it is not one
// literal program and the managed path text beside it stays protected.
func TestGAP0625ExpandingBraceProgramStaysProtected(t *testing.T) {
	for _, braces := range []string{"{1..2}", "{a..b}", "{x,y}"} {
		t.Run(braces, func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				return filepath.Join(home, "ordinary"+braces+"; "+owned) + " --event pre_tool_call"
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

// A quoted "~/x", "$HOME/x" or ANSI-C spelling of either is a relative file
// name for the shell, not the home directory: the program is the user's file
// even when its relative name looks like a managed hook path.
func TestGAP0625QuotedRelativeHomeNamesStayOrdinary(t *testing.T) {
	for _, tc := range []struct{ name, relative, word string }{
		{"ansi-c tilde", "~/.defenseclaw/hooks/ordinary", "$'~/.defenseclaw/hooks/ordinary'"},
		{"single-quoted tilde", "~/.defenseclaw/hooks/ordinary", "'~/.defenseclaw/hooks/ordinary'"},
		{"double-quoted tilde", "~/.defenseclaw/hooks/ordinary", `"~/.defenseclaw/hooks/ordinary"`},
		{"escaped tilde", "~/.defenseclaw/hooks/ordinary", `\~/.defenseclaw/hooks/ordinary`},
		{"single-quoted dollar home", "$HOME/.defenseclaw/hooks/ordinary", "'$HOME/.defenseclaw/hooks/ordinary'"},
		{"escaped dollar home", "$HOME/.defenseclaw/hooks/ordinary", `\$HOME/.defenseclaw/hooks/ordinary`},
		{"ansi-c dollar home", "$HOME/.defenseclaw/hooks/ordinary", "$'$HOME/.defenseclaw/hooks/ordinary'"},
	} {
		for _, prefix := range []string{"", "env ", "command "} {
			t.Run(strings.TrimSpace(prefix)+"|"+tc.name, func(t *testing.T) {
				commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
					work := filepath.Join(home, "ordinary-work")
					gap0625WriteExecutable(t, filepath.Join(work, tc.relative))
					command := "cd '" + work + "' && " + prefix + tc.word + " --event pre_tool_call"
					gap0625RunsInBash(t, command)
					return command
				})
				gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
			})
		}
	}
}

// The unquoted forms expand to the home directory, so they name the managed
// hook directory and stay protected: the shell resolves them before it picks
// the program.
func TestGAP0625UnquotedHomeNamesStayProtected(t *testing.T) {
	for _, word := range []string{
		"~/.defenseclaw/hooks/edited", "$HOME/.defenseclaw/hooks/edited", "${HOME}/.defenseclaw/hooks/edited",
		`"$HOME/.defenseclaw/hooks/edited"`, `"${HOME}"/.defenseclaw/hooks/edited`,
	} {
		t.Run(word, func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				return word + " --event pre_tool_call"
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

// A managed hook file, or a link to one, named by a word with an apostrophe
// is that hook when it is an argument too: "bash <path>", "source <path>" and
// ". <path>" run the exact name, and the text scan, which drops quotes, cannot
// carry the apostrophe. The same shapes beside an ordinary script stay.
func TestGAP0625ApostropheNamedScriptArgument(t *testing.T) {
	ansiC := strings.NewReplacer("/", "\\057", "'", "\\047")
	quoted := func(name string) string { return "'" + strings.ReplaceAll(name, "'", "'\\''") + "'" }
	for _, runner := range []string{"bash ", "sh ", "source ", ". ", "env bash ", "command . "} {
		for _, tc := range []struct {
			name    string
			link    bool
			managed bool
			word    func(string) string
		}{
			{"link quoted", true, true, quoted},
			{"link ansi-c", true, true, func(p string) string { return "$'" + ansiC.Replace(p) + "'" }},
			{"file quoted", false, true, quoted},
			{"file ansi-c", false, true, func(p string) string { return "$'" + ansiC.Replace(p) + "'" }},
			{"ordinary quoted", false, false, quoted},
			{"ordinary ansi-c", false, false, func(p string) string { return "$'" + ansiC.Replace(p) + "'" }},
		} {
			t.Run(strings.TrimSpace(runner)+"|"+tc.name, func(t *testing.T) {
				commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
					program := filepath.Join(home, "outside", "it's; file")
					switch {
					case tc.managed && tc.link:
						owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
						program = gap0625Link(t, owned, filepath.Join(home, "outside", "linked'file"))
					case tc.managed:
						program = gap0625WriteExecutable(t, filepath.Join(hooks, "owned'file"))
					default:
						gap0625WriteExecutable(t, program)
					}
					command := runner + tc.word(program) + " --event pre_tool_call"
					gap0625RunsInBash(t, command)
					return command
				})
				if tc.managed {
					gap0625ExpectProtected(t, verifyErr, commands, userHook)
				} else {
					gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
				}
			})
		}
	}
}
