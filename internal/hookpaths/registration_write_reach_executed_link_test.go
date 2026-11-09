package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistrationWriteReachExecutedLink(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	named := filepath.Join(root, "source", "defenseclaw-hook-user")
	for _, path := range []string{hook, named} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"false and", "dest=" + bin + "; false && ln -sf " + named + " \"$dest\"/; echo ready", false},
		{"true or", "dest=" + bin + "; true || ln -sf " + named + " \"$dest\"/; echo ready", false},
		{"false branch", "dest=" + bin + "; if false; then ln -sf " + named + " \"$dest\"/; fi; echo ready", false},
		{"elif after a false branch", "dest=" + bin + "; if false; then echo no; elif true; then ln -sf " + named + " \"$dest\"/; fi", true},
		{"true branch", "dest=" + bin + "; if true; then ln -sf " + named + " \"$dest\"/; fi", true},
		{"assignment in a skipped branch does not bind", "dest=" + bin + "; false && dest=/tmp; ln -sf " + named + " \"$dest\"/", true},
		{"assignment before a skipped or binds", "false || dest=" + bin + "; ln -sf " + named + " \"$dest\"/", true},
		{"called function with late known values", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; link_hook", true},
		{"called function with early known values", "src=" + named + "; dest=" + bin + "; link_hook() { ln -sf \"$src\" \"$dest\"/; }; link_hook", true},
		{"called function with arguments", "link_hook() { ln -sf \"$1\" \"$2\"/; }; link_hook " + named + " " + bin, true},
		{"function calling a function", "inner() { ln -sf \"$1\" \"$2\"/; }; outer() { inner \"$1\" \"$2\"; }; outer " + named + " " + bin, true},
		{"function called only in a false branch", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; false && link_hook", false},
		{"function never called", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin, false},
		{"destination changed before the call", "dest=" + bin + "; link_hook() { ln -sf " + named + " \"$dest\"/; }; dest=/tmp; link_hook", false},
		{"ordinary link in a called function", "link_hook() { ln -sf \"$1\" \"$2\"/; }; link_hook " + named + " /tmp", false},
		{"child shell assignment stays in a command substitution", "f() { dest=/tmp; }; src=" + named + "; dest=" + bin + "; x=$(f); ln -sf \"$src\" \"$dest\"/", true},
		{"child shell assignment stays in a subshell", "f() { dest=/tmp; }; src=" + named + "; dest=" + bin + "; (f); ln -sf \"$src\" \"$dest\"/", true},
		{"child shell assignment stays in a background command", "f() { dest=/tmp; }; src=" + named + "; dest=" + bin + "; f & ln -sf \"$src\" \"$dest\"/", true},
		{"child shell assignment stays in a pipe stage", "f() { dest=/tmp; }; src=" + named + "; dest=" + bin + "; f | cat; ln -sf \"$src\" \"$dest\"/", true},
		{"plain subshell assignment stays in the subshell", "src=" + named + "; dest=" + bin + "; ( dest=/tmp ); ln -sf \"$src\" \"$dest\"/", true},
		{"child shell protected value stays in the child", "f() { dest=" + bin + "; }; src=" + named + "; dest=/tmp; x=$(f); ln -sf \"$src\" \"$dest\"/", false},
		{"function in the current shell binds the destination", "f() { dest=" + bin + "; }; src=" + named + "; dest=/tmp; f; ln -sf \"$src\" \"$dest\"/", true},
		{"link inside a command substitution", "dest=" + bin + "; x=$(ln -sf " + named + " \"$dest\"/)", true},
		{"function returns before its link", "link_hook() { return 0; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; link_hook", true},
		{"function returns after its link", "link_hook() { ln -sf \"$src\" \"$dest\"/; return 0; }; src=" + named + "; dest=" + bin + "; link_hook", true},
		{"function returns only in a condition", "link_hook() { if [ -n \"$x\" ]; then return 0; fi; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; link_hook", true},
		{"link after an exit", "dest=" + bin + "; exit 0; ln -sf " + named + " \"$dest\"/", true},
		{"definition in a branch that does not run", "if false; then link_hook() { ln -sf \"$src\" \"$dest\"/; }; fi; src=" + named + "; dest=" + bin + "; link_hook", false},
		{"definition in a branch that runs", "if true; then link_hook() { ln -sf \"$src\" \"$dest\"/; }; fi; src=" + named + "; dest=" + bin + "; link_hook", true},
		{"function removed before the call", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; unset -f link_hook; link_hook", false},
		{"function removed behind builtin", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; builtin unset -f link_hook; link_hook", false},
		{"variable unset keeps the function", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; unset -v link_hook; link_hook", true},
		{"another function removed keeps this one", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; unset -f other; link_hook", true},
		{"pipeline stage state and the word lastpipe as an argument", "echo lastpipe; f() { dest=/tmp; }; src=" + named + "; dest=" + bin + "; f | cat; ln -sf \"$src\" \"$dest\"/", true},
		{"pipeline stage state with the lastpipe option", "shopt -s lastpipe; f() { dest=/tmp; }; src=" + named + "; dest=" + bin + "; f | cat; ln -sf \"$src\" \"$dest\"/", true},
		{"last pipe stage binds the destination with lastpipe", "shopt -s lastpipe; src=" + named + "; dest=/tmp; echo x | dest=" + bin + "; ln -sf \"$src\" \"$dest\"/", true},
		{"pipeline stage binds the protected destination", "echo lastpipe; f() { dest=" + bin + "; }; src=" + named + "; dest=/tmp; f | cat; ln -sf \"$src\" \"$dest\"/", true},
		{"pipeline stage state with an ordinary link", "f() { dest=/tmp; }; src=/tmp/ordinary-source; dest=/tmp/ordinary-folder; f | cat; ln -sf \"$src\" \"$dest\"/", false},
		{"pipeline without state keeps the exact reading", "dest=" + bin + "; false && ln -sf " + named + " \"$dest\"/ | cat; echo ready", false},
		{"exit with a failing redirection", "src=" + named + "; dest=" + bin + "; exit > /nonexistent-folder/never; ln -sf \"$src\" \"$dest\"/", true},
		{"return with a failing redirection", "f() { return > /nonexistent-folder/never; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; f", true},
		{"function shadowing exit", "exit() { :; }; src=" + named + "; dest=" + bin + "; exit; ln -sf \"$src\" \"$dest\"/", true},
		{"exit inside a called function", "f() { exit 0; }; src=" + named + "; dest=" + bin + "; f; ln -sf \"$src\" \"$dest\"/", true},
		{"return inside a nested block", "f() { { return 0; }; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; f", true},
		{"exit before an ordinary link", "src=/tmp/ordinary-source; dest=/tmp/ordinary-folder; exit 0; ln -sf \"$src\" \"$dest\"/", false},
		{"return before an ordinary link", "f() { return 0; ln -sf \"$1\" \"$2\"/; }; f /tmp/ordinary-source /tmp/ordinary-folder", false},
		{"function shadowing unset keeps the function", "unset() { :; }; link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; unset -f link_hook; link_hook", true},
		{"function shadowing unset with an ordinary link", "unset() { :; }; link_hook() { ln -sf \"$1\" \"$2\"/; }; unset -f link_hook; link_hook /tmp/ordinary-source /tmp/ordinary-folder", false},
		{"eval of a built command with a protected link", "dest=" + bin + "; eval \"echo ready\"; ln -sf " + named + " \"$dest\"/", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := len(RegistrationWriteReached(row.command, root, home, []string{hook, bin})) > 0
			if got != row.want {
				t.Errorf("reached %v, want %v for %q", got, row.want, row.command)
			}
		})
	}
}
