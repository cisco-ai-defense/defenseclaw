package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAgentHookConfigSplitStringEscapes keeps the escapes GNU env reads inside
// a quoted split string in the same word, so the agent after them is judged as
// when it is run directly, and keeps an ordinary quoted split string allowed.
func TestAgentHookConfigSplitStringEscapes(t *testing.T) {
	h := newGAP0048Home(t)
	rows := []struct{ name, command, want string }{
		{"quoted escaped blank disables hooks", `env -S 'claude --settings "{\"disableAllHooks\":\_true}" -p hi'`, "block"},
		{"quoted escaped blank changes config home", `env -S 'CLAUDE_CONFIG_DIR="/tmp/other\_path" claude -p hi'`, "block"},
		{"quoted escaped blank ordinary settings", `env -S 'claude --settings "{\"model\":\_\"sonnet\"}" -p hi'`, "allow"},
		{"quoted escaped blank ordinary env", `env -S 'FOO="bar\_baz" claude -p hi'`, "allow"},
	}
	for _, row := range rows {
		for _, profile := range []string{"permissive", "default", "strict"} {
			for _, managed := range []bool{false, true} {
				name := row.name + "/" + profile
				if managed {
					name += "/managed"
				} else {
					name += "/user"
				}
				t.Run(name, func(t *testing.T) {
					got := rv2Action(rv3Judge(t, "claudecode", profile, h.project, managed, "Bash", map[string]any{"command": row.command}))
					if got != row.want {
						t.Errorf("got %s, want %s for %q", got, row.want, row.command)
					}
				})
			}
		}
	}
}

// TestAgentHookConfigExecutedLinkPlacement judges a link by whether it runs:
// a called function is read at its call with the values bound by then, and a
// link in a branch a fixed condition rules out is left alone.
func TestAgentHookConfigExecutedLinkPlacement(t *testing.T) {
	h := newGAP0048Home(t)
	bin := filepath.Join(h.home, ".local", "bin")
	named := filepath.Join(h.ext, "source", "defenseclaw-hook-user")
	if err := os.MkdirAll(filepath.Dir(named), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(named, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// A sibling folder of the test home: a destination that holds the home
	// (the test tree under /tmp when TMPDIR is /tmp) is a different, existing
	// rule and not the ordinary folder this test means.
	ordinary := t.TempDir()
	rows := []struct{ name, command, want string }{
		{"called function with late known values", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; link_hook", "block"},
		{"called function with early known values", "src=" + named + "; dest=" + bin + "; link_hook() { ln -sf \"$src\" \"$dest\"/; }; link_hook", "block"},
		{"called function with arguments", "link_hook() { ln -sf \"$1\" \"$2\"/; }; link_hook " + named + " " + bin, "block"},
		{"function called twice, second call reaches", "link_hook() { ln -sf \"$1\" \"$2\"/; }; link_hook " + named + " " + ordinary + "; link_hook " + named + " " + bin, "block"},
		{"executed link in true branch", "dest=" + bin + "; if true; then ln -sf " + named + " \"$dest\"/; fi", "block"},
		{"link after a false and-list", "dest=" + bin + "; false || ln -sf " + named + " \"$dest\"/", "block"},
		{"unexecuted link with false and", "dest=" + bin + "; false && ln -sf " + named + " \"$dest\"/; echo ready", "allow"},
		{"unexecuted link with true or", "dest=" + bin + "; true || ln -sf " + named + " \"$dest\"/; echo ready", "allow"},
		{"unexecuted link in false branch", "dest=" + bin + "; if false; then ln -sf " + named + " \"$dest\"/; fi; echo ready", "allow"},
		{"unexecuted link in true branch else", "dest=" + bin + "; if true; then echo ready; else ln -sf " + named + " \"$dest\"/; fi", "allow"},
		{"function called only in a false branch", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; false && link_hook; echo ready", "allow"},
		{"function never called", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; echo ready", "allow"},
		{"function called with an ordinary folder", "link_hook() { ln -sf \"$1\" \"$2\"/; }; link_hook " + named + " " + ordinary, "allow"},
		{"destination changed before the call", "dest=" + bin + "; link_hook() { ln -sf " + named + " \"$dest\"/; }; dest=" + ordinary + "; link_hook", "allow"},
		{"child shell assignment stays in a command substitution", "f() { dest=" + ordinary + "; }; src=" + named + "; dest=" + bin + "; x=$(f); ln -sf \"$src\" \"$dest\"/", "block"},
		{"child shell assignment stays in a subshell", "f() { dest=" + ordinary + "; }; src=" + named + "; dest=" + bin + "; (f); ln -sf \"$src\" \"$dest\"/", "block"},
		{"child shell protected value stays in the child", "f() { dest=" + bin + "; }; src=" + named + "; dest=" + ordinary + "; x=$(f); ln -sf \"$src\" \"$dest\"/", "allow"},
		{"function returns before its link", "link_hook() { return 0; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; link_hook", "block"},
		{"definition in a branch that does not run", "if false; then link_hook() { ln -sf \"$src\" \"$dest\"/; }; fi; src=" + named + "; dest=" + bin + "; link_hook", "allow"},
		{"function removed before the call", "link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; unset -f link_hook; link_hook", "allow"},
		{"pipeline stage state with the word lastpipe as an argument", "echo lastpipe; f() { dest=" + ordinary + "; }; src=" + named + "; dest=" + bin + "; f | cat; ln -sf \"$src\" \"$dest\"/", "block"},
		{"pipeline stage state with the lastpipe option", "shopt -s lastpipe; f() { dest=" + ordinary + "; }; src=" + named + "; dest=" + bin + "; f | cat; ln -sf \"$src\" \"$dest\"/", "block"},
		{"pipeline stage binds the protected destination", "f() { dest=" + bin + "; }; src=" + named + "; dest=" + ordinary + "; f | cat; ln -sf \"$src\" \"$dest\"/", "block"},
		{"pipeline stage state with an ordinary link", "f() { dest=" + ordinary + "; }; src=" + named + "; dest=" + ordinary + "; f | cat; ln -sf \"$src\" \"$dest\"/", "allow"},
		{"exit with a failing redirection", "src=" + named + "; dest=" + bin + "; exit > " + ordinary + "/missing/never; ln -sf \"$src\" \"$dest\"/", "block"},
		{"return with a failing redirection", "f() { return > " + ordinary + "/missing/never; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; f", "block"},
		{"function shadowing exit", "exit() { :; }; src=" + named + "; dest=" + bin + "; exit; ln -sf \"$src\" \"$dest\"/", "block"},
		{"exit inside a called function", "f() { exit 0; }; src=" + named + "; dest=" + bin + "; f; ln -sf \"$src\" \"$dest\"/", "block"},
		{"return inside a nested block", "f() { { return 0; }; ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; f", "block"},
		{"exit before an ordinary link", "src=" + named + "; dest=" + ordinary + "; exit 0; ln -sf \"$src\" \"$dest\"/", "allow"},
		{"function shadowing unset keeps the function", "unset() { :; }; link_hook() { ln -sf \"$src\" \"$dest\"/; }; src=" + named + "; dest=" + bin + "; unset -f link_hook; link_hook", "block"},
		{"function shadowing unset with an ordinary link", "unset() { :; }; link_hook() { ln -sf \"$1\" \"$2\"/; }; unset -f link_hook; link_hook " + ordinary + "/note " + ordinary, "allow"},
	}
	for _, row := range rows {
		for _, profile := range []string{"permissive", "default", "strict"} {
			for _, managed := range []bool{false, true} {
				name := row.name + "/" + profile
				if managed {
					name += "/managed"
				} else {
					name += "/user"
				}
				t.Run(name, func(t *testing.T) {
					got := rv2Action(rv3Judge(t, "claudecode", profile, h.project, managed, "Bash", map[string]any{"command": row.command}))
					if got != row.want {
						t.Errorf("got %s, want %s for %q", got, row.want, row.command)
					}
				})
			}
		}
	}
}
