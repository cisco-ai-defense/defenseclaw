package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFindActionVariants pins that a find call writes only through an
// action predicate, in every profile and on both routes: the output file of
// -fprint, -fprint0, -fprintf and -fls and the target of an -exec, -execdir,
// -ok or -okdir child block when it is a registered hook or a link to it
// (spelled directly or through a value the command bound), and a search that
// only lists stays allowed whatever its root or test values. The name carries
// no registry path component (hooks, config): the per-user text gate reads a
// command that spells no registered path only through its variables, and such
// a word in the temporary folder name would open that gate by accident.
func TestFindActionVariants(t *testing.T) {
	h := newGAP0048Home(t)
	hook := filepath.Join(h.home, ".local", "bin", "defenseclaw-hook-user")
	ordinary := filepath.Join(h.ext, "ordinary")
	for _, path := range []string{hook, ordinary} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(h.ext, "linked-hook")
	if err := os.Symlink(hook, link); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"fprint onto the hook", "find . -fprint " + hook, "block"},
		{"fprint0 onto the hook", "find . -fprint0 " + hook, "block"},
		{"fprintf onto the hook", "find . -fprintf " + hook + " %p", "block"},
		{"fls onto the hook", "find . -fls " + hook, "block"},
		{"exec copy onto the hook", "find . -exec cp " + ordinary + " " + hook + " \\;", "block"},
		{"execdir copy onto the hook", "find . -execdir cp " + ordinary + " " + hook + " \\;", "block"},
		{"delete the hook", "find " + hook + " -delete", "block"},
		{"fprint onto a known hook", "dest=" + hook + "; find . -fprint \"$dest\"", "block"},
		{"fprint onto a link to the hook", "find . -fprint " + link, "block"},
		{"fprint onto a known link", "dest=" + link + "; find . -fprint \"$dest\"", "block"},
		{"exec copy onto a known hook", "dest=" + hook + "; find . -exec cp " + ordinary + " \"$dest\" \\;", "block"},
		{"exec copy onto a known link", "dest=" + link + "; find . -exec cp " + ordinary + " \"$dest\" \\;", "block"},
		{"fprint onto the hook after a dynamic pattern", "root=.; pattern=cp; find \"$root\" -name \"$pattern\" -fprint " + hook, "block"},
		{"exec copy onto the hook after a dynamic pattern", "root=.; pattern=cp; find \"$root\" -name \"$pattern\" -exec cp " + ordinary + " " + hook + " \\;", "block"},
		{"delete a known hook root", "root=" + hook + "; find \"$root\" -delete", "block"},
		{"remove a known hook root by exec", "root=" + hook + "; find \"$root\" -exec rm {} \\;", "block"},
		{"execdir copy onto the hook after a dynamic root", "root=.; find \"$root\" -execdir cp " + ordinary + " " + hook + " \\;", "block"},
		{"ok copy onto the hook after a dynamic root", "root=.; find \"$root\" -ok cp " + ordinary + " " + hook + " \\;", "block"},
		{"okdir copy onto the hook after a dynamic root", "root=.; find \"$root\" -okdir cp " + ordinary + " " + hook + " \\;", "block"},
		{"fprint0 onto the hook after a dynamic root", "root=.; find \"$root\" -fprint0 " + hook, "block"},
		{"fprintf onto the hook after a dynamic root", "root=.; find \"$root\" -fprintf " + hook + " %p", "block"},
		{"fls onto the hook after a dynamic root", "root=.; find \"$root\" -fls " + hook, "block"},
		{"fprint onto an ordinary file", "find . -fprint " + ordinary + ".list", "allow"},
		{"exec copy onto an ordinary file", "find . -exec cp {} " + ordinary + ".copy \\;", "allow"},
		{"dynamic root before a name", "root=.; pattern=cp; find \"$root\" -name \"$pattern\"; cat " + hook, "allow"},
		{"working directory root before a path", "pattern=cp; find \"$PWD\" -path \"$pattern\" -print; cat " + hook, "allow"},
		{"dynamic root with a name and a format", "root=.; find \"$root\" -name cp -printf %p; cat " + hook, "allow"},
		{"files0-from file", "roots_file=/dev/null; find -files0-from \"$roots_file\" -name \"$pattern\"; cat " + hook, "allow"},
		{"dynamic test value", "find . -name \"$pattern\"; cat " + hook, "allow"},
		{"dynamic root with a type and print", "root=.; find \"$root\" -type f -print; cat " + hook, "allow"},
		{"delete is a name pattern", "find . -name -delete; cat " + hook, "allow"},
		{"fprint is a print format", "find . -printf -fprint; cat " + hook, "allow"},
		{"dynamic root and read-only exec", "root=.; find \"$root\" -exec echo cp {} \\; ; cat " + hook, "allow"},
		{"dynamic root and read-only execdir", "root=.; find \"$root\" -execdir echo rm {} \\; ; cat " + hook, "allow"},
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
