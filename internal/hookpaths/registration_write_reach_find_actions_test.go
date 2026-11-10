package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A find call writes only through an action predicate: the file of -fprint,
// -fprint0, -fprintf and -fls, the target of the program an -exec, -execdir,
// -ok or -okdir action runs, and -delete. A file or link that is a registered
// hook is reached by each, with the file spelled directly or through a value
// the command bound; a search root, a test value or a read-only action is not
// a writer.
func TestRegistrationWriteReachFindActions(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	ordinary := filepath.Join(root, "ordinary")
	for _, path := range []string{hook, ordinary} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "linked-hook")
	if err := os.Symlink(hook, link); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"fprint onto the hook", "find . -fprint " + hook, true},
		{"fprint0 onto the hook", "find . -fprint0 " + hook, true},
		{"fprintf onto the hook", "find . -fprintf " + hook + " %p", true},
		{"fls onto the hook", "find . -fls " + hook, true},
		{"fprint onto a link to the hook", "find . -fprint " + link, true},
		{"fprint onto the hook with a name test first", "find . -name x -fprint " + hook, true},
		{"fprint onto a known link", "dest=" + link + "; find . -fprint \"$dest\"", true},
		{"fprint onto a known hook", "dest=" + hook + "; find . -fprint \"$dest\"", true},
		{"exec copy onto the hook", "find . -exec cp " + ordinary + " " + hook + " \\;", true},
		{"execdir copy onto the hook", "find . -execdir cp " + ordinary + " " + hook + " \\;", true},
		{"ok copy onto the hook", "find . -ok cp " + ordinary + " " + hook + " \\;", true},
		{"okdir copy onto the hook", "find . -okdir cp " + ordinary + " " + hook + " \\;", true},
		{"exec copy onto a known hook", "dest=" + hook + "; find . -exec cp " + ordinary + " \"$dest\" \\;", true},
		{"execdir copy onto a known link", "dest=" + link + "; find . -execdir cp " + ordinary + " \"$dest\" \\;", true},
		{"delete the hook", "find " + hook + " -delete", true},
		{"fprint onto the hook after a dynamic root", "root=.; find \"$root\" -fprint " + hook, true},
		{"fprint onto the hook after a dynamic pattern", "root=.; pattern=cp; find \"$root\" -name \"$pattern\" -fprint " + hook, true},
		{"execdir copy onto the hook after a dynamic root", "root=.; find \"$root\" -execdir cp " + ordinary + " " + hook + " \\;", true},
		{"fprint onto an ordinary file", "find . -fprint " + ordinary + ".list", false},
		{"fprintf onto an ordinary file", "find . -fprintf " + ordinary + ".list %p", false},
		{"exec copy onto an ordinary file", "find . -exec cp {} " + ordinary + ".copy \\;", false},
		{"execdir echo", "find . -execdir echo cp {} \\;; cat " + hook, false},
		{"dynamic root before a name", "root=.; pattern=cp; find \"$root\" -name \"$pattern\"; cat " + hook, false},
		{"working directory root before a path", "pattern=cp; find \"$PWD\" -path \"$pattern\" -print; cat " + hook, false},
		{"dynamic root with a name and a format", "root=.; find \"$root\" -name cp -printf %p; cat " + hook, false},
		{"files0-from file", "roots_file=/dev/null; find -files0-from \"$roots_file\" -name \"$pattern\"; cat " + hook, false},
		{"dynamic root with a type and print", "root=.; find \"$root\" -type f -print; cat " + hook, false},
		{"delete is a name pattern", "find . -name -delete; cat " + hook, false},
		{"fprint is a print format", "find . -printf -fprint; cat " + hook, false},
		{"dynamic root and read-only exec", "root=.; find \"$root\" -exec echo cp {} \\; ; cat " + hook, false},
		{"dynamic root and read-only execdir", "root=.; find \"$root\" -execdir echo rm {} \\; ; cat " + hook, false},
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
