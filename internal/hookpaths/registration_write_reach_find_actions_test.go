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
	source := filepath.Join(root, "source")
	for _, path := range []string{hook, ordinary, source} {
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
		{"exec chmod on a search root that is the hook", "find " + hook + " -exec chmod 000 {} \\;", true},
		{"exec copy onto a known hook root", "root=" + hook + "; find \"$root\" -exec cp " + ordinary + " {} \\;", true},
		{"exec copy onto a link root", "find " + link + " -exec cp " + ordinary + " {} \\;", true},
		{"execdir copy onto the hook root", "find " + hook + " -execdir cp " + ordinary + " {} \\;", true},
		{"execdir copy onto the hook by its relative name", "find " + hook + " -execdir cp " + ordinary + " defenseclaw-hook-user \\;", true},
		{"execdir copy onto a link root", "find " + link + " -execdir cp " + ordinary + " {} \\;", true},
		{"execdir copy by relative name from the folder", "find " + bin + " -name defenseclaw-hook-user -execdir cp " + ordinary + " defenseclaw-hook-user \\;", true},
		{"execdir copy onto a name-matched file", "find " + bin + " -name \"defenseclaw-hook-*\" -execdir cp " + ordinary + " {} \\;", true},
		{"okdir chmod on a case-folded name match", "find " + bin + " -iname DEFENSECLAW-HOOK-USER -okdir chmod 000 {} \\;", true},
		{"exec chmod on a path-matched file", "find " + bin + " -path \"*-hook-user\" -exec chmod 000 {} +", true},
		{"exec env copy onto the hook", "find . -exec env cp " + ordinary + " " + hook + " \\;", true},
		{"execdir env copy onto the hook", "find . -execdir env cp " + ordinary + " " + hook + " \\;", true},
		{"execdir timeout copy onto the hook", "find . -execdir timeout 5 cp " + ordinary + " " + hook + " \\;", true},
		{"execdir wrapped chmod on the hook root", "find " + hook + " -execdir env chmod 000 {} \\;", true},
		{"exec copy onto an ordinary root", "find " + ordinary + " -exec cp " + source + " {} \\;", false},
		{"execdir copy onto an ordinary relative name", "find " + ordinary + " -execdir cp " + source + " ordinary \\;", false},
		{"execdir copy onto an unmatched name in the hook folder", "find " + bin + " -name \"other-*\" -execdir cp " + ordinary + " {} \\;", false},
		{"exec chmod under a negated name test", "find " + bin + " ! -name defenseclaw-hook-user -exec chmod 000 {} \\;", false},
		{"exec read of the hook root", "find " + hook + " -exec cat {} \\;", false},
		{"execdir wrapped read of the hook root", "find " + hook + " -execdir env sha256sum {} \\;", false},
		{"execdir wrapped read of the hook by name", "find . -execdir env cat " + hook + " \\;", false},
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
