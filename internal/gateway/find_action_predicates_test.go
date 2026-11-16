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
	bin := filepath.Dir(hook)
	ordinary := filepath.Join(h.ext, "ordinary")
	source := filepath.Join(h.ext, "source")
	for _, path := range []string{hook, ordinary, source} {
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
	rows := []hookConfigShellRow{
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
		{"exec chmod on a search root that is the hook", "find " + hook + " -exec chmod 000 {} \\;", "block"},
		{"exec copy onto a known hook root", "root=" + hook + "; find \"$root\" -exec cp " + ordinary + " {} \\;", "block"},
		{"exec copy onto a link root", "find " + link + " -exec cp " + ordinary + " {} \\;", "block"},
		{"execdir copy onto the hook root", "find " + hook + " -execdir cp " + ordinary + " {} \\;", "block"},
		{"execdir copy onto the hook by its relative name", "find " + hook + " -execdir cp " + ordinary + " defenseclaw-hook-user \\;", "block"},
		{"execdir copy onto a link root", "find " + link + " -execdir cp " + ordinary + " {} \\;", "block"},
		{"execdir copy by relative name from the folder", "find " + bin + " -name defenseclaw-hook-user -execdir cp " + ordinary + " defenseclaw-hook-user \\;", "block"},
		{"execdir copy onto a name-matched file", "find " + bin + " -name \"defenseclaw-hook-*\" -execdir cp " + ordinary + " {} \\;", "block"},
		{"okdir chmod on a case-folded name match", "find " + bin + " -iname DEFENSECLAW-HOOK-USER -okdir chmod 000 {} \\;", "block"},
		{"exec chmod on a path-matched file", "find " + bin + " -path \"*-hook-user\" -exec chmod 000 {} +", "block"},
		{"exec env copy onto the hook", "find . -exec env cp " + ordinary + " " + hook + " \\;", "block"},
		{"execdir env copy onto the hook", "find . -execdir env cp " + ordinary + " " + hook + " \\;", "block"},
		{"execdir timeout copy onto the hook", "find . -execdir timeout 5 cp " + ordinary + " " + hook + " \\;", "block"},
		{"execdir wrapped chmod on the hook root", "find " + hook + " -execdir env chmod 000 {} \\;", "block"},
		{"exec copy onto an ordinary root", "find " + ordinary + " -exec cp " + source + " {} \\;", "allow"},
		{"execdir copy onto an ordinary relative name", "find " + ordinary + " -execdir cp " + source + " ordinary \\;", "allow"},
		{"execdir copy onto an unmatched name in the hook folder", "find " + bin + " -name \"other-*\" -execdir cp " + ordinary + " {} \\;", "allow"},
		{"exec chmod under a negated name test", "find " + bin + " ! -name defenseclaw-hook-user -exec chmod 000 {} \\;", "allow"},
		{"exec read of the hook root", "find " + hook + " -exec cat {} \\;", "allow"},
		{"execdir wrapped read of the hook by name", "find . -execdir env cat " + hook + " \\;", "allow"},
	}
	checkHookConfigShellRows(t, h, rows)
}
