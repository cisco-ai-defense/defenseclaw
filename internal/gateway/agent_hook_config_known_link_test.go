package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAgentHookConfigKnownLinkPlacement pins that a link is judged by where it
// is placed: operands bound earlier in the same command resolve before the
// destination is compared with the registered hook files, and a link that
// does not place a registered file (or is never run) is untouched.
func TestAgentHookConfigKnownLinkPlacement(t *testing.T) {
	h := newGAP0048Home(t)
	bin := filepath.Join(h.home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	named := filepath.Join(h.ext, "source", "defenseclaw-hook-user")
	ordinary := filepath.Join(h.ext, "source", "ordinary-tool")
	otherBin := filepath.Join(h.ext, "other-bin")
	for _, path := range []string{hook, named, ordinary} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(otherBin, 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"literal protected", "ln -sf " + named + " " + bin + "/", "block"},
		{"bound source", "src=" + named + "; ln -sf \"$src\" " + bin + "/", "block"},
		{"bound destination", "dest=" + bin + "; ln -sf " + named + " \"$dest\"/", "block"},
		{"bound file name", "name=defenseclaw-hook-user; ln -sf " + ordinary + " " + bin + "/\"$name\"", "block"},
		{"change to bin then link by source name", "cd " + bin + " && ln -sf " + named, "block"},
		{"called function", "link_hook() { ln -sf " + named + " " + bin + "/; }; link_hook", "block"},
		{"change to bin then link an ordinary source", "cd " + bin + " && ln -sf " + ordinary, "allow"},
		{"uncalled function", "link_hook() { ln -sf " + named + " " + bin + "/; }; echo ready", "block"},
		{"ordinary source", "src=" + ordinary + "; ln -sf \"$src\" " + bin + "/", "allow"},
		{"ordinary destination", "dest=" + otherBin + "; ln -sf " + named + " \"$dest\"/", "allow"},
		{"read-only link to the hook in a temporary folder", "ln -s " + hook + " " + otherBin + "/tmp-link && ls " + otherBin, "block"},
		// A writer name that is only an operand of another program is text.
		{"checksum after echo of a writer name", "echo cp && sha256sum " + hook, "allow"},
		{"read after echo of a writer name", "echo rm; cat " + hook, "allow"},
		{"read after printf of a writer name", "printf \"%s\\n\" ln && cat " + hook, "allow"},
		{"checksum after echo of a shell name", "echo bash; sha256sum " + hook, "allow"},
		// A dispatcher is judged by the program it runs.
		{"search for a writer name through git", "git grep cp -- README.md; cat " + hook, "allow"},
		{"echo of a writer name through busybox", "busybox echo cp; cat " + hook, "allow"},
		{"echo of a writer name through flock", "flock /tmp/lock echo cp; cat " + hook, "allow"},
		{"echo of a writer name through xargs", "printf x | xargs echo cp; cat " + hook, "allow"},
		{"find lists with a dynamic name pattern", "find . -name \"$pattern\"; cat " + hook, "allow"},
		{"find lists with a dynamic path pattern", "find . -type f -path \"$pattern\" -mtime -1; cat " + hook, "allow"},
		{"find executes a copy onto the hook after a dynamic pattern", "echo a; find . -name \"$pattern\" -exec cp " + ordinary + " " + hook + " \\;", "block"},
		{"find lists from a dynamic root", "root=.; pattern=cp; find \"$root\" -name \"$pattern\"; cat " + hook, "allow"},
		{"find lists from the working-directory root", "find \"$PWD\" -name \"$pattern\"; cat " + hook, "allow"},
		{"find lists roots read from a dynamic file", "roots_file=/dev/null; find -files0-from \"$roots_file\" -name \"$pattern\"; cat " + hook, "allow"},
		{"find prints a format from a dynamic root", "find \"$root\" -name x -printf \"%p\\n\"; cat " + hook, "allow"},
		{"find prints into the hook after a dynamic root", "echo a; find \"$root\" -fprint " + hook, "block"},
		{"find deletes the hook after a dynamic root", "echo a; find \"$root\" -name \"$pattern\" -delete; cat " + hook, "block"},
		{"find executes a copy onto the hook from a dynamic root", "echo a; find \"$root\" -exec cp " + ordinary + " " + hook + " \\;", "block"},
		{"remove the hook through git", "echo a; git rm " + hook, "block"},
		{"copy onto the hook through flock", "echo a; flock /tmp/lock cp " + ordinary + " " + hook, "block"},
		{"copy onto the hook through busybox", "echo a; busybox cp " + ordinary + " " + hook, "block"},
		{"copy onto the hook through xargs", "echo a; printf x | xargs cp " + ordinary + " " + hook, "block"},
		{"copy onto the hook after echo", "echo a; cp " + ordinary + " " + hook, "block"},
		{"copy onto the hook through a wrapper after echo", "echo a; nice -n 5 cp " + ordinary + " " + hook, "block"},
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
