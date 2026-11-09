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
