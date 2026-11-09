package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistrationWriteReachKnownLinkPlacement(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	named := filepath.Join(root, "source", "defenseclaw-hook-user")
	ordinary := filepath.Join(root, "source", "ordinary-tool")
	otherBin := filepath.Join(root, "other-bin")
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
	rows := []struct {
		name, command string
		want          bool
	}{
		{"literal protected", "ln -sf " + named + " " + bin + "/", true},
		{"bound source", "src=" + named + "; ln -sf \"$src\" " + bin + "/", true},
		{"bound destination", "dest=" + bin + "; ln -sf " + named + " \"$dest\"/", true},
		{"bound file name", "name=defenseclaw-hook-user; ln -sf " + ordinary + " " + bin + "/\"$name\"", true},
		{"bound hook file", "dest=" + hook + "; ln -sf " + ordinary + " \"$dest\"", true},
		{"change to bin then link by source name", "cd " + bin + " && ln -sf " + named, true},
		{"called function", "link_hook() { ln -sf " + named + " " + bin + "/; }; link_hook", true},
		{"change to bin then link an ordinary source", "cd " + bin + " && ln -sf " + ordinary, false},
		{"uncalled function", "link_hook() { ln -sf " + named + " " + bin + "/; }; echo ready", true},
		{"ordinary source", "src=" + ordinary + "; ln -sf \"$src\" " + bin + "/", false},
		{"ordinary destination", "dest=" + otherBin + "; ln -sf " + named + " \"$dest\"/", false},
		{"two-operand link of a state folder under a new name", "cd " + filepath.Join(home, ".local") + " && ln -s bin dc && ls dc", false},
		{"unbound destination", "ln -sf " + named + " \"$unset_dest\"/", false},
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
