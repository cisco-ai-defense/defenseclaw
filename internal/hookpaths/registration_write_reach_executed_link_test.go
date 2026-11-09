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
