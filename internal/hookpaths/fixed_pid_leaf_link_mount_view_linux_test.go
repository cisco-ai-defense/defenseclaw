package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// foreignMountViews lists the ways the mount view of another process can
// differ from the view of the hook. Each entry installs one of them; restore
// puts the hook reading back.
func foreignMountViews(t *testing.T) (views map[string]func(), restore func()) {
	t.Helper()
	other, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	own := readProcMountView
	restore = func() { readProcMountView = own }
	t.Cleanup(restore)
	foreign := func(namespace os.FileInfo, table string) func() {
		return func() {
			readProcMountView = func(dir string) (procMountView, error) {
				view, err := own(dir)
				if err == nil && dir != "/proc/thread-self" {
					if namespace != nil {
						view.namespace = namespace
					}
					view.table += table
				}
				return view, err
			}
		}
	}
	return map[string]func(){
		"other namespace":   foreign(other, ""),
		"other mount table": foreign(nil, "99 1 0:1 / /private rw - tmpfs tmpfs rw\n"),
		"unreadable": func() {
			readProcMountView = func(string) (procMountView, error) { return procMountView{}, os.ErrPermission }
		},
		"oversized": func() {
			readProcMountView = func(string) (procMountView, error) { return procMountView{}, errProcMountTableTooLarge }
		},
	}, restore
}

// A path that ends at an explicit-id process link reads the file the link
// names, whatever mount tree that process has; only a path below a directory
// link is resolved in that tree. An ordinary file stays allowed through its
// descriptor and executable links, and a protected file stays uncertain.
func TestFixedPIDLeafFileLinkIgnoresTheMountView(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	if err := os.MkdirAll(filepath.Dir(protected), 0700); err != nil {
		t.Fatal(err)
	}
	ordinaryPath := filepath.Join(root, "notes.txt")
	for path, text := range map[string]string{protected: "protected", ordinaryPath: "ordinary"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ordinary, err := os.Open(ordinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	guarded, err := os.Open(protected)
	if err != nil {
		t.Fatal(err)
	}
	defer guarded.Close()

	pid, tid := os.Getpid(), syscall.Gettid()
	descriptor := func(f *os.File) []string {
		return []string{
			fmt.Sprintf("/proc/%d/fd/%d", pid, f.Fd()),
			fmt.Sprintf("/proc/%d/task/%d/fd/%d", pid, tid, f.Fd()),
		}
	}
	ordinaryLinks := append(descriptor(ordinary),
		fmt.Sprintf("/proc/%d/exe", pid),
		fmt.Sprintf("/proc/%d/task/%d/exe", pid, tid))

	views, restore := foreignMountViews(t)
	views["shared tree"] = func() {}
	for name, set := range views {
		restore()
		set()
		for _, link := range ordinaryLinks {
			if !fixedPIDLeafProved(link) {
				t.Errorf("%s: link %q not proved as a leaf", name, link)
			}
			if got := ProtectedReach(link, home, NewTargetMemo()); got != GradeNone {
				t.Errorf("%s: ordinary link %q grade=%s, want None", name, link, got)
			}
			if got := LateCallGrade("cat "+link, root, home); got != GradeNone {
				t.Errorf("%s: command on ordinary link %q grade=%s, want None", name, link, got)
			}
		}
		for _, link := range descriptor(guarded) {
			if got := ProtectedReach(link, home, NewTargetMemo()); got == GradeNone {
				t.Errorf("%s: protected link %q grade=None", name, link)
			}
			if got := LateCallGrade("cat "+link, root, home); got == GradeNone {
				t.Errorf("%s: command on protected link %q grade=None", name, link)
			}
		}
	}
}
