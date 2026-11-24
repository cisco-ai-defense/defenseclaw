//go:build linux

package actionfacts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type credentialWalkEntry struct {
	name   string
	folder bool
}

func credentialWalkEntriesOf(dir string, stopAfter int) []credentialWalkEntry {
	var got []credentialWalkEntry
	readCredentialWalkFolder(dir, func(name []byte, folder, _ bool, _ int) bool {
		got = append(got, credentialWalkEntry{string(name), folder})
		return stopAfter <= 0 || len(got) < stopAfter
	})
	return got
}

func credentialWalkEntriesReadDir(dir string) []credentialWalkEntry {
	var got []credentialWalkEntry
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	for {
		batch, err := f.ReadDir(512)
		for _, entry := range batch {
			got = append(got, credentialWalkEntry{entry.Name(), entry.IsDir()})
		}
		if err != nil || len(batch) < 512 {
			return got
		}
	}
}

// The walk's folder read on Linux decodes getdents64 itself
// (substrate-1:GAP-0709): it must give the entries, order and types
// os.File.ReadDir gives, in a folder larger than one read buffer too, and
// stop where each stops.
func TestGAP0709WalkFolderReadMatchesReadDir(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "big")
	if err := os.Mkdir(big, 0o755); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("n", 120)
	for i := 0; i < 700; i++ {
		name := filepath.Join(big, long+strconv.Itoa(i))
		var err error
		switch i % 4 {
		case 0:
			err = os.Mkdir(name, 0o755)
		case 1:
			err = os.WriteFile(name, nil, 0o600)
		case 2:
			err = os.Symlink(root, name) // a link to a folder is not a folder
		default:
			err = os.WriteFile(filepath.Join(big, "."+strconv.Itoa(i)), nil, 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".git", ".aws", "..x", "eé"} {
		if err := os.Mkdir(filepath.Join(big, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shut := filepath.Join(root, "shut")
	if err := os.Mkdir(shut, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shut, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shut, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shut, 0o755) })
	link := filepath.Join(root, "link")
	if err := os.Symlink(big, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{big, root, shut, link, file, empty, filepath.Join(root, "absent")} {
		got, want := credentialWalkEntriesOf(dir, 0), credentialWalkEntriesReadDir(dir)
		if len(got) != len(want) {
			t.Fatalf("%s: %d entries, ReadDir %d", filepath.Base(dir), len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s entry %d: %+v, ReadDir %+v", filepath.Base(dir), i, got[i], want[i])
			}
		}
	}
	if n := len(credentialWalkEntriesReadDir(big)); n != 704 {
		t.Fatalf("big folder has %d entries, want 704", n)
	}
	if got := credentialWalkEntriesOf(big, 300); len(got) != 300 {
		t.Fatalf("stopped read gave %d entries, want 300", len(got))
	}
	// The read allocates nothing per entry (the 8 MB walk of GAP-0709).
	allocs := testing.AllocsPerRun(20, func() {
		readCredentialWalkFolder(big, func([]byte, bool, bool, int) bool { return true })
	})
	if allocs > 8 {
		t.Fatalf("reading a 704-entry folder allocates %.0f times, want at most 8", allocs)
	}
}
