//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicWriteWithLock_BasicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	content := []byte("version: 1\n")
	if err := AtomicWriteWithLock(path, content, 0o600); err != nil {
		t.Fatalf("AtomicWriteWithLock: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

func TestAtomicWriteWithLock_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	newContent := []byte("new content")
	if err := AtomicWriteWithLock(path, newContent, 0o600); err != nil {
		t.Fatalf("AtomicWriteWithLock: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(newContent) {
		t.Errorf("content mismatch: got %q, want %q", got, newContent)
	}
}

func TestAtomicWriteWithLock_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "test.yaml")

	content := []byte("test")
	if err := AtomicWriteWithLock(path, content, 0o600); err != nil {
		t.Fatalf("AtomicWriteWithLock: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

func TestAtomicWriteWithLock_PreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	if err := AtomicWriteWithLock(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("AtomicWriteWithLock: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("permissions: got %o, want %o", perm, 0o644)
	}
}

func TestAtomicWriteWithLock_NoTempFileLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	if err := AtomicWriteWithLock(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("AtomicWriteWithLock: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		name := e.Name()
		if name != "test.yaml" && name != "test.yaml.lock" {
			t.Errorf("unexpected file left behind: %s", name)
		}
	}
}

func TestAtomicWriteWithLock_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	var wg sync.WaitGroup
	writers := 10

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			content := []byte("writer " + string(rune('A'+n)) + "\n")
			if err := AtomicWriteWithLock(path, content, 0o600); err != nil {
				t.Errorf("writer %d: %v", n, err)
			}
		}(i)
	}

	wg.Wait()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("file should not be empty after concurrent writes")
	}
}
