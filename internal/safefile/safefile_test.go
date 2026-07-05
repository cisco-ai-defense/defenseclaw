// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safefile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteCreatesFile0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	want := []byte("dont-leak-me")
	if err := Write(path, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("contents mismatch: got %q want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); runtime.GOOS != "windows" && mode != 0o600 {
		t.Errorf("file mode = %o; want 0600", mode)
	}
}

func TestWriteOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := Write(path, []byte("new")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("got %q; want %q", got, "new")
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); runtime.GOOS != "windows" && mode != 0o600 {
		t.Errorf("file mode = %o; want 0600", mode)
	}
}

func TestWriteDoesNotChangeSharedParentMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory-mode regression")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(dir, "secret"), []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("shared parent mode = %o, want preserved 750", got)
	}
}

func TestWriteRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("real"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := Write(link, []byte("attack")); err == nil {
		t.Errorf("Write through symlink: want error, got nil")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "real" {
		t.Errorf("symlink target was modified: %q", got)
	}
}

func TestCreateExclusiveRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := CreateExclusive(path); err == nil {
		t.Errorf("CreateExclusive on existing path: want error, got nil")
	}
}

func TestCreateExclusiveCreates0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	f, err := CreateExclusive(path)
	if err != nil {
		t.Fatalf("CreateExclusive: %v", err)
	}
	if _, err := f.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); runtime.GOOS != "windows" && mode != 0o600 {
		t.Errorf("file mode = %o; want 0600", mode)
	}
}
