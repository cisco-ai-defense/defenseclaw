// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestActionGlobOpenDirRejectsFIFOWithoutBlocking(t *testing.T) {
	name := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(name, 0o600); err != nil {
		t.Fatal(err)
	}
	assertGlobNotDirectory(t, name)
}

func TestActionGlobOpenDirRejectsFilesAndFollowsDirectoryAliases(t *testing.T) {
	home := t.TempDir()
	dir, file := filepath.Join(home, "dir"), filepath.Join(home, "file")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fileAlias, dirAlias := filepath.Join(home, "file-alias"), filepath.Join(home, "dir-alias")
	for alias, target := range map[string]string{fileAlias: file, dirAlias: dir} {
		testSymlink(t, target, alias)
	}
	for _, name := range []string{file, fileAlias} {
		t.Run(filepath.Base(name), func(t *testing.T) { assertGlobNotDirectory(t, name) })
	}
	t.Run("directory-alias", func(t *testing.T) {
		f, err := actionGlobOpenDir(dirAlias)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		got, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !got.IsDir() || !os.SameFile(got, want) {
			t.Fatal("directory alias did not open its target directory")
		}
	})
}

// A pre-open Stat alone is insufficient: a directory matched by a previous
// glob component can become a special file before the next component lists it.
func TestActionGlobOpenDirRejectsDirectoryReplacedByFIFO(t *testing.T) {
	name := filepath.Join(t.TempDir(), "replaced")
	if err := os.Mkdir(name, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := pathStat(name)
	if err != nil || !info.IsDir() {
		t.Fatalf("initial directory stat: %v %v", info, err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(name, 0o600); err != nil {
		t.Fatal(err)
	}
	assertGlobNotDirectory(t, name)
}

func TestActionExpandGlobSkipsSpecialFilesAndRetainsDirectoryAlias(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(project, "pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(project, "keydir")
	testSymlink(t, ssh, alias)
	// Exercise the actual walker, including its ENOTDIR handling. On failure,
	// the shared bounded helper releases a regressed plain FIFO reader.
	type expansion struct {
		paths            []string
		complete, unseen bool
	}
	done := make(chan expansion, 1)
	go func() {
		paths, complete, unseen := actionExpandGlob(filepath.Join(project, "*", "*"), project, false, true, func() bool { return false })
		done <- expansion{paths, complete, unseen}
	}()
	select {
	case got := <-done:
		if !got.complete || got.unseen || !reflect.DeepEqual(got.paths, []string{filepath.Join(alias, "authorized_keys")}) {
			t.Fatalf("expansion = %+v, want only directory-alias authorized_keys and complete", got)
		}
	case <-time.After(500 * time.Millisecond):
		releaseGlobFIFOReader(pipe)
		t.Fatal("glob expansion blocked on a special file")
	}
}

func assertGlobNotDirectory(t *testing.T, name string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, err := actionGlobOpenDir(name)
		if f != nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("actionGlobOpenDir(%q) error = %v, want ENOTDIR", name, err)
		}
	case <-time.After(500 * time.Millisecond):
		releaseGlobFIFOReader(name)
		t.Fatal("directory glob blocked opening a non-directory")
	}
}

func releaseGlobFIFOReader(name string) {
	// Match the existing safefile FIFO regression's failure cleanup: connecting
	// a nonblocking writer releases a regressed plain reader without blocking
	// the test if no reader is waiting.
	if writer, err := os.OpenFile(name, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		_ = writer.Close()
	}
}
