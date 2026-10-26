// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisestatus

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A lookup on a stalled FUSE or NFS mount blocks in the kernel. Made by a
// thread of status or verify, it kept the process from exiting after it had
// printed its answer (GAP-1714, GAP-1469): the lookup runs in a stat(1)
// child, which identifies directories as os.Stat does.
func TestLaunchPathLookupRunsOutOfProcess(t *testing.T) {
	if info, err := os.Lstat(launchPathStatProgram); err != nil || !info.Mode().IsRegular() {
		t.Skipf("%s is not available", launchPathStatProgram)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	// A path stat(1) would read as an option.
	dash := filepath.Join(root, "-L")
	if err := os.Mkdir(dash, 0o700); err != nil {
		t.Fatal(err)
	}

	program := launchPathStatProgram
	missing := filepath.Join(root, "no-such-stat")
	inProcess := 0
	lookup := func(path string) (launchDirIdentity, error) {
		launchPathStatProgram = missing
		defer func() { launchPathStatProgram = program }()
		inProcess++
		return lookupLaunchPathOutOfProcess(path)
	}
	for _, path := range []string{dir, link, file, other, dash} {
		child, err := lookupLaunchPathOutOfProcess(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		local, err := lookup(path)
		if err != nil {
			t.Fatal(err)
		}
		if child != local {
			t.Fatalf("%s: stat(1) gives %+v, os.Stat gives %+v", path, child, local)
		}
	}
	a, _ := lookupLaunchPathOutOfProcess(dir)
	b, _ := lookupLaunchPathOutOfProcess(link)
	c, _ := lookupLaunchPathOutOfProcess(other)
	f, _ := lookupLaunchPathOutOfProcess(file)
	if !sameLaunchDirIdentity(a, b) || sameLaunchDirIdentity(a, c) || sameLaunchDirIdentity(f, f) {
		t.Fatalf("identities: dir %+v link %+v other %+v file %+v", a, b, c, f)
	}
	for _, path := range []string{filepath.Join(root, "absent"), filepath.Join(file, "below")} {
		_, childErr := lookupLaunchPathOutOfProcess(path)
		_, localErr := lookup(path)
		if errors.Is(localErr, fs.ErrNotExist) != errors.Is(childErr, fs.ErrNotExist) || childErr == nil {
			t.Fatalf("%s: stat(1) error %v, os.Stat error %v", path, childErr, localErr)
		}
	}
	if inProcess == 0 {
		t.Fatal("the in-process comparison never ran")
	}
}

// statLaunchPath must not look a path up in this process when stat(1) is
// there: the default lookup is the out-of-process one.
func TestLaunchPathDefaultLookupIsOutOfProcess(t *testing.T) {
	if launchPathStat == nil {
		t.Fatal("no lookup")
	}
	if info, err := os.Lstat(launchPathStatProgram); err != nil || !info.Mode().IsRegular() {
		t.Skipf("%s is not available", launchPathStatProgram)
	}
	dir := t.TempDir()
	program := launchPathStatProgram
	// A stat(1) that cannot run makes the default lookup fail, which an
	// in-process lookup would not.
	fake := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	launchPathStatProgram = fake
	t.Cleanup(func() { launchPathStatProgram = program })
	if _, err := statLaunchPath(dir); err == nil {
		t.Fatal("statLaunchPath answered without the stat(1) child: the lookup still runs in this process")
	}
}
