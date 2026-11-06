// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package hookpaths

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

func TestGX054ExtractedProtectedLinkCopier(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, "sshdir.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	if err := tw.WriteHeader(&tar.Header{Name: "s", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	command := "tar -xf ~/project/sshdir.tar -C ~/project/d1 && install -m 600 ~/project/a.txt $HOME/project/d1/s/rc"
	dest := filepath.Join(cwd, "d1")
	members := tarProtectedLinkMembers(path, dest, home)
	t.Logf("members=%v writes=%v move=%t", members, LiteralWriteOperands(command, cwd, home), ProtectedArchiveMoveName(command, cwd, home, nil))
	if !ProtectedArchiveMoveName(command, cwd, home, nil) {
		t.Fatal("extracted protected link not applied to copier")
	}
}
