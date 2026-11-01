// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// r107WriteTar writes a tar archive of headers (a body "x\n" for each
// regular file), gzip compressed when zipped.
func r107WriteTar(t *testing.T, path string, zipped bool, headers ...tar.Header) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out io.Writer = file
	var zw *gzip.Writer
	if zipped {
		zw = gzip.NewWriter(file)
		out = zw
	}
	tw := tar.NewWriter(out)
	for _, header := range headers {
		header := header
		if header.Typeflag == tar.TypeReg {
			header.Size = 2
		}
		header.Mode = 0o600
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("x\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestR107CopyOfAPlainExtractionIsPlain: a tar archive the hook client
// reads holds only regular files, so extracting it makes no link and a
// copy of the extracted folder (cp -a, rsync -a), or the folder itself,
// is written as plain files, per user and managed (rel-1-0-6:GAP-0339).
// An archive with a symbolic link, a hard link or a .. name, an archive
// the command rewrites first, and a destination folder that already holds
// a keys link keep blocking.
func TestR107CopyOfAPlainExtractionIsPlain(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg} }
		r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false, tar.Header{Name: "sub/", Typeflag: tar.TypeDir}, reg("p"), reg("sub/q"))
		r107WriteTar(t, filepath.Join(f.project, "plain.tgz"), true, reg("p"))
		r107WriteTar(t, filepath.Join(f.project, "link.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
		r107WriteTar(t, filepath.Join(f.project, "hard.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeLink, Linkname: "../.ssh/authorized_keys"})
		r107WriteTar(t, filepath.Join(f.project, "dotdot.tar"), false, reg("../p"))
		if err := os.MkdirAll(filepath.Join(f.project, "d0"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(f.keys, filepath.Join(f.project, "d0", "p")); err != nil {
			t.Fatal(err)
		}
	}
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"plain tar, cp -a of the folder, append to the copy", "project", `tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "allow"},
		{"plain tar, rsync -a of the folder, append to the copy", "project", `tar -xf plain.tar -C d1 && rsync -a d1/ e2/ && echo k >> e2/p`, "allow"},
		{"plain tar, append into the folder", "project", `tar -xf plain.tar -C d1 && echo k >> d1/sub/q`, "allow"},
		{"plain tgz, cp -a of the folder, append to the copy", "project", `tar -xzf plain.tgz -C d1 && cp -a d1 e3 && echo k >> e3/p`, "allow"},
		{"symlink tar, cp -a, append to the copy", "project", `tar -xf link.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "block"},
		{"symlink tar, append into the folder", "project", `tar -xf link.tar -C d1 && echo k >> d1/p`, "block"},
		{"hard link tar, cp -a, append to the copy", "project", `tar -xf hard.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "block"},
		{"dot-dot tar, append", "project", `tar -xf dotdot.tar -C d1 && echo k >> d1/p`, "block"},
		{"archive rewritten first", "project", `cp link.tar plain.tar; tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "block"},
		{"plain tar into a folder holding a keys link, append through it", "project", `tar -xf plain.tar -C d0 && echo k >> d0/p`, "block"},
		{"plain tar into a folder holding a keys link, cp -a, append to the copy", "project", `tar -xf plain.tar -C d0 && cp -a d0 e4 && echo k >> e4/p`, "block"},
		{"write into the extraction scope (fake archive)", "project", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "block"},
	}, setup)
}
