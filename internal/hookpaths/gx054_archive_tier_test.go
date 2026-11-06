// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestGX054UnreadArchiveScopesByTier(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(cwd, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cwd, "app", "pkg")
	for _, command := range []string{
		"tar -xzf missing.tgz -C app && cp -r app/pkg-1.0 app/pkg",
		"unzip -q pkg.zip -d app && cp -r app/pkg-1.0 app/pkg",
		"7z x pkg.7z -oapp && cp -r app/pkg-1.0 app/pkg",
		"cpio -id -D app < pkg.cpio && cp -r app/pkg-1.0 app/pkg",
	} {
		strict := CommandLinksWithFactsForTier("Bash", command, cwd, home, nil, false)
		balanced := CommandLinksWithFactsForTier("Bash", command, cwd, home, nil, true)
		if !strict.OpaqueTargetWithFacts(target, false, nil) || balanced.OpaqueTargetWithFacts(target, false, nil) {
			t.Errorf("%q: strict=%t balanced=%t", command, strict.OpaqueTargetWithFacts(target, false, nil), balanced.OpaqueTargetWithFacts(target, false, nil))
		}
	}
}

type gx054Zeros struct{}

func (gx054Zeros) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func TestGX054CompressedTarStreamBoundRetainsScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.tgz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zipped := gzip.NewWriter(file)
	writer := tar.NewWriter(zipped)
	const size = maxTarPlainBytes + 1<<20
	if err := writer.WriteHeader(&tar.Header{Name: "large", Typeflag: tar.TypeReg, Size: size, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(writer, gx054Zeros{}, size); err != nil {
		t.Fatal(err)
	}
	for _, closeWriter := range []io.Closer{writer, zipped, file} {
		if err := closeWriter.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := tarArchiveKind(path); got != 2 {
		t.Fatalf("compressed stream over bound classified %d, want conservative evidence", got)
	}
}

func TestGX054TarEvidenceRetainsScope(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(cwd, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, "link.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys", Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	command := "tar -xf link.tar -C app && echo k >> app/p"
	target := filepath.Join(cwd, "app", "p")
	facts := map[string]string{}
	_ = commandLinksWithFacts(command, cwd, home, facts, true)
	if facts[TarLinkFactPrefix+path] != "1" {
		t.Fatalf("client did not record tar evidence: %v", facts)
	}
	if !CommandLinksWithFactsForTier("Bash", command, cwd, home, facts, true).OpaqueTargetWithFacts(target, false, nil) {
		t.Fatal("balanced lost known tar evidence")
	}
}

func TestGX054ProtectedMoveNamesAndToolMapping(t *testing.T) {
	for _, row := range []struct {
		command   string
		protected bool
	}{
		{"tar -xf missing.tar -C app && mv app/pkg-1.0 app/pkg", false},
		{"tar -xf missing.tar -C app && mv app/authorized_keys app/pkg", true},
		{"tar -xf missing.tar -C app && mv app/.ssh app/pkg", true},
		{"tar -xf missing.tar -C app && mv --suffix=_keys authorized app/pkg", true},
		{"F=app/authorized_keys; tar -xf missing.tar -C app && mv \"$F\" app/pkg", true},
		{"D=app/authorized_keys; tar -xf missing.tar -C app && mv app/pkg \"$D\"", true},
		{"tar -xf missing.tar -C app && mv conf/config.sample conf/config", false},
		{"tar -czf out.tar conf && mv conf/config.sample conf/config", false},
		{"tar -tf out.tar && mv conf/rc.sample conf/rc", false},
		{"tar -xf missing.tar -C app && mv conf/environment.sample conf/environment", false},
		{"tar -xf missing.tar -C app && mv conf/config.sample ~/.ssh/config", true},
		{"tar -xf missing.tar -C app && mv ~/.ssh/environment conf/environment", true},
	} {
		if got := ProtectedArchiveMoveName(row.command, "/home/test/project", "/home/test"); got != row.protected {
			t.Errorf("%q: got %t", row.command, got)
		}
	}
	for _, tool := range []string{"patch", "apply_patch"} {
		if got := ConnectorActionTool("opencode", tool); got != "apply_patch" {
			t.Errorf("%q mapped to %q", tool, got)
		}
	}
	if got := ConnectorActionTool("hermes", "patch"); got != "patch" {
		t.Errorf("Hermes tool changed to %q", got)
	}
}

func TestGX054NamedSSHWriteOperand(t *testing.T) {
	for _, row := range []struct {
		command string
		want    bool
	}{
		{"unzip -q pkg.zip -d app && cp -r app/pkg/. ~/.ssh/", true},
		{"unzip -q pkg.zip -d app && rsync -a app/pkg/ $HOME/.ssh/", true},
		{"unzip -q pkg.zip -d ~/.ssh && echo ok > notes.txt", true},
		{"tar -xf x.tar -C app && ln -s pkg app/current", false},
		{"tar -xf x.tar -C app && mv conf/config.sample conf/config", false},
	} {
		if got := NamedSSHWriteOperand(row.command, "/home/test/project", "/home/test"); got != row.want {
			t.Errorf("%q: got %t, want %t", row.command, got, row.want)
		}
	}
}
