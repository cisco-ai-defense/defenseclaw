// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestGAP1173PythonArchiveDestinations(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, command := range []string{
		`python3 -c 'import tarfile; tarfile.open("archive.tar").extractall("` + filepath.ToSlash(state) + `")'`,
		`python3 -c 'import zipfile; zipfile.ZipFile("archive.zip").extractall("` + filepath.ToSlash(state) + `")'`,
		`python3 -c 'import shutil; shutil.unpack_archive("archive.zip", "` + filepath.ToSlash(state) + `")'`,
	} {
		if paths := ArchiveExtractionPaths(command, cwd, home); !slices.Contains(paths, state) {
			t.Errorf("archive path reader missed destination: %q", paths)
		}
	}
}

func TestGAP1173ArchiveStatementDirectory(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	if got := ArchiveExtractionPaths(`cd ~/.defenseclaw && tar -xf archive.tar`, cwd, home); !slices.Contains(got, state) {
		t.Errorf("placed extraction: %q", got)
	}
	if runtime.GOOS == "windows" {
		command := `tar -xf archive.tar -C ` + filepath.Join(home, ".defenseclaw")
		if got := ArchiveExtractionPaths(command, cwd, home); !slices.Contains(got, state) {
			t.Errorf("native separator reading: %q", got)
		}
	}
}
