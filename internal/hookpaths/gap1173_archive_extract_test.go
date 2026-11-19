// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// gap1173Archive writes a tar or zip archive holding members at path.
func gap1173Archive(t *testing.T, path string, members ...string) {
	t.Helper()
	var buf bytes.Buffer
	if filepath.Ext(path) == ".zip" {
		w := zip.NewWriter(&buf)
		for _, member := range members {
			f, err := w.Create(member)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("x: 1\n")); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		w := tar.NewWriter(&buf)
		for _, member := range members {
			if err := w.WriteHeader(&tar.Header{Name: member, Mode: 0o600, Size: 5, Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("x: 1\n")); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rel-1-0-10:GAP-1173: the extraction reader reads Expand-Archive, the .NET
// ZipFile ExtractToDirectory call and Python tarfile, zipfile and
// shutil.unpack_archive as it reads tar and unzip: the folder, a named
// member, and the whole archive whose members the archive tells.
func TestGAP1173ReadArchiveExtractions(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, ".defenseclaw")
	archive := func(name string) string { return filepath.Join(cwd, name) }
	type whole struct{ folder, archive string }
	for _, row := range []struct {
		name, command string
		paths         []string
		unknown       []string
		whole         []whole
	}{
		{"tar whole into home", "tar -xf a.tar -C ~", []string{home}, nil, []whole{{home, archive("a.tar")}}},
		{"unzip whole into home", "unzip -o a.zip -d ~", []string{home}, nil, []whole{{home, archive("a.zip")}}},
		{"tar named member", "tar -xf a.tar -C ~ .defenseclaw/config.yaml", []string{home, filepath.Join(state, "config.yaml")}, nil, nil},
		{"tar member list", "tar -xf a.tar -C ~ -T list", []string{home}, []string{home}, nil},
		{"python tarfile extractall", `python3 -c 'import tarfile, os; tarfile.open("a.tar").extractall(os.path.expanduser("~"))'`, []string{home}, nil, []whole{{home, archive("a.tar")}}},
		{"python tarfile with", "python3 -c 'import tarfile, os\nwith tarfile.open(\"a.tar\") as t:\n    t.extractall(path=os.path.expanduser(\"~/.defenseclaw\"))'", []string{state}, nil, []whole{{state, archive("a.tar")}}},
		{"python zipfile cwd", `python3 -c 'import zipfile; zipfile.ZipFile("a.zip").extractall()'`, []string{cwd}, nil, []whole{{cwd, archive("a.zip")}}},
		{"python extract member", `python3 -c 'import tarfile, os; tarfile.open("a.tar").extract(".defenseclaw/config.yaml", os.path.expanduser("~"))'`, []string{home, filepath.Join(state, "config.yaml")}, nil, nil},
		{"python extractall members", `python3 -c 'import tarfile, os; t = tarfile.open("a.tar"); t.extractall(os.path.expanduser("~"), members=m)'`, []string{home}, []string{home}, nil},
		{"python shutil", `python3 -c 'import shutil, os; shutil.unpack_archive("a.zip", os.path.expanduser("~"))'`, []string{home}, nil, []whole{{home, archive("a.zip")}}},
		{"python shutil keyword", `python3 -c 'import shutil, os; shutil.unpack_archive(filename="a.zip", extract_dir=os.path.expanduser("~/.defenseclaw"))'`, []string{state}, nil, []whole{{state, archive("a.zip")}}},
		{"python dynamic folder", `python3 -c 'import tarfile, sys; tarfile.open("a.tar").extractall(sys.argv[1])' x`, nil, nil, nil},
		{"python comment", "python3 -c '# tarfile.open(\"a.tar\").extractall(\"/\")\nprint(1)'", nil, nil, nil},
		{"Expand-Archive named", "Expand-Archive -Path a.zip -DestinationPath $HOME", []string{home}, nil, []whole{{home, archive("a.zip")}}},
		{"Expand-Archive positional tilde", "Expand-Archive a.zip ~/.defenseclaw -Force", []string{state}, nil, []whole{{state, archive("a.zip")}}},
		{"Expand-Archive prefix and env", `Expand-Archive -LiteralPath 'a.zip' -Dest "$env:USERPROFILE/.defenseclaw"`, []string{state}, nil, []whole{{state, archive("a.zip")}}},
		{"Expand-Archive colon value", "Expand-Archive -Path:a.zip -DestinationPath:$HOME", []string{home}, nil, []whole{{home, archive("a.zip")}}},
		{"Expand-Archive module qualified", `Microsoft.PowerShell.Archive\Expand-Archive a.zip "$HOME/.defenseclaw"`, []string{state}, nil, []whole{{state, archive("a.zip")}}},
		{"Expand-Archive current folder", "Expand-Archive -Path a.zip", []string{cwd}, nil, []whole{{cwd, archive("a.zip")}}},
		{"Expand-Archive piped archive", "Get-Item a.zip | Expand-Archive -DestinationPath $HOME", []string{home}, nil, nil},
		{"Expand-Archive WhatIf", "Expand-Archive -Path a.zip -DestinationPath $HOME -WhatIf", nil, nil, nil},
		{"Expand-Archive WhatIf false", "Expand-Archive -Path a.zip -DestinationPath $HOME -WhatIf:$false", []string{home}, nil, []whole{{home, archive("a.zip")}}},
		{"Expand-Archive dynamic folder", "Expand-Archive -Path a.zip -DestinationPath $dest", nil, nil, nil},
		{"ZipFile ExtractToDirectory", `[System.IO.Compression.ZipFile]::ExtractToDirectory('a.zip', "$HOME")`, []string{home}, nil, []whole{{home, archive("a.zip")}}},
		{"ZipFile short type in statement", `Add-Type -A System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory("a.zip", "$HOME/.defenseclaw", $true)`, []string{state}, nil, []whole{{state, archive("a.zip")}}},
		{"ZipFileExtensions", `[System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($z, $HOME)`, []string{home}, nil, nil},
		{"ZipFile tilde is a folder", `[IO.Compression.ZipFile]::ExtractToDirectory('a.zip', '~')`, []string{filepath.Join(cwd, "~")}, nil, []whole{{filepath.Join(cwd, "~"), archive("a.zip")}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			read := ReadArchiveExtractions(row.command, cwd, home)
			if !slices.Equal(read.Paths, row.paths) {
				t.Errorf("paths %q, want %q", read.Paths, row.paths)
			}
			if !slices.Equal(read.Unknown, row.unknown) {
				t.Errorf("unknown %q, want %q", read.Unknown, row.unknown)
			}
			var got []whole
			for _, w := range read.Whole {
				got = append(got, whole{w.Folder, w.Archive})
			}
			if !slices.Equal(got, row.whole) {
				t.Errorf("whole %q, want %q", got, row.whole)
			}
			if read.Caps.Any() {
				t.Errorf("caps %v", read.Caps)
			}
		})
	}
}

// rel-1-0-10:GAP-1173: Landing reads the archive: a tar or zip of plain
// members lists where they land; an archive that is there and cannot be
// read, or a call that renames the members, is present and not listed; a
// missing archive is not present.
func TestGAP1173ArchiveWholeLanding(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	for _, name := range []string{"s.tar", "s.zip"} {
		gap1173Archive(t, filepath.Join(dir, name), ".defenseclaw/config.yaml", "notes.txt")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.zip"), []byte("not an archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(home, "notes.txt")}
	for _, row := range []struct {
		name, command   string
		present, listed bool
	}{
		{"tar", "tar -xf s.tar -C '" + home + "'", true, true},
		{"unzip", "unzip -o s.zip -d '" + home + "'", true, true},
		{"python shutil zip", `python3 -c 'import shutil; shutil.unpack_archive("s.zip", "` + filepath.ToSlash(home) + `")'`, true, true},
		{"python shutil tar", `python3 -c 'import shutil; shutil.unpack_archive("s.tar", "` + filepath.ToSlash(home) + `")'`, true, true},
		{"Expand-Archive", "Expand-Archive -Path s.zip -DestinationPath '" + home + "'", true, true},
		{"unreadable", "Expand-Archive -Path bad.zip -DestinationPath '" + home + "'", true, false},
		{"tar strip", "tar -xf s.tar --strip-components=1 -C '" + home + "'", true, false},
		{"unzip junk", "unzip -oj s.zip -d '" + home + "'", true, false},
		{"missing", "tar -xf gone.tar -C '" + home + "'", false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			read := ReadArchiveExtractions(row.command, dir, home)
			if len(read.Whole) != 1 {
				t.Fatalf("whole %v", read.Whole)
			}
			landing, present, listed := read.Whole[0].Landing()
			if present != row.present || listed != row.listed {
				t.Fatalf("present %t listed %t, want %t %t", present, listed, row.present, row.listed)
			}
			if listed && !slices.Equal(landing, want) {
				t.Fatalf("landing %q, want %q", landing, want)
			}
		})
	}
}
