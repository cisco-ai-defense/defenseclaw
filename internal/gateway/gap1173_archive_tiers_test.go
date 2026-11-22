// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gap1173WriteArchive writes a tar or zip archive holding members.
func gap1173WriteArchive(t *testing.T, path string, members ...string) {
	t.Helper()
	var buf bytes.Buffer
	if strings.HasSuffix(path, ".zip") {
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

// gap1173Want is the verdict of a row kind in a tier. A proven state write
// is a HIGH alert in the default, permissive and managed default packs and a
// block in strict and managed strict (rel-1-0-10:GAP-0747, owner tiering
// 2026-11-15T15:20Z); a possible write (the unknown tier) alerts in the
// default, permissive and managed default packs and blocks in strict; a keep
// row is allowed with no state finding. Every write and unknown row carries
// the state finding in every tier.
func gap1173Want(kind, tier string) string {
	switch kind {
	case "write", "unknown":
		if strings.Contains(tier, "strict") {
			return "block"
		}
		return "alert"
	}
	return "allow"
}

// gap1173WantFor is gap1173Want for a row whose findings are known: a write
// row that also names another tamper or persistence rule keeps the block of
// that rule in every tier (gap0747OtherTamperFinding).
func gap1173WantFor(kind, tier, action string, findings []string) string {
	if kind == "write" && action == "block" && gap0747OtherTamperFinding(findings) {
		return "block"
	}
	return gap1173Want(kind, tier)
}

// rel-1-0-10:GAP-1173 (P1, cert110 L74/L75; lead ruling 16:30Z, re-tiered to
// the GAP-0747 owner tiering 2026-11-15T15:20Z). An extraction whose folder
// is the DefenseClaw state is a proven state write (a HIGH alert outside
// strict, a block in strict and managed strict); one into a folder that holds
// the state (the home) is that write when the archive lists a member that
// lands in the state, takes the unknown tier when the archive is there and
// cannot be listed (or the call renames its members), and stays allowed
// when the archive lists none there or is not there to be read (the pinned
// allow rows of TestTMinArchiveReadsAndOtherFoldersStayAllowed).
// Git Bash and POSIX shells: tar, unzip and Python tarfile, zipfile and
// shutil.unpack_archive; on Windows also the PowerShell tool: Expand-Archive
// and [IO.Compression.ZipFile]::ExtractToDirectory, directly and through
// powershell -Command.
func TestGAP1173ArchiveExtractionTiers(t *testing.T) {
	home, cwd := gap1173WindowsStateHome(t)
	gap1173WriteArchive(t, filepath.Join(cwd, "state.tar"), ".defenseclaw/config.yaml", "notes.txt")
	gap1173WriteArchive(t, filepath.Join(cwd, "state.zip"), ".defenseclaw/config.yaml", "notes.txt")
	gap1173WriteArchive(t, filepath.Join(cwd, "plain.tar"), "notes.txt", "docs/a.md")
	gap1173WriteArchive(t, filepath.Join(cwd, "plain.zip"), "notes.txt", "docs/a.md")
	for _, name := range []string{"bad.tar", "bad.zip"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte("not an archive\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type row struct{ kind, tool, name, command string }
	rows := []row{
		{"write", "Bash", "tar whole state member into home", "tar -xf state.tar -C ~"},
		{"write", "Bash", "unzip whole state member into home", "unzip -o state.zip -d ~"},
		{"write", "Bash", "tar plain into state", "tar -xf plain.tar -C ~/.defenseclaw"},
		{"unknown", "Bash", "tar unreadable into home", "tar -xf bad.tar -C ~"},
		{"unknown", "Bash", "unzip unreadable into home", "unzip -o bad.zip -d ~"},
		{"unknown", "Bash", "tar strip-components into home", "tar -xf state.tar --strip-components=1 -C ~"},
		{"keep", "Bash", "tar plain into home", "tar -xf plain.tar -C ~"},
		{"keep", "Bash", "unzip plain into home", "unzip -o plain.zip -d ~"},
		{"keep", "Bash", "tar missing archive into home", "tar -xf gone.tar -C ~"},
		{"keep", "Bash", "tar state archive into project", "tar -xf state.tar -C out"},
		{"write", "Bash", "python tarfile state member into home", `python3 -c 'import tarfile, os; tarfile.open("state.tar").extractall(os.path.expanduser("~"))'`},
		{"write", "Bash", "python zipfile state member into home", `python3 -c 'import zipfile, os; zipfile.ZipFile("state.zip").extractall(os.path.expanduser("~"))'`},
		{"write", "Bash", "python shutil state member into home", `python3 -c 'import shutil, os; shutil.unpack_archive("state.zip", os.path.expanduser("~"))'`},
		{"write", "Bash", "python tarfile plain into state", `python3 -c 'import tarfile, os; tarfile.open("plain.tar").extractall(os.path.expanduser("~/.defenseclaw"))'`},
		{"write", "Bash", "python extract state member", `python3 -c 'import tarfile, os; tarfile.open("plain.tar").extract(".defenseclaw/config.yaml", os.path.expanduser("~"))'`},
		{"write", "Bash", "python hand-off of the state folder", `python3 -c 'import tarfile, sys; tarfile.open(sys.argv[1]).extractall(sys.argv[2])' plain.tar ~/.defenseclaw`},
		{"unknown", "Bash", "python unreadable into home", `python3 -c 'import zipfile, os; zipfile.ZipFile("bad.zip").extractall(os.path.expanduser("~"))'`},
		{"keep", "Bash", "python plain into home", `python3 -c 'import tarfile, os; tarfile.open("plain.tar").extractall(os.path.expanduser("~"))'`},
		{"keep", "Bash", "python state archive into project", `python3 -c 'import tarfile; tarfile.open("state.tar").extractall("out")'`},
	}
	if runtime.GOOS == "windows" {
		rows = append(rows,
			row{"write", "PowerShell", "Expand-Archive state member into home", "Expand-Archive -Path state.zip -DestinationPath $HOME"},
			row{"write", "PowerShell", "Expand-Archive positional into home", `Expand-Archive state.zip ~ -Force`},
			row{"write", "PowerShell", "Expand-Archive plain into state", `Expand-Archive -LiteralPath plain.zip -DestinationPath "$env:USERPROFILE\.defenseclaw" -Force`},
			row{"write", "PowerShell", "ZipFile state member into home", `[System.IO.Compression.ZipFile]::ExtractToDirectory('state.zip', "$HOME")`},
			row{"write", "PowerShell", "ZipFile plain into state", `[IO.Compression.ZipFile]::ExtractToDirectory('plain.zip', "$env:USERPROFILE\.defenseclaw")`},
			row{"write", "Bash", "powershell -Command Expand-Archive into state", `powershell -NoProfile -Command "Expand-Archive -Path plain.zip -DestinationPath ~\.defenseclaw -Force"`},
			row{"unknown", "PowerShell", "Expand-Archive unreadable into home", "Expand-Archive -Path bad.zip -DestinationPath $HOME"},
			row{"unknown", "PowerShell", "ZipFile unreadable into home", `[IO.Compression.ZipFile]::ExtractToDirectory('bad.zip', $HOME)`},
			row{"keep", "PowerShell", "Expand-Archive plain into home", "Expand-Archive -Path plain.zip -DestinationPath $HOME"},
			row{"keep", "PowerShell", "Expand-Archive state archive into project", "Expand-Archive -Path state.zip -DestinationPath out"},
			row{"keep", "PowerShell", "Expand-Archive WhatIf", "Expand-Archive -Path state.zip -DestinationPath $HOME -WhatIf"},
		)
	}
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			for _, r := range rows {
				action, findings := boundedDecideClaudeCode(t, api, boundedEnv{home: home, cwd: cwd},
					boundedLaneCall{tool: r.tool, input: map[string]any{"command": r.command}})
				want := gap1173WantFor(r.kind, tier.name, action, findings)
				state := findingStringHasRuleID(findings, "tamper.detector_state_write")
				if action != want || (r.kind == "keep") == state {
					t.Errorf("%s %s [%s]: action %q state finding %t, want %q: %v", tier.name, r.kind, r.name, action, state, want, findings)
				}
			}
		})
	}
}
