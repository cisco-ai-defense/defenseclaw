// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104Refix4VisibleWriteDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "read.awk"), []byte("{print}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "writer.awk"), []byte("BEGIN {print \"marker\" >> \"alias\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-0493 Git root link", `git -C sub pull && echo marker >> future`, false},
		{"GAP-0493 outside Git root", `git -C sub pull && echo marker >> ../notes.txt`, false},
		{"GAP-0498 dynamic input protected literal", `awk 'BEGIN {print "marker" >> "alias"}' "$input"`, true},
		{"GAP-0498 dynamic input ordinary literal", `awk 'BEGIN {print "marker" >> "report.txt"}' "$input"`, false},
		{"review AWK -v program-looking data", `awk -v 'm={print > "alias"}' '{print m}' input.txt`, true},
		{"review AWK regex-looking data", `awk '/print > "alias"/ {print}' input.txt`, true},
		{"GAP-0509 shell expanded output", `out=alias; awk "BEGIN {print \"marker\" >> \"$out\"}"`, true},
		{"GAP-0509 dynamic data can add an output", `awk "BEGIN {print $1 >> \"report.txt\"}" input.txt`, false},
		{"GAP-0509 fixed ordinary output", `awk 'BEGIN {print "marker" >> "report.txt"}' input.txt`, false},
		{"GAP-0509 no visible file output", `awk "BEGIN {print $field}" input.txt`, false},
		{"BEN-0482 read-only dynamic AWK", `awk "{print $1}" ~/.ssh/known_hosts > out/known-hostnames.txt`, false},
		{"GAP-0508 visible companion output", `gawk -f read.awk -e 'BEGIN {print "marker" >> "alias"}' -- "$input"`, true},
		{"GAP-0508 static AWK program file", `awk -f writer.awk input.txt`, true},
		{"GAP-0508 attached AWK program file", `awk -fwriter.awk input.txt`, true},
		{"GAP-0508 ordinary AWK program file", `awk -f read.awk input.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.block {
					t.Fatalf("decision %d = %v, want %v", i, got, tc.block)
				}
			}
		})
	}
}

func TestR104Refix4PowerShellNewlineWrite(t *testing.T) {
	input := actionfacts.Input{Tool: "PowerShell", CWD: `C:\Users\fixture\project`,
		ActiveHome: `C:\Users\fixture`, DialectHint: actionfacts.DialectPowerShell}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-0510 LF", "Write-Output 'ok'\nAdd-Content -Path '~/.ssh/authorized_keys' -Value 'marker'", true},
		{"GAP-0510 CRLF", "Write-Output 'ok'\r\nSet-Content -LiteralPath '~/.ssh/authorized_keys' -Value 'marker'", true},
		{"GAP-0510 after empty lines", "Write-Output 'ok'\n\nOut-File -FilePath '~/.ssh/authorized_keys' -InputObject 'marker'", true},
		{"ordinary newline write", "Write-Output 'ok'\nAdd-Content -Path 'notes.txt' -Value 'marker'", false},
		{"protected path is only data", "Write-Output '~/.ssh/authorized_keys'\nAdd-Content -Path 'notes.txt' -Value 'marker'", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input.Command = tc.command
			if got := trustedWindowsLocationAuthorizedKeysWrite(input); got != tc.block {
				t.Fatalf("protected write = %v, want %v", got, tc.block)
			}
		})
	}
}
