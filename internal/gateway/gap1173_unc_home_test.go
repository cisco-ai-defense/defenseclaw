// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10:GAP-1173: a UNC home (\\server\share\user, a redirected or
// roaming profile) is judged as a drive home: an extraction into its state
// is a write, one into the home whose members nothing tells is a possible
// write, and the share is never asked (the judge reads only the hook's
// target map here).
func TestGAP1173UNCHomeArchiveState(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a UNC home is a Windows form")
	}
	const share = `\\dc-test-srv\home$`
	var asked atomic.Int32
	restore := overrideNetworkSharesIdle(t, func(name string) string {
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(share)) {
			return share
		}
		return ""
	}, func(string) { asked.Add(1) })
	t.Cleanup(restore)
	home := share + `\person`
	facts := actionfacts.Facts{ActiveHome: home, CWD: home + `\proj`}
	judge, ok := newStateJudge(facts, trustedActionRequest{SkipLocalFilesystemResolution: true})
	if !ok {
		t.Fatal("a UNC home was not judged")
	}
	for path, want := range map[string]bool{
		home + `\.defenseclaw`:                    true,
		home + `\.defenseclaw\config.yaml`:        true,
		`\\DC-TEST-SRV\HOME$\Person\.DefenseClaw`: true,
		home + `\proj\.defenseclaw\config.yaml`:   false,
		home + `\.defenseclaw-old\config.yaml`:    false,
		`\\other-srv\home$\person\.defenseclaw`:   false,
		`C:\Users\person\.defenseclaw`:            false,
	} {
		if got := judge.reaches(path); got != want {
			t.Errorf("reaches(%s) = %t, want %t", path, got, want)
		}
	}
	for folder, want := range map[string]bool{
		home:                   true,
		share:                  true,
		home + `\.defenseclaw`: true,
		home + `\proj`:         false,
		`\\other-srv\home$`:    false,
	} {
		if got := judge.holds(folder); got != want {
			t.Errorf("holds(%s) = %t, want %t", folder, got, want)
		}
	}
	for _, row := range []struct {
		tool, command    string
		writes, possible bool
	}{
		{"Bash", "tar -xf a.tar -C ~/.defenseclaw", true, false},
		{"Bash", "unzip -o a.zip -d ~ .defenseclaw/config.yaml", true, false},
		{"Bash", "tar -xf a.tar -C ~ -T list", false, true},
		{"Bash", `python3 -c 'import tarfile, os; tarfile.open("a.tar").extractall(os.path.expanduser("~/.defenseclaw"))'`, true, false},
		{"PowerShell", `Expand-Archive -Path a.zip -DestinationPath "$HOME\.defenseclaw"`, true, false},
		{"PowerShell", `[IO.Compression.ZipFile]::ExtractToDirectory('a.zip', "$env:USERPROFILE\.defenseclaw")`, true, false},
		{"Bash", "tar -xf a.tar -C out", false, false},
	} {
		request := trustedActionRequest{SkipLocalFilesystemResolution: true,
			Input: actionfacts.Input{Tool: row.tool, Command: row.command, CWD: facts.CWD, ActiveHome: home}}
		reading := readArchiveState(facts, request)
		if reading.writes != row.writes || reading.possible != row.possible {
			t.Errorf("%s: writes %t possible %t, want %t %t", row.command, reading.writes, reading.possible, row.writes, row.possible)
		}
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the share was asked %d times", n)
	}
}
