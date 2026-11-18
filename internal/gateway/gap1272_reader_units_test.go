// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"
)

// GAP-1272: the wildcard matcher, the folder split and the twins of the
// cmdlet reader.
func TestGAP1272WildcardReaderUnits(t *testing.T) {
	for _, row := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", "settings.json", true}, {"set*", "Settings.json", true}, {"*.toml", "config.toml", true},
		{"?onfig.yaml", "config.yaml", true}, {"[a-d]onfig.*", "config.yaml", true}, {"[xyz]onfig.*", "config.yaml", false},
		{"*.log", "settings.json", false}, {"s*s*s*s*s*s*s*x", "ssssssssssssssssssssssssssssss", false},
		{"`*", "*", true}, {"`*", "a", false}, {"[s", "settings", false}, {"[*", "settings", true}, {"a?", "a", false},
	} {
		if got := psWildcardMatch(row.pattern, row.name); got != row.want {
			t.Errorf("psWildcardMatch(%q, %q) = %t, want %t", row.pattern, row.name, got, row.want)
		}
	}
	const home, cwd = "/h/u", "/h/u/proj"
	protected := newPSProtectedPaths([]string{"/h/u/.claude/settings.json", "/h/u/.codex/config.toml"},
		[]string{".claude/settings.json", ".defenseclaw/config.yaml", ".defenseclaw/policies"})
	remove := func(path string) string { return "Remove-Item -LiteralPath '" + path + "' -Recurse -Force" }
	write := func(path string) string { return "Set-Content -LiteralPath '" + path + "' -Value x" }
	// Each match is read as written in place and as removed.
	both := func(paths ...string) (out []string) {
		for _, path := range paths {
			out = append(out, write(path), remove(path))
		}
		return out
	}
	for _, row := range []struct {
		statement string
		want      []string
	}{
		{"Remove-Item -Path ~/.claude/*", both("/h/u/.claude/settings.json")},
		{"Set-Content -Path $HOME/.codex/c* -Value x", both("/h/u/.codex/config.toml")},
		{"Remove-Item ~/* -Recurse", both("/h/u/.claude", "/h/u/.claude/settings.json", "/h/u/.codex", "/h/u/.codex/config.toml")},
		{"Remove-Item ~/.c*/settings.json", both("/h/u/.claude/settings.json")},
		{"Set-Content ~/.claude/x.txt 'set*'", nil},
		{"Set-Content -LiteralPath ~/.claude/s* -Value x", nil},
		{"Set-Content -LiteralPath ~/.claude/x.txt 's*'", nil},
		{"Copy-Item ~/.claude/* ./backup", nil},
		{"Copy-Item notes.txt -Destination ~/.claude/s*", both("/h/u/.claude/settings.json")},
		{"Get-ChildItem ~/.claude/*", nil},
		{"Remove-Item ~/.claude/*.log", nil},
		{"Remove-Item ~/.codex/sessions/* -Recurse", nil},
		{"Remove-Item ~/.claude -Include s* -Recurse", both("/h/u/.claude/settings.json")},
		{"Remove-Item ../.defenseclaw/* -Filter conf*", both("/h/u/.defenseclaw/config.yaml")},
		{"Set-Content -Path ~/.defenseclaw/policies/*.rego -Value x", both("/h/u/.defenseclaw/policies/*.rego")},
		{"Rename-Item -Path ~/.claude/s* -NewName ~/.claude/x*", both("/h/u/.claude/settings.json")},
		{"Remove-Item -Path $env:CFG/.claude/*", []string{"Remove-Item -Path $env:CFG/.claude -Recurse -Force"}},
	} {
		got := psWildcardWriteTwins(row.statement, psReading{merge: psMerger{home: home, cwd: cwd}, protected: protected}, &psBudget{})
		if !slices.Equal(got, row.want) {
			t.Errorf("psWildcardWriteTwins(%s) = %q, want %q", row.statement, got, row.want)
		}
	}
	// A drive home: the twin is a drive path.
	drive := newPSProtectedPaths([]string{`C:\Users\a\.claude\settings.json`}, nil)
	reading := psReading{merge: psMerger{home: `C:\Users\a`, cwd: `C:\Users\a\proj`}, protected: drive}
	if got := psWildcardWriteTwins(`Remove-Item -Path "$env:USERPROFILE\.claude\*"`, reading, &psBudget{}); !slices.Equal(got, []string{write(`C:\Users\a\.claude\settings.json`), remove(`C:\Users\a\.claude\settings.json`)}) {
		t.Errorf("drive home twins = %q", got)
	}
}
