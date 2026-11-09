// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const emptySourceLoop = `IFS=; for f in keylink; do cp "$IFS" "$f"; done`

// A reading is a copy that opens no source only when the source operand is
// the empty string and every word before it is an option that takes no value
// (rel-1-0-6:GAP-0880, GAP-0885).
func TestCopyOpensNoSourceNeedsAnEmptySourceAndValuelessOptions(t *testing.T) {
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	cwd := t.TempDir()
	for _, row := range []struct {
		reading string
		want    bool
	}{
		{`cp '' keylink`, true},
		{`cp "" keylink`, true},
		{`gcp '' keylink`, true},
		{`cp -f '' keylink`, true},
		{`cp -- '' keylink`, true},
		{`cp -aR '' keylink`, true},
		{`cp a.txt keylink`, false},
		{`cp '-' keylink`, false},
		{`cp -t keylink ''`, false},
		{`cp -S '' x keylink`, false},
		{`cp --target-directory=d '' keylink`, false},
		{`mv '' keylink`, false},
		{`cp '' keylink; echo`, false},
		{`cp '' keylink > out`, false},
		{`cp '' keylink &`, false},
		{`cp '' b keylink`, false},
		{`X=1 cp '' keylink`, false},
	} {
		if got := copyOpensNoSource(row.reading, emptySourceLoop, cwd, "/h"); got != row.want {
			t.Errorf("copyOpensNoSource(%q) = %v, want %v", row.reading, got, row.want)
		}
	}
}

// The reading is judged only in a command whose copy is proved to open no
// source and to be the system copy: a source the command can change, a cp
// that PATH or a function can replace, or any statement after the loop
// leaves the reading described (rel-1-0-6:GAP-0880, GAP-0885).
func TestCopyOpensNoSourceNeedsTheProvedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the rows spell POSIX paths")
	}
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	t.Setenv("DC_TEST_EXPORTED_NAME", "1")
	cwd := t.TempDir()
	system := "/usr/bin" + string(os.PathListSeparator) + "/bin"
	if _, err := os.Stat("/bin/cp"); err != nil {
		t.Skip("the rows need the system cp")
	}
	if err := os.WriteFile(filepath.Join(cwd, "cp"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", system)
	const reading = `cp '' keylink`
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"loop", emptySourceLoop, true},
		{"loop-assigned-source", `src=; for f in keylink; do cp "$src" "$f"; done`, true},
		{"loop-option", `IFS=; for f in keylink; do cp -f "$IFS" "$f"; done`, true},
		{"loop-target-option", `IFS=; for f in keylink; do cp -t "$f" "$IFS"; done`, false},
		{"loop-absolute-system-cp", `IFS=; for f in keylink; do /bin/cp "$IFS" "$f"; done`, true},
		{"loop-noop-first", `cd .; ` + emptySourceLoop, true},
		{"path-dot-before", `PATH=.; ` + emptySourceLoop, false},
		{"path-dot-after-ifs", `IFS=; PATH=.; for f in keylink; do cp "$IFS" "$f"; done`, false},
		{"path-dot-and-system", `PATH=.:/usr/bin; ` + emptySourceLoop, false},
		{"loader-variable", `LD_PRELOAD=x; ` + emptySourceLoop, false},
		{"exported-name", `DC_TEST_EXPORTED_NAME=; ` + emptySourceLoop, false},
		{"relative-program", `IFS=; for f in keylink; do ./cp "$IFS" "$f"; done`, false},
		{"read-in-loop", `IFS=; src=; for f in keylink; do read src <<< a.txt; cp "$src" "$f"; done`, false},
		{"assignment-in-loop", `IFS=; src=; for f in keylink; do src=a.txt; cp "$src" "$f"; done`, false},
		{"read-after-loop", emptySourceLoop + `; read IFS <<< a.txt; cp "$IFS" keylink`, false},
		{"copy-after-loop", emptySourceLoop + `; cp a.txt keylink`, false},
		{"function-first", `cp() { :; }; ` + emptySourceLoop, false},
		{"group", `{ ` + emptySourceLoop + `; }`, false},
		{"copy-outside-loop", `IFS=; cp "$IFS" keylink`, false},
		{"nonempty-ifs", `IFS=x; for f in keylink; do cp "$IFS" "$f"; done`, false},
	} {
		if got := copyOpensNoSource(reading, row.command, cwd, "/h"); got != row.want {
			t.Errorf("%s: copyOpensNoSource(%q) = %v, want %v", row.name, row.command, got, row.want)
		}
	}
	// A cp in a project directory that PATH lists, or a relative PATH entry
	// that reaches it, replaces the system copy.
	for _, path := range []string{cwd + ":" + system, ".:" + system, ":" + system} {
		t.Setenv("PATH", path)
		if copyOpensNoSource(reading, emptySourceLoop, cwd, "/h") {
			t.Errorf("PATH=%q puts a project cp first: the reading must stay described", path)
		}
	}
	t.Setenv("PATH", system+":"+cwd)
	if !copyOpensNoSource(reading, emptySourceLoop, cwd, "/h") {
		t.Error("the system cp comes first on PATH: the reading is a copy that opens no source")
	}
	t.Setenv("PATH", system)
	t.Setenv("BASH_ENV", "/h/startup.sh")
	if copyOpensNoSource(reading, emptySourceLoop, cwd, "/h") {
		t.Error("a startup file can redefine cp: the copy is not proved to open no source")
	}
}

// The copy that runs is identified by the file it reaches, not by the name or
// by where PATH finds it: a program named cp outside the project (ambient
// PATH or an absolute word) is not the system copy, and a project link to the
// system copy is (rel-1-0-6:GAP-0880).
func TestCopyOpensNoSourceFollowsTheProgramToTheFileItReaches(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the rows spell POSIX paths")
	}
	if _, err := os.Stat("/bin/cp"); err != nil {
		t.Skip("the rows need the system cp")
	}
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	cwd := t.TempDir()
	outside := t.TempDir()
	system := "/usr/bin" + string(os.PathListSeparator) + "/bin"
	fake := filepath.Join(outside, "cp")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/cp", filepath.Join(cwd, "cp")); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.Symlink(fake, filepath.Join(linked, "cp")); err != nil {
		t.Fatal(err)
	}
	const reading = `cp '' keylink`
	for _, row := range []struct {
		name, path, command string
		want                bool
	}{
		{"project-link-to-system-cp-first", cwd + ":" + system, emptySourceLoop, true},
		{"project-link-by-path-word", system, `IFS=; for f in keylink; do ./cp "$IFS" "$f"; done`, true},
		{"outside-program-first-on-path", outside + ":" + system, emptySourceLoop, false},
		{"outside-program-by-absolute-word", system, `IFS=; for f in keylink; do ` + fake + ` "$IFS" "$f"; done`, false},
		{"link-to-outside-program", linked + ":" + system, emptySourceLoop, false},
		{"no-cp-on-path", outside + "/none", emptySourceLoop, false},
	} {
		t.Setenv("PATH", row.path)
		if got := copyOpensNoSource(reading, row.command, cwd, "/h"); got != row.want {
			t.Errorf("%s: copyOpensNoSource(%q) with PATH=%q = %v, want %v", row.name, row.command, row.path, got, row.want)
		}
	}
}

// A described empty-source copy carries the name of its program: the gateway
// reads an explicit path outside the system directories as an unknown program
// (rel-1-0-6:GAP-0880).
func TestDescribedCopyReadingNamesTheProgram(t *testing.T) {
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	cwd := t.TempDir()
	const unproved = `IFS=x; for f in keylink; do /tmp/tool/cp "$IFS" "$f"; done`
	for _, row := range []struct {
		name, reading, command, want string
		described                    bool
	}{
		{"explicit-path", "/tmp/tool/cp '' keylink", unproved, "cp '' keylink", true},
		{"explicit-gcp", "/opt/t/gcp '' keylink", unproved, "gcp '' keylink", true},
		{"bare-name", "cp '' keylink", unproved, "cp '' keylink", true},
		{"named-source", "/tmp/tool/cp a.txt keylink", unproved, "/tmp/tool/cp a.txt keylink", true},
		{"proved", "cp '' keylink", emptySourceLoop, "", false},
	} {
		if row.name == "proved" && runtime.GOOS == "windows" {
			continue
		}
		t.Setenv("PATH", "/usr/bin"+string(os.PathListSeparator)+"/bin")
		if _, err := os.Stat("/bin/cp"); err != nil && row.name == "proved" {
			continue
		}
		got, described := describedCopyReading(row.reading, row.command, cwd, "/h")
		if got != row.want || described != row.described {
			t.Errorf("%s: describedCopyReading(%q) = %q, %v; want %q, %v", row.name, row.reading, got, described, row.want, row.described)
		}
	}
}
