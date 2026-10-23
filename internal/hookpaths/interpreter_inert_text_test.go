// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func r104Loop2Home(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, cwd
}

func r104Loop2Check(t *testing.T, command, cwd, home, reason string) {
	t.Helper()
	if got := UnprovenProtectedWrite(command, cwd, home); got != reason {
		t.Fatalf("class = %q, want %q", got, reason)
	}
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[UnprovenReasonKey] != reason {
		t.Fatalf("hook evidence class = %q, want %q", targets[UnprovenReasonKey], reason)
	}
}

// Loop 2: only awk program text is code. A -v or -F value, an operand, a
// var=value assignment, a regular expression literal, a string and a comment
// are data, so a "print > file" inside one is not an output. The same lexer
// must not hide a real computed output after such data.
func TestR104Loop2AWKProgramTextOnly(t *testing.T) {
	home, cwd := r104Loop2Home(t)
	for _, tc := range []struct {
		name, command, reason string
	}{
		{"-v value is data", `awk -v message='print > report.txt' '{print message}' input.txt`, ""},
		{"attached -v value is data", `awk -vmessage='print > report.txt' '{print message}' input.txt`, ""},
		{"long assign value is data", `gawk --assign=message='print > out' '{print message}' input.txt`, ""},
		{"-v value is data with dynamic input", `awk -v message='print > out' '{print message}' "$input"`, ""},
		{"field separator is data", `awk -F'print > x' '{print $1}' input.txt`, ""},
		{"operand assignment is data", `awk '{print}' 'msg=print > out' input.txt`, ""},
		{"operand file name is data", `awk '{print}' 'print > out'`, ""},
		{"regex pattern is data", `awk '/print > out/ {print}' input.txt`, ""},
		{"matched regex is data", `awk '$0 ~ /print > out/' input.txt`, ""},
		{"negated regex is data", `awk '!/print > b/' input.txt`, ""},
		{"regex argument is data", `awk '{n = split($0, a, /print > y/); print n}' input.txt`, ""},
		{"regex after block is data", `awk '{print} /print > out/ {print}' input.txt`, ""},
		{"slash in bracket stays in regex", `awk '/[/]print > out/ {print}' input.txt`, ""},
		{"class in bracket stays in regex", `awk '/[[:alpha:]/]print > out/ {print}' input.txt`, ""},
		{"comment is data", `awk '{print} # print > out' input.txt`, ""},
		{"string is data", `awk '{ print "a > b" }' input.txt`, ""},
		{"source program regex is data", `gawk -e '/print > out/ {print}' -- "$input"`, ""},
		{"literal output after comment", `awk '{print > "report.txt"} # print > out' "$input"`, ""},
		{"division is not a regex", `awk '{ x = a / 2; print x }' input.txt`, ""},
		// Real program text still fails closed on a computed output.
		{"computed output", `awk '{print > out}' input.txt`, "dynamic-argument"},
		{"computed output after regex", `awk '/x/ {print > out}' input.txt`, "dynamic-argument"},
		{"computed output after block regex", `awk '{print} /y/ {print > out}' input.txt`, "dynamic-argument"},
		{"quote in regex does not open a string", `awk '/["]/ {print > out}' input.txt`, "dynamic-argument"},
		{"apostrophe in regex does not open a string", `awk "/'/ {print > out}" input.txt`, "dynamic-argument"},
		{"class closer does not end bracket early", `awk '/[[:alpha:]/]=/ {print > out} /x/' input.txt`, "dynamic-argument"},
		{"continued line division is not a regex", "awk '{ x = 4 \\\n/ 2; print > out; y = 1 / 2 }' input.txt", "dynamic-argument"},
		{"print continues after comma newline", "awk '{print $1,\n $2 > out}' input.txt", "dynamic-argument"},
		{"code after comment line", "awk '# note\n{print > out}' input.txt", "dynamic-argument"},
		{"computed output with -v data", `awk -v m='print > report.txt' '{print > out}' input.txt`, "dynamic-argument"},
		{"computed source program", `gawk -e '{print > out}' input.txt`, "dynamic-argument"},
		{"unknown option shifts the program", `gawk -l lib '{print > out}' input.txt`, "dynamic-argument"},
		{"unknown option shifts the program to a value", `gawk -l lib -v '{print > out}' input.txt`, "dynamic-argument"},
		{"unterminated regex", `awk '/abc {print}' input.txt`, "dynamic-argument"},
		{"pipe after regex data with dynamic input", `awk '/print > x/ {print | "sh"}' "$input"`, "dynamic-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r104Loop2Check(t, tc.command, cwd, home, tc.reason)
		})
	}
}

// Loop 2: an f-string (or any prefixed string) with no replacement field is
// inert data once the destination is a proved ordinary file. An f- or
// t-string with a field evaluates code and stays under write analysis, and a
// protected destination is never proved by its data.
func TestR104Loop2PythonInertPrefixedData(t *testing.T) {
	home, cwd := r104Loop2Home(t)
	for _, tc := range []struct {
		name, command, reason string
	}{
		{"f-string data", `python3 -c 'open("report.txt","w").write(f"~/.ssh/authorized_keys")'`, ""},
		{"uppercase f-string data", `python3 -c 'open("report.txt","w").write(F"~/.ssh/authorized_keys")'`, ""},
		{"raw f-string data", `python3 -c 'open("report.txt","w").write(rf"~/.ssh/authorized_keys")'`, ""},
		{"f raw string data", `python3 -c 'open("report.txt","w").write(fR"~/.ssh/authorized_keys")'`, ""},
		{"f-string doubled braces", `python3 -c 'open("report.txt","w").write(f"{{~/.ssh/authorized_keys}}")'`, ""},
		{"single-quoted f-string data", `python3 -c "open('report.txt','w').write(f'~/.ssh/authorized_keys')"`, ""},
		{"raw string data", `python3 -c 'open("report.txt","w").write(r"~/.ssh/authorized_keys")'`, ""},
		{"raw bytes data", `python3 -c 'open("report.txt","wb").write(rb"~/.ssh/authorized_keys")'`, ""},
		{"unicode string data", `python3 -c 'open("report.txt","w").write(u"~/.ssh/authorized_keys")'`, ""},
		{"Path f-string data", `python3 -c 'from pathlib import Path; Path("report.txt").write_text(f"~/.ssh/authorized_keys")'`, ""},
		{"f-string data with dynamic argument", `python3 -c 'open("report.txt","w").write(f"~/.ssh/authorized_keys")' "$USER"`, ""},
		{"print f-string data", `python3 -c 'print(f"~/.ssh/authorized_keys")'`, ""},
		// A replacement field is code, and a protected destination stays blocked.
		{"f-string field", `python3 -c 'open("report.txt","w").write(f"~/.ssh/{k}")'`, "interpreter-path"},
		{"backslash does not escape a field", `python3 -c 'open("report.txt","w").write(f"\{k}~/.ssh/authorized_keys")'`, "interpreter-path"},
		{"raw f-string field", `python3 -c 'open("report.txt","w").write(rf"\N{k}~/.ssh/authorized_keys")'`, "interpreter-path"},
		{"lone closing brace", `python3 -c 'open("report.txt","w").write(f"~/.ssh/authorized_keys}")'`, "interpreter-path"},
		{"t-string field", `python3 -c 'open("report.txt","w").write(t"{k}~/.ssh/authorized_keys")'`, "interpreter-path"},
		{"f-string field opens protected file", `python3 -c 'open("report.txt","w").write(f"{open(\"alias\",\"a\")}")'`, "interpreter-path"},
		{"implicit concatenation", `python3 -c 'open("report.txt","w").write(f"a" "~/.ssh/authorized_keys")'`, "interpreter-path"},
		{"protected destination with f-string data", `python3 -c 'open("alias","w").write(f"x")'`, "interpreter-path"},
		{"print f-string field", `python3 -c 'print(f"{open(\"alias\",\"w\")}")'`, "interpreter-path"},
		{"unknown prefix", `python3 -c 'open("report.txt","w").write(x"~/.ssh/authorized_keys")'`, "interpreter-path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r104Loop2Check(t, tc.command, cwd, home, tc.reason)
		})
	}
}
