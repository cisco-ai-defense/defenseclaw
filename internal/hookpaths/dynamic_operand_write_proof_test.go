// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Loop 1 review fixes: a dynamic AWK input operand and a dynamic argument
// after a proved ordinary interpreter program are not protected writes, while
// the same dynamic values still fail closed when the program has an
// unproved file or command effect.
func TestR104Loop1DynamicOperandWriteProof(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
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
	if err := os.Symlink(protected, filepath.Join(cwd, "linked-out.txt")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for name, program := range map[string]string{"read.awk": "{print}\n", "write.awk": "{print > out}\n"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(program), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command, reason string
	}{
		// AWK input operands are read; only an unproved output or command
		// effect lets a dynamic operand (or var=value assignment) matter.
		{"awk dynamic input", `awk '{print}' "$input"`, ""},
		{"awk unquoted dynamic input", `awk '{print}' $input`, ""},
		{"awk braced dynamic input", `awk '{print}' "${input}"`, ""},
		{"awk field separator and dynamic inputs", `awk -F, '{print $1}' "$input" "$other"`, ""},
		{"awk attached separator", `awk -F: -v n=1 '{print n}' "$input"`, ""},
		{"awk end of options", `awk -- '{print}' "$input"`, ""},
		{"awk dynamic -v assignment", `awk -v "$assign" '{print}' input.txt`, ""},
		{"awk attached dynamic -v value", `awk -vn="$N" '{print n}' "$input"`, ""},
		{"awk attached dynamic long assign", `gawk --assign=n="$N" '{print n}' "$input"`, ""},
		{"awk attached dynamic separator", `awk -F"$sep" '{print $1}' "$input"`, ""},
		{"awk attached dynamic program file", `awk -f"$program" input.txt`, "dynamic-argument"},
		{"awk attached dynamic -v with computed output", `awk -vout="$o" '{print > out}' input.txt`, "dynamic-argument"},
		{"awk attached dynamic -v with pipe", `awk -vn="$N" '{print | "sh"}' input.txt`, "dynamic-argument"},
		{"awk dynamic field separator", `awk -F "$sep" '{print $1}' "$input"`, ""},
		{"gawk harmless flag", `gawk --posix '{print}' "$input"`, ""},
		{"awk literal ordinary output", `awk '{print > "report.txt"}' "$input"`, ""},
		{"awk regex alternation is not a pipe", `awk '/a|b/ {print}' "$input"`, ""},
		{"awk logical or is not a pipe", `awk '$1 == "a" || $1 == "b"' "$input"`, ""},
		{"awk shell output redirect", `awk '{print}' "$input" > report.txt`, ""},
		{"awk computed output with dynamic input", `awk '{print > out}' "$input"`, "dynamic-argument"},
		{"awk computed output with dynamic assignment", `awk '{print > out}' "$assign" input.txt`, "dynamic-argument"},
		{"awk pipe with dynamic input", `awk '{print | "sh"}' "$input"`, "dynamic-argument"},
		{"awk system with dynamic input", `awk '{system("cp " $0 " x")}' "$input"`, "dynamic-argument"},
		{"awk getline command with dynamic input", `awk '{"date" | getline d}' "$input"`, "dynamic-argument"},
		{"awk dynamic program", `awk "$program" input.txt`, "dynamic-argument"},
		{"awk dynamic program file", `awk -f "$program" input.txt`, "dynamic-argument"},
		{"awk missing program file with dynamic input", `awk -f missing.awk -- "$input"`, "dynamic-argument"},
		{"awk read-only program file with dynamic input", `awk -f read.awk -- "$input"`, ""},
		{"awk attached read-only program file with dynamic input", `awk -fread.awk -- "$input"`, ""},
		{"awk program file then static and dynamic inputs", `awk -f read.awk input.txt "$input"`, ""},
		{"awk program file with dynamic option-position word", `awk -f read.awk "$input"`, "dynamic-argument"},
		{"awk writing program file with dynamic input", `awk -f write.awk -- "$input"`, "dynamic-argument"},
		{"awk dynamic -v before effect", `awk -v "$assign" '{print > out}' input.txt`, "dynamic-argument"},
		{"awk unknown option with dynamic input", `gawk -o "$input" '{print}' input.txt`, "dynamic-argument"},
		{"awk include with dynamic input", `gawk -i lib '{print}' "$input"`, "dynamic-argument"},
		{"awk gawk source program with dynamic input", `gawk -e '{print | "sh"}' -- "$input"`, "dynamic-argument"},
		{"awk gawk source program read only", `gawk -e '{print}' -- "$input"`, ""},
		{"awk gawk source program with dynamic option-position word", `gawk -e '{print}' "$input"`, "dynamic-argument"},
		// A dynamic argument after a proved ordinary interpreter program
		// cannot redirect its fixed destination.
		{"python ordinary open with dynamic argument", `python3 -c 'open("out.txt","w").write("alias")' "$USER"`, ""},
		{"python ordinary Path with dynamic argument", `python3 -c 'from pathlib import Path; Path("out.txt").write_text("alias")' "$USER"`, ""},
		{"node ordinary write with dynamic argument", `node -e 'require("fs").writeFileSync("out.txt","alias")' "$USER"`, ""},
		{"wrapped python ordinary open with dynamic argument", `nice python3 -c 'open("out.txt","w").write("alias")' "$USER"`, ""},
		{"env python ordinary open with dynamic argument", `env python3 -c 'open("out.txt","a").write("x")' "$USER" "$HOME"`, ""},
		{"python protected open with dynamic argument", `python3 -c 'open("alias","a").write("marker")' "$USER"`, "interpreter-argument"},
		{"python linked ordinary-looking open with dynamic argument", `python3 -c 'open("linked-out.txt","w").write("x")' "$USER"`, "interpreter-argument"},
		{"python argv destination", `python3 -c 'import sys; open(sys.argv[1],"w").write("x")' "$USER"`, "interpreter-path"},
		{"python chdir from argv", `python3 -c 'import os,sys; os.chdir(sys.argv[1]); open("out.txt","w").write("alias")' "$USER"`, "interpreter-argument"},
		{"wrapped python protected open with dynamic argument", `nice python3 -c 'open("alias","a").write("marker")' "$USER"`, "dynamic-argument"},
		{"wrapped python argv destination", `env python3 -c 'import sys; open(sys.argv[1],"w").write("x")' "$USER"`, "dynamic-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := UnprovenProtectedWrite(tc.command, cwd, home); got != tc.reason {
				t.Fatalf("class = %q, want %q", got, tc.reason)
			}
			if hookWriteEvidenceHost() {
				payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
					"tool_input": map[string]string{"command": tc.command}})
				if err != nil {
					t.Fatal(err)
				}
				targets, ok := Decode(Resolve(payload))
				if !ok || targets[UnprovenReasonKey] != tc.reason {
					t.Fatalf("hook evidence class = %q, want %q", targets[UnprovenReasonKey], tc.reason)
				}
			}
		})
	}
}
