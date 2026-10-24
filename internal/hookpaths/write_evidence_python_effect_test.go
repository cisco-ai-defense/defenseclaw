// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestR104Refix3WriteEvidence(t *testing.T) {
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
	for _, tc := range []struct {
		name, command, reason string
	}{
		{"awk computed target", `awk 'BEGIN { target="alias"; print "marker" >> target }'`, "dynamic-argument"},
		{"awk adjacent literal target", `awk 'BEGIN { print "marker" >> "ali" "as" }'`, "dynamic-argument"},
		{"awk mutated target", `awk 'BEGIN { target="report.txt"; sub(/report.txt/, "alias", target); print "marker" >> target }'`, "dynamic-argument"},
		{"awk side effect before target", `awk 'BEGIN { target="report.txt"; system("ln -sf ~/.ssh/authorized_keys report.txt"); print "marker" >> target }'`, "dynamic-argument"},
		{"awk quoted ordinary target", `awk 'BEGIN { print "marker" >> "report.txt" }'`, ""},
		{"computed Path receiver", `python3 -c 'from pathlib import Path; p=Path("ali"+"as"); p.write_text("marker")'`, "interpreter-path"},
		{"ordinary Path data", `python3 -c 'from pathlib import Path; Path("out/result.json").write_text("alias")'`, ""},
		{"ordinary Path escaped data", `python3 -c 'from pathlib import Path; Path("out/result.json").write_text("alias\n")'`, ""},
		{"ordinary open data", `python3 -c 'open("out.txt","w").write("alias")'`, ""},
		{"parse error after write", `echo marker >> alias; if (`, "shell-parse"},
		{"parse error after dynamic write", `echo marker >> "$destination"; if (`, "shell-parse"},
		{"parse error after copy", `cp report.txt alias; if (`, "shell-parse"},
		{"parse error after Python write", `python3 -c 'open("alias","a").write("marker")'; if (`, "shell-parse"},
		{"parse error after ordinary copy", `cp report.txt out.txt; if (`, ""},
		{"parse error with protected data", `echo alias >> out.txt; if (`, ""},
		{"nice unknown option", `nice --adjustment=5 python3 -c 'open("alias","a").write("marker")'`, "dynamic-argument"},
		{"timeout unknown option", `timeout --signal=TERM 30 python3 -c 'open("alias","a").write("marker")'`, "dynamic-argument"},
		{"opaque launcher computed target", `nice --adjustment=5 python3 -c 'open("ali"+"as","a").write("marker")'`, "interpreter-path"},
		{"xargs replacement form", `printf alias | xargs --replace=DEST python3 -c 'open("DEST","a").write("marker")'`, ""},
		{"copyfile keyword literal expression", `python3 -c 'import shutil; shutil.copyfile(src="payload",dst="ali" "as")'`, "interpreter-path"},
		{"copyfile optional literal expression", `python3 -c 'import shutil; shutil.copyfile("payload","ali" "as",follow_symlinks=True)'`, "interpreter-path"},
		{"GAP-0475 f-string with inert argv", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{p.write_text("marker")}"""' .`, "interpreter-path"},
		{"GAP-0475 triple string beside the protected path", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; """{p.write_text("marker")}"""'`, "interpreter-path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := UnprovenProtectedWrite(tc.command, cwd, home); got != tc.reason {
				t.Fatalf("reason=%q, want %q", got, tc.reason)
			}
		})
	}
	for _, command := range []string{
		`printf alias | xargs --replace=DEST python3 -c 'open("DEST","a").write("marker")'`,
		`python3 -c 'from shutil import copyfile; copyfile("payload","alias")'`,
		`python3 -c 'import shutil; shutil.copyfile(src="payload",dst="alias")'`,
		`python3 -c 'import shutil; shutil.copyfile("payload","alias",follow_symlinks=True)'`,
	} {
		if got := LiteralWriteOperands(command, cwd, home); !slices.Contains(got, filepath.Join(cwd, "alias")) {
			t.Errorf("%q operands=%q, want alias", command, got)
		}
	}
}

func TestR104PythonStringEffectPosition(t *testing.T) {
	for _, tc := range []struct {
		code string
		want bool
	}{
		{`f"""{p.write_text("marker")}"""`, true},
		{`fr"""{p.write_text("marker")}"""`, true},
		{`"""{p.write_text("marker")}"""`, false},
		{`f"""{{p.write_text("marker")}}"""`, false},
		{`"value"; p.write_text("marker")`, true},
	} {
		position := strings.Index(tc.code, "write_text")
		if got := pythonExecutableCodePosition(tc.code, position); got != tc.want {
			t.Errorf("code %q: executable=%v, want %v", tc.code, got, tc.want)
		}
	}
}
