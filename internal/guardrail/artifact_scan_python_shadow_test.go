// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// An import the program never uses still runs the module it loads, and the
// modules that module imports in turn; for python -c the first place Python
// looks is the working directory. A subprocess.py, helper.py, or a re.py that
// json and pathlib import, there can run the program's docstring, so the
// docstring is not inert. With nothing in that directory the standard
// library runs no string. The interpreter shows the write happen or not; the
// scan, given the directory, must count the docstring whenever the
// interpreter ran it and leave it inert beside nothing, and without the
// directory must keep the docstring whole. Beside a module the interpreter
// never loads for this program (os.py) the scan still counts it: the
// interpreter's own imports, such as a codec lookup, load from there.
func TestShadowedModuleRunsTheMainDocstring(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	const docstring = `"""open("written-by-docstring", "w").write("x")"""`
	for _, module := range []string{"subprocess", "helper", "json"} {
		code := docstring + "\nimport " + module + "\n"
		if !PythonStringsMayRun(MaskPythonStrings(code), "") {
			t.Errorf("PythonStringsMayRun(%q, unknown dir) = false: a shadowed %s.py runs the docstring", code, module)
		}
	}
	preloaded := docstring + "\nimport os\n"
	if !PythonStringsMayRun(MaskPythonStrings(preloaded), "") {
		t.Errorf("PythonStringsMayRun(%q, unknown dir) = false: the interpreter imports on its own", preloaded)
	}
	if PythonStringsMayRun(MaskPythonStrings(preloaded), t.TempDir()) {
		t.Errorf("PythonStringsMayRun(%q, empty dir) = true, want false", preloaded)
	}
	python, err := exec.LookPath("python3")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("no python3 to show the shadowed import run")
	}
	for _, tc := range []struct {
		shadow, imports string
		ran             bool
	}{
		{"subprocess", "import subprocess", true},
		{"helper", "import helper", true},
		{"os", "import os", false},
		{"re", "import json", true},
		{"re", "from pathlib import Path", true},
		{"fnmatch", "from pathlib import Path", true},
		{"", "import subprocess", false},
		{"", "import json", false},
		{"", "from pathlib import Path", false},
	} {
		dir := t.TempDir()
		if tc.shadow != "" {
			shadow := "import sys\nexec(sys.modules['__main__'].__doc__)\n"
			if err := os.WriteFile(filepath.Join(dir, tc.shadow+".py"), []byte(shadow), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		code := docstring + "\n" + tc.imports + "\n"
		mayRun := PythonStringsMayRun(MaskPythonStrings(code), dir)
		cmd := exec.Command(python, "-c", code)
		cmd.Dir = dir
		cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
			return strings.HasPrefix(kv, "PYTHON")
		})
		// A shadow may break the import after it ran; the standard library
		// alone must run clean.
		if out, err := cmd.CombinedOutput(); err != nil && tc.shadow == "" {
			t.Fatalf("python3 -c %q beside %q: %v: %s", tc.imports, tc.shadow, err, out)
		}
		_, err := os.Stat(filepath.Join(dir, "written-by-docstring"))
		if ran := err == nil; ran != tc.ran {
			t.Errorf("%s beside %q.py ran the docstring = %t, want %t", tc.imports, tc.shadow, ran, tc.ran)
		}
		if tc.ran && !mayRun || tc.shadow == "" && mayRun {
			t.Errorf("PythonStringsMayRun(%q, dir with %q.py) = %t, the interpreter ran it = %t", code, tc.shadow, mayRun, tc.ran)
		}
	}
}

// Code can move what a standard-library import loads, or the interpreter
// imports on its own: sys under another name (s = sys, (sys), os.sys,
// sys.exit.__self__) whose path it changes, a package's __path__, a .pth
// file site.addsitedir runs, a module the code links or renames into the
// working directory, or a codec lookup or help() that imports from it with no
// import statement. The working directory is empty when the scan looks; the
// interpreter shows each program run the docstring, so the scan must count
// it.
func TestImportPathMovesRunTheMainDocstring(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	python, err := exec.LookPath("python3")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("no python3 to show the moved import run")
	}
	const docstring = `"""open("written-by-docstring", "w").write("x")"""`
	const shadow = "import sys\nexec(sys.modules['__main__'].__doc__)\n"
	for _, tc := range []struct {
		name   string
		staged string // a file of the staging directory, SHADOW in code
		local  string // a file of the working directory
		code   string
	}{
		{"sys alias", "json.py", "", "import sys; s = sys; s.path.insert(0, SHADOW); import json"},
		{"sys in parentheses", "json.py", "", "import sys; (sys).path.insert(0, SHADOW); import json"},
		{"sys in a list", "json.py", "", "import sys; [sys][0].path.insert(0, SHADOW); import json"},
		{"sys through __self__", "json.py", "", "import sys; sys.exit.__self__.path.insert(0, SHADOW); import json"},
		{"sys through os", "json.py", "", "import os; p = os.sys; p.path.insert(0, SHADOW); import json"},
		{"sys renamed in a list", "json.py", "", "import sys as s, sys; s.path.insert(0, SHADOW); import json"},
		{"package path", "evil.py", "", "import json; json.__path__.insert(0, SHADOW); import json.evil"},
		{"site directory", "x.pth", "", "import site; site.addsitedir(SHADOW)"},
		{"symlink into the directory", "json.py", "", "import os; os.symlink(SHADOW + '/json.py', 'json.py'); import json"},
		{"rename into the directory", "json.py", "", "import os; os.rename(SHADOW + '/json.py', 'json.py'); import json"},
		{"codec lookup", "", "stringprep.py", "'a'.encode('idna')"},
		{"help", "", "pydoc.py", "help(len)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, staging := t.TempDir(), t.TempDir()
			if tc.staged != "" {
				body := shadow
				if filepath.Ext(tc.staged) == ".pth" {
					body = "import sys; exec(sys.modules['__main__'].__doc__)\n"
				}
				if err := os.WriteFile(filepath.Join(staging, tc.staged), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.local != "" {
				if err := os.WriteFile(filepath.Join(work, tc.local), []byte(shadow), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code := docstring + "\n" + strings.ReplaceAll(tc.code, "SHADOW", strconv.Quote(staging)) + "\n"
			mayRun := PythonStringsMayRun(MaskPythonStrings(code), work)
			cmd := exec.Command(python, "-c", code)
			cmd.Dir = work
			cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
				return strings.HasPrefix(kv, "PYTHON") || strings.HasPrefix(kv, "PAGER=")
			}), "PAGER=cat")
			_, _ = cmd.CombinedOutput() // a shadow may break the program after it ran
			if _, err := os.Stat(filepath.Join(work, "written-by-docstring")); err != nil {
				t.Fatalf("python3 -c %q did not run the docstring: the case shows nothing", tc.code)
			}
			if !mayRun {
				t.Errorf("PythonStringsMayRun(%q, working directory) = false: the interpreter ran the docstring", code)
			}
		})
	}
}
