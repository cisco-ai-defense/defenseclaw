// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// An f- or t-string runs its replacement fields, so only inert comments and
// triple-quoted strings are blanked; source the scan cannot follow is left
// whole (fail closed).
func TestMaskPythonCommentsAndDocstringsKeepsExecutedText(t *testing.T) {
	const write = "p.write_text("
	for _, tc := range []struct {
		name, source string
		visible      bool
	}{
		{"comment", "x = 1  # p.write_text(\"k\")\n", false},
		{"docstring", `"""p.write_text("k")"""` + "\nprint(1)\n", false},
		{"bytes docstring", `b"""p.write_text("k")"""`, false},
		{"docstring after an f-string", `print(f"{1}"); """p.write_text("k")"""`, false},
		{"name ending in a prefix letter", `if"""p.write_text("k")""" in x: pass`, false},
		{"code", `p.write_text("k")`, true},
		{"f-string field", `f"""{p.write_text("k")}"""`, true},
		{"raw f-string field", `rF'''{p.write_text("k")}'''`, true},
		{"template string field", `t"""{p.write_text("k")}"""`, true},
		{"same quotes in a field", `f"""{"""a""" + str(p.write_text("k"))}"""`, true},
		{"format spec field", `f"""{x:{p.write_text("k")}}"""`, true},
		{"code after an escaped quote", `x = """a\""""; p.write_text("k")`, true},
		{"code after an f-string", `f"""{x!r:>{w}}"""; p.write_text("k")`, true},
		// The literal text of an f-string is inert; only its fields run.
		{"f-string literal text", `f"""p.write_text("k")"""`, false},
		{"raw f-string literal text", `Rf'''p.write_text("k")'''`, false},
		{"template string literal text", `t"""p.write_text("k") {x}"""`, false},
		{"f-string text after a field", `f"""{x!r:>{w}} p.write_text("k")"""`, false},
		{"f-string text beside a field that writes", `f"""p.write_text {p.write_text("k")}"""`, true},
		{"f-string escaped braces are text", `f"""{{p.write_text("k")}}"""`, false},
		// Format spec text is literal; its nested fields run.
		{"format spec text", `f"""{x:p.write_text("k")}"""`, false},
		{"format spec text after a conversion", `f"""{x!r:p.write_text("k")}"""`, false},
		{"format spec text after a nested field", `f"""{x:{w}p.write_text("k")}"""`, false},
		{"multiline f-string field", "f\"\"\"a\n{\n p.write_text(\"k\")\n}\nb\"\"\"", true},
		{"single-quoted f-string", `f"p.write_text('k')"`, true},
		{"unclosed field", `f"""{p.write_text("k")"""`, true},
		{"unclosed docstring", `"""p.write_text("k")`, true},
	} {
		masked := MaskPythonCommentsAndDocstrings(tc.source)
		if len(masked) != len(tc.source) {
			t.Fatalf("%s: masked length %d, want %d", tc.name, len(masked), len(tc.source))
		}
		if got := strings.Contains(masked, write); got != tc.visible {
			t.Errorf("%s: %q masked to %q: write visible=%t, want %t", tc.name, tc.source, masked, got, tc.visible)
		}
	}
}

// MaskPythonStrings leaves only the code that runs: the text of every string
// is blanked, f-string fields are kept with their own strings blanked.
func TestMaskPythonStringsKeepsOnlyCode(t *testing.T) {
	const write = "p.write_text("
	for _, tc := range []struct {
		name, source string
		visible      bool
	}{
		{"code", `p.write_text("k")`, true},
		{"string", `print("p.write_text(1)")`, false},
		{"one-line f-string text", `print(f"p.write_text(42)")`, false},
		{"one-line f-string field", `print(f"{p.write_text('k')}")`, true},
		{"string in a field", `print(f"{'p.write_text(1)'}")`, false},
		{"nested f-string text", `print(f"{f'p.write_text(1) {x}'}")`, false},
		{"docstring", `"""p.write_text(1)"""`, false},
		{"comment", "x = 1 # p.write_text(1)", false},
		{"bytes", `b"p.write_text(1)"`, false},
		{"unclosed string", `print("p.write_text(1)`, true},
		// Format spec text is literal; a nested field and the expression run.
		{"one-line format spec text", `print(f"{x:p.write_text(42)}")`, false},
		{"format spec text after a conversion", `print(f"{x!s:p.write_text(42)}")`, false},
		{"format spec text beside a nested field", `print(f"{x:>{w}p.write_text(42)}")`, false},
		{"nested format spec field", `print(f"{x:{p.write_text(42)}}")`, true},
		{"expression before a format spec", `print(f"{p.write_text(42):>10}")`, true},
		{"expression before a conversion", `print(f"{p.write_text(42)!r}")`, true},
		{"inequality in a field", `print(f"{p.write_text(42) != 1}")`, true},
	} {
		masked := MaskPythonStrings(tc.source)
		if len(masked) != len(tc.source) {
			t.Fatalf("%s: masked length %d, want %d", tc.name, len(masked), len(tc.source))
		}
		if got := strings.Contains(masked, write); got != tc.visible {
			t.Errorf("%s: %q masked to %q: write visible=%t, want %t", tc.name, tc.source, masked, got, tc.visible)
		}
	}
}

// Only the expressions of f-string fields are code: the braces, a conversion,
// a self-documenting "=" and format spec text are blanked.
func TestMaskPythonStringsFieldExpressions(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`f"{x:>{w}}"`, `f  x   w   `},
		{`f"{p=}"`, `f  p   `},
		{`f"{p = !r}"`, `f  p       `},
		{`f"{p!r}"`, `f  p    `},
		{`f"{a != b}"`, `f  a != b  `},
		{`f"{a == b}"`, `f  a == b  `},
		{`f"{x!r:{w}}"`, `f  x    w   `},
		{`f"{d['k']=}"`, `f  d[   ]   `},
	} {
		if got := MaskPythonStrings(tc.source); got != tc.want {
			t.Errorf("MaskPythonStrings(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
}

// Code may run a string only through a sink it names in code, or through a
// module an import may load from the working directory (a shadowed
// subprocess.py or helper.py can run __main__.__doc__). In a directory that
// holds no module, an import of standard-library modules no name of which is
// used runs nothing, nor does a variable of the program's own whose name
// holds a sink word. With the directory not known every program counts: the
// interpreter imports on its own ("a".encode("idna") imports stringprep).
func TestPythonStringsMayRun(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	clean := t.TempDir()
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{`import subprocess; """x"""; print("ok")`, false},
		{"import subprocess as sp, ctypes\nfrom os import system as run, popen\nprint('ok')", false},
		{"from os import system as run, popen\nprint('ok')", false},
		{`if x: import subprocess`, false},
		{`if x: import os`, false},
		{"from importlib import (util,\n    machinery)", false},
		{"from os import (path,\n    sep)", false},
		// A module outside the standard library may be a file of the working
		// directory, used or not.
		{`import helper`, true},
		{`import os.path as p; p.join("a")`, false},
		{`from os.path import join; join("a")`, false},
		{`import sys, io, abc, codecs, stat`, false},
		{`import builtins`, false},
		{`from . import helper`, true},
		{`from .helper import x`, true},
		{`from.helper import x`, true},
		{`import os,`, true},
		// Python reads identifiers in NFKC form: a name the scan cannot
		// match may be exec or an import of any module.
		{"ｅｘｅｃ(\"x\")", true},
		{"import ｊｓｏｎ", true},
		{"import os; print('café')", false},
		{`print("exec subprocess")`, false},
		{`# exec`, false},
		{`f"exec {x}"`, false},
		{`import subprocess; subprocess.run(["true"])`, true},
		{`import subprocess as sp; sp.run(["true"])`, true},
		{`from subprocess import run; f = run`, true},
		{`from subprocess import *`, true},
		{`from subprocess import run,`, true},
		{`exec("x")`, true},
		{`f"{eval('x')}"`, true},
		{`import os; os.posix_spawn("/bin/true", [], {})`, true},
		{`import timeit; timeit.timeit("x")`, true},
		{`exec(__doc__)`, true},
		{`print(__doc__)`, true},
		{`import sys; print(sys.orig_argv)`, true},
		{`open("m.py", "w").write("x"); import m`, true},
		{`import sys; sys.modules["subprocess"]`, true},
		{`().__class__.__base__.__subclasses__()`, true},
		{`import pty`, false},
		{`import pty; pty.spawn("sh")`, true},
		// A variable of the program's own is not a sink.
		{`source = 1; print(source)`, false},
		{`source: int = 1`, false},
		{`(source := 1)`, false},
		{"for frame in []:\n    pass", false},
		{`def write(doc, handler=None): return doc`, false},
		{`class Loader: pass`, false},
		{`copy_count = 1; f(write=True)`, false},
		{`code = 1; gc = code`, false},
		// A builtin, a dunder, an attribute, an imported name, or a name a star
		// import may bind still counts.
		{`source = exec; source("x")`, true},
		{`exec = print`, true},
		{`print(copyright)`, true},
		{`print(__loader__)`, true},
		{`print(x.source)`, true},
		{"print(x.\\\n source)", true},
		{`from inspect import getsource as source; print(source)`, true},
		{`from m import source; print(source)`, true},
		{`from os import *; source = 1`, true},
		{`from os import *; system("x")`, true},
		{`import os as source; source.getcwd()`, true},
	} {
		if got := PythonStringsMayRun(MaskPythonStrings(tc.source), clean); got != tc.want {
			t.Errorf("PythonStringsMayRun(%q, clean dir) = %t, want %t", tc.source, got, tc.want)
		}
		if !PythonStringsMayRun(MaskPythonStrings(tc.source), "") {
			t.Errorf("PythonStringsMayRun(%q, unknown dir) = false: the interpreter imports on its own", tc.source)
		}
	}
}

// A write call spelled in a string, or in the literal text of an f-string,
// writes nothing; a path in a string that a call in code writes still does.
func TestPythonPathWriteMatchNeedsAWriteCallInCode(t *testing.T) {
	rule := regexp.MustCompile(`authorized_keys`)
	sourceDir := t.TempDir()
	// The script itself sits in its directory; it is not a module beside it.
	script := filepath.Join(sourceDir, "writer.py")
	if err := os.WriteFile(script, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	for _, tc := range []struct {
		name, source string
		want         bool
	}{
		{"assigned then written", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\np.write_text(\"k\")\n", true},
		{"open append", "open('/home/a/.ssh/authorized_keys', 'a').write('k')\n", true},
		{"f-string field open", "print(f\"{open('/home/a/.ssh/authorized_keys', 'a')}\")\n", true},
		{"exec of a string", "exec(\"open('/home/a/.ssh/authorized_keys', 'a').write('k')\")\n", true},
		{"f-string text", "p = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"p.write_text(42)\")\n", false},
		{"string text", "p = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", false},
		{"f-string text beside an import", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"p.write_text(42)\")\n", false},
		{"string text beside an import", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", false},
		{"string text beside a preloaded import", "import os\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", false},
		{"printed open", "print(\"open('/home/a/.ssh/authorized_keys', 'a')\")\n", false},
		{"printed Path write", "print(\"Path('/home/a/.ssh/authorized_keys').write_text('k')\")\n", false},
		{"format spec text", "p = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"{1:p.write_text(42)}\")\n", false},
		{"format spec field", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"{1:{p.write_text(42)}}\")\n", true},
		{"printed open beside an ordinary variable", "source = 1\nprint(\"open('/home/a/.ssh/authorized_keys', 'a')\")\n", false},
		{"exec through a local alias", "source = exec\nsource(\"open('/home/a/.ssh/authorized_keys', 'a').write('k')\")\n", true},
	} {
		if got := pythonPathWriteMatch(rule, tc.source, script) != nil; got != tc.want {
			t.Errorf("%s: pythonPathWriteMatch(%q) = %t, want %t", tc.name, tc.source, got, tc.want)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "pathlib.py"), []byte("# local module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shadowed := "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n"
	if pythonPathWriteMatch(rule, shadowed, script) == nil {
		t.Fatal("a local pathlib.py can consume the program's string text")
	}
	if err := os.Remove(filepath.Join(sourceDir, "pathlib.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "fnmatch.py"), []byte("# pathlib dependency\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pythonPathWriteMatch(rule, shadowed, script) == nil {
		t.Fatal("an import dependency can consume the program's string text")
	}
	if err := os.Remove(filepath.Join(sourceDir, "fnmatch.py")); err != nil {
		t.Fatal(err)
	}
	pathChanged := "import sys\nsys.path.insert(0, 'other')\n" + shadowed
	if pythonPathWriteMatch(rule, pathChanged, script) == nil {
		t.Fatal("a changed sys.path can load another module")
	}
	t.Setenv("PYTHONPATH", sourceDir)
	if pythonPathWriteMatch(rule, shadowed, script) == nil {
		t.Fatal("PYTHONPATH can load another module")
	}
}

// With the directory Python imports from first known, a standard-library
// import leaves the strings inert only when that directory holds nothing an
// import can load and nothing moves the import path. Any other import, a
// sink, a loadable file or package of any kind, a link, an unreadable or
// oversized directory, PYTHONPATH or PYTHONHOME, or code that changes
// sys.path or the directory still counts.
func TestPythonStringsMayRunInAKnownDirectory(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"docs", "my-dir", ".git"} {
		if err := os.MkdirAll(filepath.Join(clean, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A directory no import can name, or a directory that is not a package.
	for _, file := range []string{"docs/README.md", "my-dir/__init__.py", ".git/__init__.py"} {
		if err := os.WriteFile(filepath.Join(clean, file), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{`import subprocess; """x"""; print("ok")`, false},
		{"import subprocess as sp, ctypes\nfrom os import system as run, popen\nprint('ok')", false},
		{`import json; print(json.loads("1"))`, false},
		{`from pathlib import Path; print(Path("a"))`, false},
		{`import os, json`, false},
		{`import xml.etree.ElementTree as ET`, false},
		{`from __future__ import annotations`, false},
		{"from collections import (OrderedDict,\n    deque)", false},
		// Not the standard library, or not a form the scan reads.
		{`import helper`, true},
		{`import json, helper`, true},
		{`from helper import x`, true},
		{`from . import helper`, true},
		{`from .helper import x`, true},
		{`from json import *`, true},
		{`import __main__`, true},
		{`import tomllib`, true},
		{`import imp`, true},
		// A sink still counts.
		{`import subprocess; subprocess.run(["true"])`, true},
		{`import json; exec("x")`, true},
		// The import path or the directory moves.
		{`import sys; sys.path.insert(0, "x"); import json`, true},
		{`import sys; sys . meta_path.clear(); import json`, true},
		{`import sys; sys.path_hooks.clear(); import json`, true},
		{`import os; os.sys.path.insert(0, "x"); import json`, true},
		{`from sys import path; path.insert(0, "x"); import json`, true},
		{`import sys as s; s.path.insert(0, "x"); import json`, true},
		{`import os, sys as s; import json`, true},
		{`import os; os.chdir("/tmp"); import json`, true},
		{`from os import chdir as cd; cd("/tmp"); import json`, true},
		{`import os; os.fchdir(3); import json`, true},
		{`import os; os.chroot("x"); import json`, true},
		// sys by another name, or an attribute that holds the import system.
		{`import sys; s = sys; s.path.insert(0, "x"); import json`, true},
		{`import sys; (sys).path.insert(0, "x"); import json`, true},
		{`import sys; [sys][0].path.insert(0, "x"); import json`, true},
		{`import sys; m = {"m": sys}; import json`, true},
		{`import sys; f(sys); import json`, true},
		{`import sys; (s := sys); import json`, true},
		{`import sys; f"{sys}"; import json`, true},
		{"import sys\nmatch sys:\n    case _: pass\nimport json", true},
		{"import os\nmatch os:\n    case object(sys=s): pass\nimport json", true},
		{`import sys; sys.exit.__self__.path.insert(0, "x"); import json`, true},
		{`import os; p = os.sys; p.path.insert(0, "x"); import json`, true},
		{`import codecs; codecs.sys.path.insert(0, "x"); import json`, true},
		{`import os; os.path.sys.path.insert(0, "x"); import json`, true},
		{`import sys as s, sys; s.path.insert(0, "x"); import json`, true},
		{"import sys \\\n    as s; import json", true},
		{"from sys \\\n    import path; import json", true},
		{`from os import sys as s; import json`, true},
		{`from os import (sys as s); import json`, true},
		{`import sys; sys = None; import json`, true},
		{`import sys; sys.pycache_prefix = "x"; import json`, true},
		{`import sys; sys.implementation.cache_tag = "x"; import json`, true},
		{`import sys; sys.remote_exec(1, "x"); import json`, true},
		{`import sys; sys.path_importer_cache.clear(); import json`, true},
		{`import sys; sys.`, true},
		// A package's search path, or a module that loads from any directory.
		{`import json; json.__path__.insert(0, "x"); import json.evil`, true},
		{`import json; json.__spec__.submodule_search_locations.append("x")`, true},
		{`import site; site.addsitedir("x")`, true},
		{`from site import addsitedir; addsitedir("x")`, true},
		{`import zipimport`, true},
		// A module the code puts in the directory before it imports.
		{`import os; os.symlink("x", "json.py"); import json`, true},
		{`import os; os.link("x", "json.py"); import json`, true},
		{`import os; os.rename("x", "json.py"); import json`, true},
		{`import os; os.replace("x", "json.py"); import json`, true},
		{`from pathlib import Path; Path("json.py").symlink_to("x"); import json`, true},
		{`from pathlib import Path; Path("x").rename("json.py"); import json`, true},
		{`import shutil; shutil.move("x", "json.py"); import json`, true},
		{`import shutil; shutil.unpack_archive("x"); import json`, true},
		{`import zipfile; zipfile.ZipFile("x").extractall(); import json`, true},
		{`import urllib.request; urllib.request.urlretrieve("x", "json.py"); import json`, true},
		{`import os; os.mkfifo("json.py"); import json`, true},
		// sys read through attributes that hold nothing of the import system.
		{`import sys; sys.exit(0); import json`, false},
		{`import os, sys; print(os.sys.version_info, sys.platform); import json`, false},
		{"import sys\nsys.stderr.flush()\nsys . maxsize\nimport json", false},
		{`from os import sys; sys.exit(0)`, false},
		{`import sys.monitoring`, false},
		// No import statement: the interpreter's own imports load from the
		// directory too, and it holds nothing.
		{`"a".encode("idna")`, false},
	} {
		if got := PythonStringsMayRun(MaskPythonStrings(tc.source), clean); got != tc.want {
			t.Errorf("PythonStringsMayRun(%q, clean dir) = %t, want %t", tc.source, got, tc.want)
		}
	}
	const program = `import json; """x"""; print("ok")`
	// The interpreter imports on its own ("a".encode("idna") imports
	// stringprep and re, help() imports pydoc), with no import statement.
	const implicit = `"""x"""; "a".encode("idna"); help(len)`
	// Anything an import may load, in the directory.
	for _, entry := range []string{
		"helper.py", "JSON.PY", "tool.pyw", "cached.pyc", "old.pyo", "native.so",
		"native.cpython-312-x86_64-linux-gnu.so", "native.pyd", "bundle.zip", "bundle.egg",
		"pkg/__init__.py", "pkg/__init__.pyc", "pkg/__init__.cpython-312-x86_64-linux-gnu.so",
		"Pkg/__INIT__.PY", "caf\u00e9/__init__.py",
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, entry)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, code := range []string{program, implicit} {
			if !PythonStringsMayRun(MaskPythonStrings(code), dir) {
				t.Errorf("PythonStringsMayRun(%q) beside %s = false: an import may load it", code, entry)
			}
		}
	}
	if runtime.GOOS != "windows" {
		linked := t.TempDir()
		if err := os.Symlink(filepath.Join(clean, "notes.txt"), filepath.Join(linked, "notes")); err != nil {
			t.Fatal(err)
		}
		if !PythonStringsMayRun(MaskPythonStrings(program), linked) {
			t.Error("PythonStringsMayRun beside a link = false: a link may name a module")
		}
	}
	crowded := t.TempDir()
	for i := 0; i <= pythonDirMaxEntries; i++ {
		if err := os.WriteFile(filepath.Join(crowded, fmt.Sprintf("n%03d.txt", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !PythonStringsMayRun(MaskPythonStrings(program), crowded) {
		t.Error("PythonStringsMayRun in a directory over the entry bound = false")
	}
	bigPackage := t.TempDir()
	for _, sub := range []string{"a", "b"} {
		for i := 0; i < pythonPackageMaxEntries/2+1; i++ {
			name := filepath.Join(bigPackage, sub, fmt.Sprintf("n%04d.txt", i))
			if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !PythonStringsMayRun(MaskPythonStrings(program), bigPackage) {
		t.Error("PythonStringsMayRun past the package entry bound = false")
	}
	for _, dir := range []string{"", "relative/dir", filepath.Join(clean, "missing")} {
		for _, code := range []string{program, implicit} {
			if !PythonStringsMayRun(MaskPythonStrings(code), dir) {
				t.Errorf("PythonStringsMayRun(%q, %q) = false: the directory is not known", code, dir)
			}
		}
	}
	if !PythonStringsMayRun(MaskPythonStrings(program), clean+string(filepath.Separator)+"notes.txt") {
		t.Error("PythonStringsMayRun with a file for a directory = false")
	}
	t.Setenv("PYTHONPATH", clean)
	if !PythonStringsMayRun(MaskPythonStrings(program), clean) {
		t.Error("PYTHONPATH puts another directory first")
	}
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", clean)
	if !PythonStringsMayRun(MaskPythonStrings(program), clean) {
		t.Error("PYTHONHOME moves the standard library")
	}
}

// The artifact scan reads a script's imports from the script's own
// directory, wherever the scan is started from.
func TestArtifactPythonPathWriteReadsTheScriptsDirectory(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	pack := &RulePack{RuleFiles: []*RulesFileYAML{{
		Category: "persistence",
		Rules: []RuleDefYAML{{
			ID: "SSH-KEYS", Pattern: `authorized_keys`, Title: "authorized keys write",
			Severity: "HIGH", Confidence: 0.9,
			Expression: "f.paths.exists(p, p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE)",
		}},
	}}}
	work := t.TempDir()
	t.Chdir(work)
	// work/scripts is clean; the skill's own scripts directory is not.
	for _, dir := range []string{"scripts", filepath.Join("skill", "scripts")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	script := "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n"
	writer := filepath.Join("skill", "scripts", "writer.py")
	if err := os.WriteFile(writer, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"skill", writer} {
		findings, err := pack.ScanArtifact(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Errorf("ScanArtifact(%s) beside no module = %+v, want none (the text is printed)", path, findings)
		}
	}
	if err := os.WriteFile(filepath.Join("skill", "scripts", "re.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"skill", writer} {
		findings, err := pack.ScanArtifact(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 1 {
			t.Errorf("ScanArtifact(%s) beside re.py = %+v, want the write (pathlib imports re)", path, findings)
		}
	}
}
