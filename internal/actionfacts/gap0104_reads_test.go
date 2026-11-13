// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// gap0104PythonWriteFixtures are the existing write fixtures of this suite and
// of find_leading_options_test.go (by id), with the callable each names. The
// derived forms below reach the same callable through a reference
// (rel-1-0-10:GAP-0244); no new write string is written here.
var gap0104PythonWriteFixtures = []struct{ id, code, callee string }{
	{"os-remove", `import os; os.remove("/h/c")`, "os.remove"},
	{"os-replace", `import os; os.replace("/tmp/x", "/h/c")`, "os.replace"},
	{"os-chmod", `import os; os.chmod("/h/c", 0o777)`, "os.chmod"},
	{"find-os-remove", `import os, sys; os.remove(sys.argv[1])`, "os.remove"},
	{"shutil-copy", `import shutil; shutil.copy("/tmp/x", "/h/c")`, "shutil.copy"},
	{"subprocess-run", `import subprocess; subprocess.run(["rm", "/h/c"])`, "subprocess.run"},
}

// gap0104DerivedWriteForms rewrites a fixture's call of its callable into a
// reference to it: an alias, a parenthesised or subscripted callee, a call of
// a computed value, an f-string field, a default-argument and a mapped value.
func gap0104DerivedWriteForms(code, callee string) map[string]string {
	call := callee + "("
	head, tail, _ := strings.Cut(code, call)
	expr := call + tail
	if cut := strings.LastIndex(code, "; "); cut >= 0 {
		expr = code[cut+2:]
	}
	return map[string]string{
		"alias":           head + "ref = " + callee + "; ref(" + tail,
		"parenthesised":   head + "(" + callee + ")(" + tail,
		"subscripted":     head + "[" + callee + "][0](" + tail,
		"computed":        head + "sorted([" + callee + "])[0](" + tail,
		"f-string":        code[:strings.LastIndex(code, "; ")+2] + `print(f"{` + expr + `}")`,
		"mapped":          head + "list(map(" + callee + ", [1]))",
		"keyword-value":   head + "sorted([1], key=" + callee + ")",
		"walrus-alias":    head + "(ref := " + callee + ")(" + tail,
		"conditional-ref": head + "(" + callee + " if True else None)(" + tail,
	}
}

// rel-1-0-10:GAP-0104, GAP-0244: Python code is read-only only when every
// name it uses is on the reviewed allowlist.
func TestGAP0104PythonCodeOnlyReads(t *testing.T) {
	for code, reads := range map[string]bool{
		// Reads the allowlist accepts.
		`import json; print(json.load(open("/h/.claude/settings.json")))`:                                              true,
		`import sys; print(open(sys.argv[1], "rb").read())`:                                                            true,
		`from pathlib import Path; print(Path("/h/c.toml").read_text().splitlines()[0])`:                               true,
		`print(line.replace("~/p", "<p>"))`:                                                                            true,
		`import copy; d = copy.deepcopy({}); e = {}.copy(); sys.stdout.write("x")`:                                     true,
		`with open("/h/c.toml", mode="r") as f: print(f.read())`:                                                       true,
		`import os; os.open("/h/c", os.O_RDONLY)`:                                                                      true,
		"import json\nfrom pathlib import Path\nprint(Path('/h/c').read_text())":                                       true,
		`import sys; print(len(open(sys.argv[1]).read().splitlines()))`:                                                true,
		`import json, sys; d = json.load(open(sys.argv[1])); print(sorted(d.keys()))`:                                  true,
		`from pathlib import Path; p = Path("/h/c.toml"); print(p.name, p.exists(), p.stat().st_size)`:                 true,
		`import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())`:                       true,
		`import os; print([n for n in os.listdir("/h") if n.endswith(".toml")])`:                                       true,
		`import re; print(re.findall(r"a+", open("/h/c").read()))`:                                                     true,
		`import sys; print(f"{len(open(sys.argv[1]).read())} bytes")`:                                                  true,
		`import os; print(os.environ.get("HOME", ""), os.environ["HOME"])`:                                             true,
		"for line in open('/h/c'):\n    print(line.rstrip())":                                                          true,
		"import sys\nfor a in sys.argv[1:]:\n    print(a)":                                                             true,
		`d = {"a": " x "}; print({k: v.strip() for k, v in d.items()})`:                                                true,
		`import json; p = "/h/c"; d = json.load(open(p)); print([(k, len(v)) for k, v in d.get("hooks", {}).items()])`: true,
		`import sys; print(open(sys.argv[1], encoding="utf-8").read(), file=sys.stdout)`:                               true,
		`from hashlib import sha256; print(sha256(b"x").hexdigest())`:                                                  true,
		`try:
    print(open("/h/c").read())
except OSError as e:
    print(e)`: true,
		// Writes and everything the allowlist does not recognise.
		`open("/h/c.toml", "w").write("")`:                         false,
		`open("/h/c.toml", "a")`:                                   false,
		`open("/h/c.toml", mode)`:                                  false,
		`from pathlib import Path; Path("/h/c").write_text("")`:    false,
		`from pathlib import Path; Path("/tmp/x").replace("/h/c")`: false,
		`with Path("/h/c").open("w") as f: f.write("")`:            false,
		`import ctypes`:                            false,
		`import helper; helper.show()`:             false,
		`from mylib import load; print(load())`:    false,
		`import tempfile; print(1)`:                false,
		`import os as o; print(o.getcwd())`:        false,
		`from os import *`:                         false,
		`from . import x`:                          false,
		`from os import remove`:                    false,
		`x = "a"; print(x.frobnicate())`:           false,
		`print(sorted([1], key=len))`:              false,
		`f = print; f(1)`:                          false,
		`print(list(map(str, [1])))`:               false,
		`print(open)`:                              false,
		`print((lambda: 1)())`:                     false,
		"def f():\n    pass":                       false,
		"class C:\n    pass":                       false,
		"@x\ndef f(): pass":                        false,
		`print(x.__class__)`:                       false,
		`print(__builtins__)`:                      false,
		`import os; os.environ["A"] = "b"`:         false,
		`import sys; sys.stdout = None`:            false,
		`import os; print(os.path)`:                false,
		`print(f"{x!r:{w}}")`:                      true,
		`print(f"{open}")`:                         false,
		`print(f"{")`:                              false,
		`print(open("/h/c"`:                        false,
		`print("a")(1)`:                            false,
		`d = {}; d["k"](1)`:                        false,
		`import json; json.dump({}, open("/h/c"))`: false,
		`import os; os.getcwd = 1`:                 false,
		``:                                         false,
		`a = "x"; b = "y"; print(f"{a} {b}")`:      true,
		`from pathlib import Path; Path("/h/c").replace(f"{a}{b}")`: false,
	} {
		if got := PythonCodeOnlyReads(code); got != reads {
			t.Errorf("PythonCodeOnlyReads(%q) = %t, want %t", code, got, reads)
		}
	}
	for _, name := range strings.Fields("getattr setattr delattr eval exec compile vars globals locals input breakpoint " +
		"memoryview type object super classmethod staticmethod property callable map filter hasattr dir id") {
		for _, code := range []string{name + "('x')", "print(" + name + ")", "ref = " + name} {
			if PythonCodeOnlyReads(code) {
				t.Errorf("PythonCodeOnlyReads(%q) = true: builtin %s is not reviewed", code, name)
			}
		}
	}
}

// The unsafe fixtures stay may-write, and so does every reference form of
// the callable they name.
func TestGAP0104PythonWriteFixturesAndTheirReferenceForms(t *testing.T) {
	for _, fixture := range gap0104PythonWriteFixtures {
		if PythonCodeOnlyReads(fixture.code) {
			t.Errorf("fixture %s %q reads as read-only", fixture.id, fixture.code)
		}
		for form, code := range gap0104DerivedWriteForms(fixture.code, fixture.callee) {
			if PythonCodeOnlyReads(code) {
				t.Errorf("fixture %s, %s form %q reads as read-only", fixture.id, form, code)
			}
			argv := []string{"find", "/h", "-name", "c.yaml", "-exec", "python3", "-c", code, "{}", ";"}
			if !FindHandedEntries(argv).Writes() {
				t.Errorf("fixture %s, %s form: find -exec hands off no write for %q", fixture.id, form, code)
			}
		}
	}
	// A method reached by reference (Path(...).write_text bound, then called).
	const method = `from pathlib import Path; Path("/h/c").write_text("")`
	for form, code := range map[string]string{
		"bound":      strings.Replace(method, `Path("/h/c").write_text("")`, `w = Path("/h/c").write_text; w("")`, 1),
		"in a list":  strings.Replace(method, `Path("/h/c").write_text("")`, `[Path("/h/c").write_text][0]("")`, 1),
		"f-string":   strings.Replace(method, `Path("/h/c").write_text("")`, `print(f"{Path('/h/c').write_text('')}")`, 1),
		"read-first": strings.Replace(method, `Path("/h/c").write_text("")`, `p = Path("/h/c"); p.read_text(); p.write_text("")`, 1),
	} {
		if PythonCodeOnlyReads(code) {
			t.Errorf("method form %s %q reads as read-only", form, code)
		}
	}
}

// A find -exec shell body or python -c code that only reads changes no handed
// entry; one that writes still may.
func TestGAP0104FindHandedReadOnlyBodies(t *testing.T) {
	for _, tc := range []struct {
		argv   []string
		writes bool
	}{
		{[]string{"find", "/h/.defenseclaw/hooks", "-type", "f", "-exec", "sh", "-c", `for f do printf "%s " "$f"; sha256sum "$f"; done`, "sh", "{}", "+"}, false},
		{[]string{"find", "/h", "-exec", "bash", "-c", `jq -c keys "$1" 2>/dev/null; stat -c %s "$1" >&2`, "sh", "{}", ";"}, false},
		{[]string{"find", "/h", "-name", "c.yaml", "-exec", "python3", "-c", "import sys; print(open(sys.argv[1]).read())", "{}", ";"}, false},
		{[]string{"find", "/h", "-exec", "sh", "-c", `: > "$1"`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "-c", `cat "$1" > /tmp/out`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "-c", `rm -f "$1"`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "-c", `eval "$1"`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "-c", `f() { rm "$1"; }; f "$1"`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "-c", `$CMD "$1"`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "-c", `sed -i s/a/b/ "$1"`, "sh", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "python3", "-c", "import sys; open(sys.argv[1], 'w')", "{}", ";"}, true},
		{[]string{"find", "/h", "-exec", "sh", "/tmp/script.sh", "{}", ";"}, true},
	} {
		if got := FindHandedEntries(tc.argv).Writes(); got != tc.writes {
			t.Errorf("FindHandedEntries(%q).Writes() = %t, want %t", tc.argv, got, tc.writes)
		}
	}
}
