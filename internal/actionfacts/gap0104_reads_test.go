// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// rel-1-0-10:GAP-0104: Python code that only reads files is not a write.
func TestGAP0104PythonCodeOnlyReads(t *testing.T) {
	for code, reads := range map[string]bool{
		`import json; print(json.load(open("/h/.claude/settings.json")))`:                true,
		`import sys; print(open(sys.argv[1], "rb").read())`:                              true,
		`from pathlib import Path; print(Path("/h/c.toml").read_text().splitlines()[0])`: true,
		`print(line.replace("~/p", "<p>"))`:                                              true,
		`import copy; d = copy.deepcopy({}); e = {}.copy(); sys.stdout.write("x")`:       true,
		`with open("/h/c.toml", mode="r") as f: print(f.read())`:                         true,
		`import os; os.open("/h/c", os.O_RDONLY)`:                                        true,
		`open("/h/c.toml", "w").write("")`:                                               false,
		`open("/h/c.toml", "a")`:                                                         false,
		`open("/h/c.toml", mode)`:                                                        false,
		`from pathlib import Path; Path("/h/c").write_text("")`:                          false,
		`import os; os.replace("/tmp/x", "/h/c")`:                                        false,
		`from pathlib import Path; Path("/tmp/x").replace("/h/c")`:                       false,
		`import shutil; shutil.copy("/tmp/x", "/h/c")`:                                   false,
		`import os; os.remove("/h/c")`:                                                   false,
		`import subprocess; subprocess.run(["rm", "/h/c"])`:                              false,
		`exec("open('/h/c','w')")`:                                                       false,
		`import os; os.chmod("/h/c", 0o777)`:                                             false,
		`with Path("/h/c").open("w") as f: f.write("")`:                                  false,
		`import ctypes`:                         false,
		`import helper; helper.show()`:          false,
		`from mylib import load; print(load())`: false,
		"import json\nfrom pathlib import Path\nprint(Path('/h/c').read_text())": true,
		`print(open("/h/c"`: false,
	} {
		if got := PythonCodeOnlyReads(code); got != reads {
			t.Errorf("PythonCodeOnlyReads(%q) = %t, want %t", code, got, reads)
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
