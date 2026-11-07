// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

type hermesManifestCase struct{ Name, File, Body string }

// hermesScannerManifests loads every case with the real plugin scanner
// (_load_manifest) in one Python process and returns the entrypoints it reads
// from each, and whether the scanner raised. The test skips where Python or
// the scanner is absent.
func hermesScannerManifests(t *testing.T, cases []hermesManifestCase) (read [][]string, raised []bool) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	cli, err := filepath.Abs(filepath.Join("..", "..", "cli"))
	if err != nil {
		t.Fatal(err)
	}
	const script = `import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from defenseclaw.scanner.plugin_scanner import scanner
out = []
for case in json.load(sys.stdin):
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, case["File"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(case["Body"])
        try:
            manifest = scanner._load_manifest(directory)
            out.append({"E": list(manifest.entrypoints) if manifest else [], "R": False})
        except Exception:
            out.append({"E": [], "R": True})
print(json.dumps(out))`
	run := func(cases []hermesManifestCase) ([]byte, error) {
		input, err := json.Marshal(cases)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(python, "-I", "-c", script, cli)
		cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		cmd.Stdin = bytes.NewReader(input)
		return cmd.Output()
	}
	if _, err := run([]hermesManifestCase{{"probe", "plugin.yaml", "name: p\n"}}); err != nil {
		t.Skipf("plugin scanner not importable: %v", err)
	}
	out, err := run(cases)
	if err != nil {
		t.Fatalf("plugin scanner: %v", err)
	}
	var results []struct {
		E []string
		R bool
	}
	if err := json.Unmarshal(out, &results); err != nil || len(results) != len(cases) {
		t.Fatalf("plugin scanner output: %v (%d results for %d cases)", err, len(results), len(cases))
	}
	for _, r := range results {
		read, raised = append(read, r.E), append(raised, r.R)
	}
	return read, raised
}

// requireScannerEntrypoints checks that, for every case, the watcher binds
// exactly the entrypoints the plugin scanner reads: not a replaced or refused
// one (a false block on an ordinary cache write) and not fewer (a protected
// allow). A manifest this package cannot decide (ok false) is bound as a whole,
// which is allowed only where the scanner reads nothing from it or the caller
// names the case.
func requireScannerEntrypoints(t *testing.T, cases []hermesManifestCase, undecided ...string) {
	t.Helper()
	read, raised := hermesScannerManifests(t, cases)
	var failures []string
	for i, c := range cases {
		ours, ok := hermesManifestEntrypoints(c.File, []byte(c.Body))
		want := slices.Clone(read[i])
		slices.Sort(want)
		want = slices.Compact(want)
		slices.Sort(ours)
		ours = slices.Compact(ours)
		switch {
		case !ok && (len(want) == 0 || slices.Contains(undecided, c.Name)):
		case !ok:
			failures = append(failures, fmt.Sprintf("%s: not decided here, scanner reads %q", c.Name, want))
		case raised[i] && len(ours) == 0:
		case !slices.Equal(want, ours):
			failures = append(failures, fmt.Sprintf("%s: scanner reads %q (raised %v), watcher binds %q", c.Name, want, raised[i], ours))
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		shown := failures[:min(len(failures), 40)]
		t.Fatalf("%d of %d manifests differ from the plugin scanner:\n%s", len(failures), len(cases), strings.Join(shown, "\n"))
	}
}

// hermesYAMLKeySpellings are mapping keys of every type PyYAML resolves, in
// plain, quoted and tagged spellings; PyYAML makes one dict key of 1, 1.0 and
// True, of 1:00 and 60, of .inf and +.Inf, and of !!int 1 and 1.
var hermesYAMLKeySpellings = []string{
	"1", "1.0", "+1", "01", "0b1", "0x1", "1_", "!!int 1", "!!float 1", "!!int 0x1", "!!bool true", "!!bool yes",
	"true", "True", "yes", "on", "! 1",
	`"1"`, `'1'`, "!!str 1", `"true"`,
	"0", "-0.0", "false", "no", "off", "!!int 0", "!!bool off",
	"~", "null", "Null", "!!null null", "!!null x", "!!null ~", `"null"`, "!!str null",
	"60", "1:00", "0b111100", "0x3c", "074", "!!int 1:00", "60.0", "1:00.0", "!!float 60", "!!float 1:00.0", "-1:00", "-60",
	".inf", "+.Inf", ".INF", "-.inf", "!!float .inf", "!!float +.INF", ".nan", ".NaN", "!!float .nan",
	".5", "0.5", "!!float 0.5", "1000", "!!int 1_000", "!!float 1e3", "1e3",
	"2001-01-01", "!!timestamp 2001-01-01", `"2001-01-01"`,
	"=", `"="`, "!!value =", "<<", `"<<"`, "!!merge <<", "!!str <<",
	"[a]", "{a: b}", "!!seq [a]", "!!set {a}",
	"!!binary YQ==", "!!binary YQ",
	"p", "!!str p", `"p"`, "!foo p",
}

// GAP-0645 review 15: two keys in a bin map are one key to the plugin
// scanner exactly when PyYAML builds one dict key from them, whatever their
// spelling, and the later value replaces the earlier. Every ordered pair of
// spellings is run through the real scanner.
func TestHermesYAMLKeyIdentityMatchesScanner(t *testing.T) {
	var cases []hermesManifestCase
	for _, a := range hermesYAMLKeySpellings {
		for _, b := range hermesYAMLKeySpellings {
			cases = append(cases, hermesManifestCase{
				Name: a + " then " + b, File: "plugin.yaml",
				Body: "name: p\nbin:\n  " + a + ": __pycache__/provider.cpython-312.pyc\n  " + b + ": lib/run.js\n",
			})
		}
	}
	requireScannerEntrypoints(t, cases)
}

// A scalar is a str, and so an entrypoint, exactly when PyYAML builds a str
// from it; a number, a Boolean, a null, a date or a binary is not.
func TestHermesYAMLScalarTypesMatchScanner(t *testing.T) {
	values := []string{
		"lib/run.js", "5", "1.5", "true", "null", "~", "", "0x10", "1:00", "2001-01-01", ".inf", "=", "<<",
		`"5"`, `'5'`, `'  '`, "!!str 5", "!!int 5", "!!int abc", "!!int 1.5", "!!bool maybe", "!!float x", "!foo x",
		"!!binary YQ==", "!!null x", "!!timestamp 2001-01-01", "[a]", "{a: b}", "!!str lib/run.js",
		"|\n    lib/run.js", ">\n    lib/run.js", "! lib/run.js", "&a lib/run.js", "!!str", "!!int", "0o7", "0b102", "089",
	}
	templates := []string{"main: V\n", "bin: V\n", "bin:\n  p: V\n  q: other.js\n", "entry: V\n", "entrypoint: V\n"}
	var cases []hermesManifestCase
	for _, template := range templates {
		for _, value := range values {
			cases = append(cases, hermesManifestCase{
				Name: strings.TrimSpace(strings.ReplaceAll(template, "V", value)), File: "plugin.yaml",
				Body: "name: p\n" + strings.ReplaceAll(template, "V", value),
			})
		}
	}
	requireScannerEntrypoints(t, cases)
}

// A document the plugin scanner refuses declares nothing: a second document,
// a tag the safe loader has no constructor for, a bad scalar of a known tag, a
// merge key that is not a mapping, an unhashable key, anywhere in the file.
func TestHermesYAMLDocumentsMatchScanner(t *testing.T) {
	docs := map[string]string{
		"plain":                 "main: lib/run.js\n",
		"multi-document":        "main: lib/run.js\n---\nname: p\n",
		"empty-second-document": "main: lib/run.js\n---\n",
		"document-end-marker":   "main: lib/run.js\n...\n",
		"leading-marker":        "---\nmain: lib/run.js\n",
		"unknown-tag":           "main: lib/run.js\nx: !foo y\n",
		"python-tag":            "main: lib/run.js\nx: !!python/name:os.system\n",
		"bad-int":               "main: lib/run.js\nx: !!int abc\n",
		"bad-bool":              "main: lib/run.js\nx: !!bool maybe\n",
		"bad-float":             "main: lib/run.js\nx: !!float abc\n",
		"merge-scalar":          "main: lib/run.js\n<<: 5\n",
		"merge-list-scalar":     "main: lib/run.js\n<<: [5]\n",
		"merge-list":            "<<: [{a: 1}, {main: lib/run.js}]\n",
		"merge-as-value":        "main: lib/run.js\nx: <<\n",
		"value-as-value":        "main: lib/run.js\nx: =\n",
		"value-as-key":          "main: lib/run.js\n=: x\n",
		"unhashable-key":        "main: lib/run.js\n[a]: x\n",
		"unhashable-nested-key": "main: lib/run.js\nx:\n  [a]: y\n",
		"unhashable-map-key":    "main: lib/run.js\n? {a: b}\n: x\n",
		"set":                   "main: lib/run.js\nx: !!set {a, b}\n",
		"omap":                  "main: lib/run.js\nx: !!omap [{a: 1}, {b: 2}]\n",
		"omap-bad":              "main: lib/run.js\nx: !!omap [a]\n",
		"pairs":                 "main: lib/run.js\nx: !!pairs [{a: 1}, {a: 2}]\n",
		"binary":                "main: lib/run.js\nx: !!binary YQ==\n",
		"str-on-map":            "main: lib/run.js\nx: !!str {a: b}\n",
		"map-on-scalar":         "main: lib/run.js\nx: !!map a\n",
		"seq-on-scalar":         "main: lib/run.js\nx: !!seq a\n",
		"int-on-seq":            "main: lib/run.js\nx: !!int [1]\n",
		"timestamps":            "main: lib/run.js\nx: 2001-01-01\ny: 2001-01-01 10:00:00 +01:00\n",
		"top-list":              "- main\n",
		"top-scalar":            "main\n",
		"empty":                 "",
		"comment-only":          "# nothing\n",
		"recursive-anchor":      "main: lib/run.js\nx: &a {y: *a}\n",
		"recursive-list":        "main: lib/run.js\nx: &a [*a]\n",
		"alias-key":             "k: &k main\n*k : lib/run.js\n",
		"byte-order-mark":       "\ufeffmain: lib/run.js\n",
		"crlf":                  "main: lib/run.js\r\nname: p\r\n",
		"flow-mapping":          "{main: lib/run.js, name: p}\n",
		"complex-key":           "? main\n: lib/run.js\n",
		"empty-key":             "? \n: x\nmain: lib/run.js\n",
		"merge-explicit-tag":    "!!merge <<: {main: lib/run.js}\n",
		"merge-quoted":          "'<<': {main: other.js}\nmain: lib/run.js\n",
		"merge-recursive":       "x: &x\n  <<: *x\nmain: lib/run.js\n",
		"merge-in-set":          "main: lib/run.js\nx: !!set\n  <<: {a: null}\n",
		"int-keys-then-main":    "1: a\n1.0: b\nmain: lib/run.js\n",
		"bin-string-and-map":    "bin: lib/a.js\nbin:\n  p: lib/run.js\n",
		"main-tagged-key":       "!!str main: lib/run.js\n",
		"main-quoted-key":       "'main': lib/run.js\n",
		"bin-null-value":        "bin:\n  p:\n  q: lib/run.js\n",
		"anchor-on-key-and-use": "&k main: lib/run.js\nother: *k\n",
		"multiline-plain":       "main: lib/\n  run.js\n",
		"timestamp-bad":         "main: lib/run.js\nx: !!timestamp abc\n",
		"float-sexagesimal-bad": "main: lib/run.js\nx: !!float 1:xx\n",
		"int-sexagesimal-bad":   "main: lib/run.js\nx: !!int 1:xx\n",
		"null-with-value":       "main: lib/run.js\nx: !!null yes\n",
		"bool-case":             "main: lib/run.js\nx: !!bool TRUE\n",
		"verbatim-tag":          "main: lib/run.js\nx: !<tag:yaml.org,2002:int> 5\n",
		"verbatim-local-tag":    "main: lib/run.js\nx: !<!local> 5\n",
		"tag-directive":         "%TAG !e! tag:yaml.org,2002:\n---\nmain: lib/run.js\nx: !e!int 5\n",
		"tag-directive-unknown": "%TAG !e! tag:example.com,2000:\n---\nmain: lib/run.js\nx: !e!int 5\n",
		"yaml-directive":        "%YAML 1.1\n---\nmain: lib/run.js\n",
		"yaml-directive-1-2":    "%YAML 1.2\n---\nmain: lib/run.js\n",
		"long-int":              "main: lib/run.js\nx: 123456789012345678901234567890\n",
		"octal-like":            "main: lib/run.js\nx: 0o17\ny: 08\n",
		"special-floats":        "main: lib/run.js\nx: [.inf, -.inf, .nan, 1e3, 1.5e+3]\n",
	}
	var cases []hermesManifestCase
	for name, body := range docs {
		cases = append(cases, hermesManifestCase{Name: name, File: "plugin.yaml", Body: body})
	}
	// libyaml (the scanner loader) reads a %YAML 1.2 directive and a mapping
	// that merges itself; yaml.v3 does not, so those are bound as a whole.
	requireScannerEntrypoints(t, cases, "merge-recursive", "yaml-directive-1-2")
}

// GAP-0645 review 15: the plugin scanner reads a .json manifest with
// json.loads, which refuses text YAML would read, and accepts NaN and
// Infinity. A manifest it refuses declares nothing, and a manifest it reads
// declares exactly its entrypoints.
func TestHermesJSONManifestMatchesScanner(t *testing.T) {
	docs := map[string]string{
		"plain":                `{"main":"lib/run.js"}`,
		"trailing-comma":       `{"main":"lib/run.js",}`,
		"single-quotes":        `{'main':'lib/run.js'}`,
		"yaml-object":          "main: lib/run.js\n",
		"yaml-flow":            `{main: lib/run.js}`,
		"nan":                  `{"x":NaN,"main":"lib/run.js"}`,
		"infinity":             `{"x":Infinity,"main":"lib/run.js"}`,
		"negative-infinity":    `{"x":-Infinity,"main":"lib/run.js"}`,
		"negative-nan":         `{"x":-NaN,"main":"lib/run.js"}`,
		"plus-number":          `{"x":+1,"main":"lib/run.js"}`,
		"leading-zero":         `{"x":01,"main":"lib/run.js"}`,
		"trailing-dot":         `{"x":1.,"main":"lib/run.js"}`,
		"leading-dot":          `{"x":.5,"main":"lib/run.js"}`,
		"exponent":             `{"x":1e5,"main":"lib/run.js"}`,
		"signed-exponent":      `{"x":-1.5E+5,"main":"lib/run.js"}`,
		"negative-zero":        `{"x":-0,"main":"lib/run.js"}`,
		"bad-exponent":         `{"x":1e,"main":"lib/run.js"}`,
		"hex":                  `{"x":0x1,"main":"lib/run.js"}`,
		"duplicate-main":       `{"main":"a.js","main":"lib/run.js"}`,
		"duplicate-main-last":  `{"main":"lib/run.js","main":"a.js"}`,
		"duplicate-bin":        `{"bin":{"a":"x.js","a":"lib/run.js"}}`,
		"bin-blank":            `{"bin":"  "}`,
		"bin-string":           `{"bin":"lib/run.js"}`,
		"main-number":          `{"main":5}`,
		"main-null":            `{"main":null}`,
		"main-list":            `{"main":["lib/run.js"]}`,
		"all-keys":             `{"main":"a.js","bin":{"p":"b.js"},"entry":"c.js","entrypoint":"d.js"}`,
		"comment":              `{"main":"lib/run.js"} // c`,
		"trailing-data":        `{"main":"lib/run.js"} x`,
		"two-values":           `{"main":"lib/run.js"}{}`,
		"empty":                ``,
		"whitespace":           " \n\t ",
		"array-top":            `["main"]`,
		"string-top":           `"main"`,
		"control-character":    "{\"main\":\"lib/run.js\",\"x\":\"a\tb\"}",
		"escaped-slash":        `{"main":"lib\/run.js"}`,
		"bad-escape":           `{"main":"lib\x/run.js"}`,
		"unicode-escape":       `{"main":"lib\u002frun.js"}`,
		"short-unicode-escape": `{"main":"lib\u12/run.js"}`,
		"lone-surrogate":       `{"x":"\ud800","main":"lib/run.js"}`,
		"surrogate-pair":       `{"x":"\ud83d\ude00","main":"lib/run.js"}`,
		"byte-order-mark":      "\ufeff{\"main\":\"lib/run.js\"}",
		"form-feed":            "\f{\"main\":\"lib/run.js\"}",
		"missing-colon":        `{"main" "lib/run.js"}`,
		"missing-comma":        `{"x":1 "main":"lib/run.js"}`,
		"unquoted-key":         `{main:"lib/run.js"}`,
		"unterminated-string":  `{"main":"lib/run.js`,
		"unterminated-object":  `{"main":"lib/run.js"`,
		"nested":               `{"a":{"b":[1,2,{"c":null}]},"main":"lib/run.js"}`,
		"deep":                 `{"x":` + strings.Repeat("[", 60) + strings.Repeat("]", 60) + `,"main":"lib/run.js"}`,
		"trailing-comma-array": `{"x":[1,],"main":"lib/run.js"}`,
		"empty-array-member":   `{"x":[,1],"main":"lib/run.js"}`,
		"literal-prefix":       `{"x":nulls,"main":"lib/run.js"}`,
		"capital-literal":      `{"x":True,"main":"lib/run.js"}`,
		"crlf":                 "{\r\n\"main\": \"lib/run.js\"\r\n}\r\n",
	}
	var cases []hermesManifestCase
	for name, body := range docs {
		for _, file := range []string{"package.json", ".claude-plugin/plugin.json"} {
			cases = append(cases, hermesManifestCase{Name: file + " " + name, File: file, Body: body})
		}
	}
	requireScannerEntrypoints(t, cases)
}
