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
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// manifestReaderCase is one manifest and the entrypoints the plugin scanner
// reads from it.
type manifestReaderCase struct {
	name, manifest, text string
	want                 []string
}

const (
	cachedProtected = "__pycache__/protected.pyc"
	cachedGenerated = "__pycache__/generated.pyc"
)

// manifestReaderCases hold the spellings that decide which file a manifest
// names: aliases as a key and as a value, escapes, repeated keys, merge keys,
// nesting, comments and prose, keys the scanner does not read, and text the
// loader refuses. The scanner is the reference (see the differential test).
var manifestReaderCases = []manifestReaderCase{
	{"alias used as the key", "plugin.yaml", "key: &exec main\n*exec: " + cachedProtected + "\n", []string{cachedProtected}},
	{"alias used as the key, quoted value", "plugin.yaml", "key: &exec \"m\\x61in\"\n*exec: '" + cachedProtected + "'\n", []string{cachedProtected}},
	{"alias of an escaped value", "plugin.yaml", "note: &entry \"__pycache__/prot\\x65cted.pyc\"\nmain: *entry\n", []string{cachedProtected}},
	{"escaped key", "plugin.yaml", "\"m\\u0061in\": " + cachedProtected + "\n", []string{cachedProtected}},
	{"explicit key", "plugin.yaml", "? main\n: " + cachedProtected + "\n", []string{cachedProtected}},
	{"value on the next line", "plugin.yaml", "main:\n  \"" + cachedProtected + "\"\n", []string{cachedProtected}},
	{"entry and entrypoint", "plugin.yaml", "entry: lib/a.js\nentrypoint: " + cachedProtected + "\n", []string{"lib/a.js", cachedProtected}},
	{"bin as a string", "plugin.yaml", "bin: " + cachedProtected + "\n", []string{cachedProtected}},
	{"bin map keeps the last value of a name", "plugin.yaml", "bin:\n  a: " + cachedGenerated + "\n  a: lib/run.js\n  b: " + cachedProtected + "\n", []string{"lib/run.js", cachedProtected}},
	{"last repeated key wins", "plugin.yaml", "main: lib/run.js\nmain: " + cachedProtected + "\n", []string{cachedProtected}},
	{"merge key supplies the value", "plugin.yaml", "base: &b\n  main: " + cachedProtected + "\n<<: *b\n", []string{cachedProtected}},
	{"recursive anchor beside the key", "plugin.yaml", "loop: &a [*a]\nmain: " + cachedProtected + "\n", []string{cachedProtected}},
	{"json escapes", "package.json", `{"main":"__pycache__/prot\u0065cted.pyc"}`, []string{cachedProtected}},
	{"json surrogate pair in the name", "package.json", `{"main":"__pycache__/\ud83d\ude00.pyc"}`, []string{"__pycache__/\U0001F600.pyc"}},
	{"json value the strict reader refuses", "package.json", `{"main":"` + cachedProtected + `","n":NaN}`, []string{cachedProtected}},
	{"json last repeated key wins", "package.json", `{"main":"lib/run.js","main":"` + cachedProtected + `"}`, []string{cachedProtected}},
	{"json bin map", "package.json", `{"bin":{"a":"lib/a.js","b":"` + cachedProtected + `"}}`, []string{"lib/a.js", cachedProtected}},

	// Benign twins: nothing here names a cache file the scanner reads.
	{"nested main", "plugin.yaml", "main: lib/run.js\nmeta:\n  main: " + cachedGenerated + "\n", []string{"lib/run.js"}},
	{"comment", "plugin.yaml", "main: lib/run.js # main: " + cachedGenerated + "\n", []string{"lib/run.js"}},
	{"quoted prose", "plugin.yaml", "description: \"use main: " + cachedGenerated + " here\"\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"block prose", "plugin.yaml", "description: |\n  main: " + cachedGenerated + "\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"shadowed repeated key", "plugin.yaml", "main: " + cachedGenerated + "\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"explicit key shadows a merged one", "plugin.yaml", "base: &b\n  main: " + cachedGenerated + "\n<<: *b\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"first merged mapping wins", "plugin.yaml", "a: &a\n  main: lib/run.js\nb: &b\n  main: " + cachedGenerated + "\n<<: [*a, *b]\n", []string{"lib/run.js"}},
	{"scripts and hooks are not files", "plugin.yaml", "main: lib/run.js\nscripts:\n  start: " + cachedGenerated + "\nhooks: [" + cachedGenerated + "]\nmodule: " + cachedGenerated + "\n", []string{"lib/run.js"}},
	{"plural key and list bin", "plugin.yaml", "entrypoints: [" + cachedGenerated + "]\nbin: [" + cachedGenerated + "]\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"null and blank values", "plugin.yaml", "main: ~\nentry: \"  \"\nentrypoint:\nbin: lib/run.js\n", []string{"lib/run.js"}},
	{"quoted merge indicator is a plain key", "plugin.yaml", "\"<<\":\n  main: " + cachedGenerated + "\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"non-string key", "plugin.yaml", "1: x\nmain: lib/run.js\n", []string{"lib/run.js"}},
	{"json nested main", "package.json", `{"meta":{"main":"` + cachedGenerated + `"},"main":"lib/run.js"}`, []string{"lib/run.js"}},
	{"json shadowed repeated key", "package.json", `{"main":"` + cachedGenerated + `","main":"lib/run.js"}`, []string{"lib/run.js"}},
	{"json prose", "package.json", `{"description":"main: ` + cachedGenerated + `","main":"lib/run.js"}`, []string{"lib/run.js"}},

	// Text the scanner refuses declares nothing.
	{"two documents", "plugin.yaml", "main: lib/a.js\n---\nmain: " + cachedGenerated + "\n", nil},
	{"unknown tag", "plugin.yaml", "main: " + cachedGenerated + "\nx: !custom y\n", nil},
	{"key that is a list", "plugin.yaml", "main: " + cachedGenerated + "\n? [a]\n: b\n", nil},
	{"merge of a scalar", "plugin.yaml", "main: " + cachedGenerated + "\n<<: 1\n", nil},
	{"root that is a list", "plugin.yaml", "- main\n- " + cachedGenerated + "\n", nil},
	{"unterminated flow", "plugin.yaml", "main: " + cachedGenerated + "\nx: [a\n", nil},
	{"json with trailing data", "package.json", `{"main":"lib/a.js"} {"main":"` + cachedGenerated + `"}`, nil},
	{"json root that is a list", "package.json", `["main","` + cachedGenerated + `"]`, nil},
}

// The reader used while the plugin scanner cannot be asked returns exactly
// what the effective top-level mapping declares.
func TestHermesFallbackReadsTheEffectiveMapping(t *testing.T) {
	for _, tc := range manifestReaderCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hermesManifestCandidates(map[string][]byte{tc.manifest: []byte(tc.text)})
			if !sameStrings(got, tc.want) {
				t.Errorf("candidates = %q, want %q", got, tc.want)
			}
		})
	}
}

// The same cases through the real scanner: the fallback and the scanner
// declare the same files. The test skips where the scanner CLI is absent.
func TestHermesFallbackEntrypointsMatchScanner(t *testing.T) {
	load := hermesScannerLoader(t)
	for _, tc := range manifestReaderCases {
		t.Run(tc.name, func(t *testing.T) {
			manifests := map[string][]byte{tc.manifest: []byte(tc.text)}
			scanned, err := load(manifests)
			if err != nil {
				t.Fatalf("scanner: %v", err)
			}
			if got := hermesManifestCandidates(manifests); !sameStrings(got, scanned) {
				t.Errorf("fallback = %q, scanner = %q", got, scanned)
			}
		})
	}
}

func sameStrings(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// During a reader outage under the per-user default, through the watcher: a
// cache file the scanner reads as declared is scanned when it appears, and an
// ordinary cache write beside a manifest that only mentions it is neither a
// scan nor an admission.
func TestHermesManifestOutageScansOnlyWhatTheScannerWouldRead(t *testing.T) {
	for _, tc := range manifestReaderCases {
		wantScans := 0
		if slices.ContainsFunc(tc.want, func(e string) bool { return e == cachedProtected }) {
			wantScans = 1
		}
		t.Run(tc.name, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.plugin(f.bundledRoot, "web/ddgs")
			writePluginFile(t, filepath.Join(path, tc.manifest), tc.text)
			writePluginFile(t, filepath.Join(path, "lib", "run.js"), "safe()\n")
			f.pinVendor("web/ddgs", path)
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			admitted := len(f.admitted[path])
			f.w.hermesManifests = failingManifestLoader
			writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedProtected)), "exec()\n")
			writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedGenerated)), "exec()\n")
			f.w.runRescanCycle(context.Background())
			if got := f.scan.scans(path); got != wantScans {
				t.Errorf("cache files added during the outage caused %d scans, want %d", got, wantScans)
			}
			if got := len(f.admitted[path]); wantScans == 0 && got != admitted {
				t.Errorf("ordinary cache writes caused %d admissions", got-admitted)
			}
		})
	}
}

// What a scanner declares can change with its modules and data while its
// launcher stays the same bytes. The watcher asks the scanner again for each
// snapshot, so the protected file the changed scanner declares is scanned.
func TestHermesManifestAnswerFollowsScannerDependency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	data := filepath.Join(t.TempDir(), "declared")
	script := filepath.Join(t.TempDir(), "defenseclaw")
	body := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.0.9\\n'; exit 0; fi\n" +
		"while read -r _line; do :; done\nread -r answer < '" + data + "'\nprintf '{\"entrypoints\":[\"%s\"]}' \"$answer\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	declare := func(entry string) {
		t.Helper()
		if err := os.WriteFile(data, []byte(entry+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	load := newHermesManifestCache().loader(&scanner.PluginScanner{BinaryPath: script})
	declare("__pycache__/a.pyc")
	if got, err := load(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/a.pyc"}) {
		t.Fatalf("first answer = %q, %v", got, err)
	}
	// A benign twin: nothing changed, the answer is the same.
	if got, err := load(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/a.pyc"}) {
		t.Fatalf("repeated answer = %q, %v", got, err)
	}
	declare("__pycache__/b.pyc")
	if got, err := load(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/b.pyc"}) {
		t.Errorf("after the scanner data changed the watcher answers %q, %v", got, err)
	}

	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\n")
	f.pinVendor("web/ddgs", path)
	declare("__pycache__/a.pyc")
	f.w.hermesManifests = nil
	f.cfg.Scanners.PluginScanner = script
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	writePluginFile(t, filepath.Join(path, "__pycache__", "a.pyc"), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 1 {
		t.Fatalf("the declared cache file caused %d scans, want 1", got)
	}
	declare("__pycache__/b.pyc")
	writePluginFile(t, filepath.Join(path, "__pycache__", "b.pyc"), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 2 {
		t.Errorf("the cache file the changed scanner declares caused %d scans in total, want 2", got)
	}
}
