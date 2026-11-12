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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

const (
	cachedProtected = "__pycache__/protected.pyc"
	cachedGenerated = "__pycache__/generated.pyc"
)

// protectedManifests is a manifest that declares a bytecode cache file as its
// entrypoint.
var protectedManifests = map[string][]byte{"plugin.yaml": []byte("name: p\nmain: " + cachedProtected + "\n")}

// healthyManifestLoader is a scanner that answers: the manifests declare
// cachedProtected.
func healthyManifestLoader(map[string][]byte) ([]string, error) {
	return []string{cachedProtected}, nil
}

// outagePlugin writes a plugin folder with protectedManifests and the two cache
// files, and returns it.
func outagePlugin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), string(protectedManifests["plugin.yaml"]))
	writePluginFile(t, filepath.Join(dir, filepath.FromSlash(cachedProtected)), "one")
	writePluginFile(t, filepath.Join(dir, filepath.FromSlash(cachedGenerated)), "one")
	return dir
}

// Outage rule (a): the scanner cannot answer, so the last answer it gave for
// the same manifest bytes is applied exactly, in the same process and after a
// restart, whatever the policy tier: the cache file it declared stays bound
// and an ordinary generated cache file stays out.
func TestHermesManifestOutageAppliesTheLastScannerAnswer(t *testing.T) {
	for _, open := range []bool{true, false} {
		t.Run(fmt.Sprintf("failOpen=%v", open), func(t *testing.T) {
			data := t.TempDir()
			failOpen := func() bool { return open }
			first := newHermesManifestPolicy(data, nil)
			if got, err := first.byPolicy(healthyManifestLoader, failOpen)(protectedManifests); err != nil || !slices.Equal(got, []string{cachedProtected}) {
				t.Fatalf("answer = %q, %v", got, err)
			}
			for name, policy := range map[string]*hermesManifestPolicy{
				"same process": first,
				"restart":      newHermesManifestPolicy(data, nil),
			} {
				load := policy.byPolicy(failingManifestLoader, failOpen)
				got, err := load(protectedManifests)
				if err != nil || !slices.Equal(got, []string{cachedProtected}) {
					t.Fatalf("%s: outage answer = %q, %v, want the last answer", name, got, err)
				}
				dir := outagePlugin(t)
				base := skippedTreeHash(dir, load)
				if base == "" {
					t.Fatalf("%s: the declared cache file is not bound during the outage", name)
				}
				writePluginFile(t, filepath.Join(dir, filepath.FromSlash(cachedGenerated)), "two")
				if skippedTreeHash(dir, load) != base {
					t.Errorf("%s: an ordinary cache write changed the hash during the outage", name)
				}
				writePluginFile(t, filepath.Join(dir, filepath.FromSlash(cachedProtected)), "two")
				if skippedTreeHash(dir, load) == base {
					t.Errorf("%s: an edit of the declared cache file was not seen during the outage", name)
				}
			}
		})
	}
}

// Outage rule (b): no earlier answer for these manifest bytes means the
// manifests are unknown. A changed manifest, a damaged store file and a
// missing store are each unknown, and the tier decides.
func TestHermesManifestOutageWithoutAnAnswerIsUnknown(t *testing.T) {
	changed := map[string][]byte{"plugin.yaml": append(slices.Clone(protectedManifests["plugin.yaml"]), "# edited\n"...)}
	extra := map[string][]byte{"plugin.yaml": protectedManifests["plugin.yaml"], "package.json": []byte("{}")}
	data := t.TempDir()
	open, closed := func() bool { return true }, func() bool { return false }
	if _, err := newHermesManifestPolicy(data, nil).byPolicy(healthyManifestLoader, open)(protectedManifests); err != nil {
		t.Fatal(err)
	}
	damaged := t.TempDir()
	if err := os.WriteFile(filepath.Join(damaged, hermesStoreFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		dir       string
		manifests map[string][]byte
	}{
		"manifest bytes changed":   {data, changed},
		"manifest file added":      {data, extra},
		"damaged store":            {damaged, protectedManifests},
		"store never written":      {t.TempDir(), protectedManifests},
		"no data directory at all": {"", protectedManifests},
	} {
		if _, err := newHermesManifestPolicy(tc.dir, nil).byPolicy(failingManifestLoader, open)(tc.manifests); !errors.Is(err, errHermesManifestFailOpen) {
			t.Errorf("%s: per-user default error = %v, want the fail-open outage rule", name, err)
		}
		if _, err := newHermesManifestPolicy(tc.dir, nil).byPolicy(failingManifestLoader, closed)(tc.manifests); err == nil || errors.Is(err, errHermesManifestFailOpen) {
			t.Errorf("%s: strict error = %v, want the closed outage rule", name, err)
		}
	}
	// The unchanged manifests still have their answer.
	if got, err := newHermesManifestPolicy(data, nil).byPolicy(failingManifestLoader, open)(protectedManifests); err != nil || !slices.Equal(got, []string{cachedProtected}) {
		t.Errorf("unchanged manifests = %q, %v, want the last answer", got, err)
	}
}

// A scanner that answers is always believed over the store, and replaces it.
func TestHermesManifestOutageStoreNeverOverridesALiveAnswer(t *testing.T) {
	data := t.TempDir()
	open := func() bool { return true }
	policy := newHermesManifestPolicy(data, nil)
	if _, err := policy.byPolicy(healthyManifestLoader, open)(protectedManifests); err != nil {
		t.Fatal(err)
	}
	other := func(map[string][]byte) ([]string, error) { return []string{"lib/run.js"}, nil }
	if got, err := policy.byPolicy(other, open)(protectedManifests); err != nil || !slices.Equal(got, []string{"lib/run.js"}) {
		t.Fatalf("live answer = %q, %v", got, err)
	}
	if got, err := newHermesManifestPolicy(data, nil).byPolicy(failingManifestLoader, open)(protectedManifests); err != nil || !slices.Equal(got, []string{"lib/run.js"}) {
		t.Errorf("outage answer = %q, %v, want the newest live answer", got, err)
	}
}

// Each distinct outage is printed and audited once, naming the outage.
func TestHermesManifestOutageIsAuditedOncePerKind(t *testing.T) {
	var rows []string
	policy := newHermesManifestPolicy("", func(details string) { rows = append(rows, details) })
	open, closed := func() bool { return true }, func() bool { return false }
	for range 3 {
		_, _ = policy.byPolicy(failingManifestLoader, open)(protectedManifests)
	}
	if len(rows) != 1 || !strings.Contains(rows[0], "outage") {
		t.Fatalf("fail-open outage rows = %q, want one naming the outage", rows)
	}
	for range 3 {
		_, _ = policy.byPolicy(failingManifestLoader, closed)(protectedManifests)
	}
	if len(rows) != 2 {
		t.Fatalf("rows after a strict outage = %q, want two", rows)
	}
}

// Through the watcher. Outage rule (a): a shipped plugin whose scanner answer
// was kept keeps its declared cache file bound while the scanner is down, and
// its ordinary cache writes are neither scans nor admissions, in every tier.
// Outage rule (b): with no earlier answer the per-user default allows writes
// in the plugin folder with an audit row naming the outage, and the strict
// tier scans them. (A managed install takes the Secure Client path, which has
// no vendor shortcut.)
func TestHermesManifestOutageInWatcherFollowsTheRule(t *testing.T) {
	for _, tc := range []struct {
		name          string
		tier          string
		answered      bool
		wantGenerated int
		wantTotal     int
	}{
		{"last answer, per-user default", "", true, 0, 1},
		{"last answer, strict", "strict", true, 0, 1},
		{"no answer, per-user default", "", false, 0, 0},
		{"no answer, strict", "strict", false, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			f.w.cfg.Guardrail.RulePack = tc.tier
			path := f.plugin(f.bundledRoot, "web/ddgs")
			writePluginFile(t, filepath.Join(path, "plugin.yaml"), string(protectedManifests["plugin.yaml"]))
			generated := filepath.Join(path, filepath.FromSlash(cachedGenerated))
			if tc.answered {
				// The scanner is asked once, because a cache file exists.
				writePluginFile(t, generated, "one")
			}
			f.pinVendor("web/ddgs", path)
			f.w.hermesManifests = healthyManifestLoader
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			f.w.hermesManifests = failingManifestLoader
			admitted := len(f.admitted[path])
			writePluginFile(t, generated, "two")
			f.w.runRescanCycle(context.Background())
			if got := f.scan.scans(path); got != tc.wantGenerated {
				t.Errorf("an ordinary cache write during the outage caused %d scans, want %d", got, tc.wantGenerated)
			}
			if got := len(f.admitted[path]); tc.wantGenerated == 0 && got != admitted {
				t.Errorf("an ordinary cache write during the outage caused %d admissions", got-admitted)
			}
			writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedProtected)), "exec()\n")
			f.w.runRescanCycle(context.Background())
			if got := f.scan.scans(path); got != tc.wantTotal {
				t.Errorf("the declared cache file written during the outage gave %d scans in total", got)
			}
			logs, _ := f.runtime.snapshot()
			named := false
			for _, record := range logs {
				raw, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				named = named || strings.Contains(string(raw), "manifest reader outage")
			}
			if !named {
				t.Error("no audit row names the manifest reader outage")
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
	load := hermesManifestsFrom(&scanner.PluginScanner{BinaryPath: script})
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

// A stored answer that is not a scanner answer is damaged, so its manifests are
// unknown and the tier decides: a record with no entrypoints list, a null list
// or a null element is dropped, as the scanner reply decoder rejects the same
// shapes. An explicit empty list is an answer.
func TestHermesManifestOutageDamagedStoredAnswerIsUnknown(t *testing.T) {
	digest := hermesManifestDigest(protectedManifests)
	open, closed := func() bool { return true }, func() bool { return false }
	for _, tc := range []struct {
		name, record string
		wantAnswer   bool
	}{
		{"entrypoints missing", `{"seen":123}`, false},
		{"entrypoints null", `{"entrypoints":null,"seen":123}`, false},
		{"null element", `{"entrypoints":[null],"seen":123}`, false},
		{"null element after a name", `{"entrypoints":["lib/run.js",null],"seen":123}`, false},
		{"explicit empty list", `{"entrypoints":[],"seen":123}`, true},
		{"named entrypoint", `{"entrypoints":["` + cachedProtected + `"],"seen":123}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := t.TempDir()
			writePluginFile(t, filepath.Join(data, hermesStoreFileName), `{"answers":{"`+digest+`":`+tc.record+`}}`)
			if got, err := newHermesManifestPolicy(data, nil).byPolicy(failingManifestLoader, open)(protectedManifests); tc.wantAnswer != (err == nil) {
				t.Errorf("per-user default: %q, %v, want an answer = %v", got, err, tc.wantAnswer)
			} else if !tc.wantAnswer && !errors.Is(err, errHermesManifestFailOpen) {
				t.Errorf("per-user default error = %v, want the fail-open outage rule", err)
			}
			outage := newHermesManifestPolicy(data, nil).byPolicy(failingManifestLoader, closed)
			if got, err := outage(protectedManifests); tc.wantAnswer != (err == nil) {
				t.Errorf("strict: %q, %v, want an answer = %v", got, err, tc.wantAnswer)
			} else if !tc.wantAnswer && errors.Is(err, errHermesManifestFailOpen) {
				t.Errorf("strict error = %v, want the closed outage rule", err)
			}
			// Strict binds the declared cache file when the answer is unknown
			// and when it names the file; an explicit empty list binds none.
			dir := outagePlugin(t)
			first := skippedTreeHash(dir, outage)
			writePluginFile(t, filepath.Join(dir, filepath.FromSlash(cachedProtected)), "two")
			bound := skippedTreeHash(dir, outage) != first
			wantBound := !tc.wantAnswer || tc.record != `{"entrypoints":[],"seen":123}`
			if bound != wantBound {
				t.Errorf("strict: an edit of the declared cache file changed the hash = %v, want %v", bound, wantBound)
			}
		})
	}
}

// The strict tier scans a declared cache file written during an outage when
// the store holds a damaged answer for the plugin's manifests.
func TestHermesManifestOutageDamagedStoredAnswerInStrictWatcher(t *testing.T) {
	f := newHermesPluginFixture(t)
	f.w.cfg.Guardrail.RulePack = "strict"
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), string(protectedManifests["plugin.yaml"]))
	f.pinVendor("web/ddgs", path)
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	digest := hermesManifestDigest(protectedManifests)
	writePluginFile(t, filepath.Join(f.w.cfg.DataDir, hermesStoreFileName), `{"answers":{"`+digest+`":{"entrypoints":null,"seen":123}}}`)
	f.w.hermesManifests = failingManifestLoader
	writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedProtected)), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got == 0 {
		t.Fatal("the declared cache file written during the outage was not scanned")
	}
}

// A record of another digest that is damaged is dropped alone: the valid answer
// for these manifests still applies during an outage, in every tier.
func TestHermesManifestOutageDamagedSiblingKeepsTheValidAnswer(t *testing.T) {
	digest := hermesManifestDigest(protectedManifests)
	valid := `{"entrypoints":["` + cachedProtected + `"],"seen":123}`
	open, closed := func() bool { return true }, func() bool { return false }
	for _, tc := range []struct{ name, sibling string }{
		{"entrypoints is not a list", `{"entrypoints":"x","seen":1}`},
		{"entrypoints holds a number", `{"entrypoints":[1],"seen":1}`},
		{"seen is not a number", `{"entrypoints":[],"seen":"x"}`},
		{"record is a string", `"x"`},
		{"record is a list", `[1,2]`},
		{"record is null", `null`},
		{"null element", `{"entrypoints":[null],"seen":1}`},
		{"entrypoints missing", `{"seen":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := t.TempDir()
			writePluginFile(t, filepath.Join(data, hermesStoreFileName),
				`{"answers":{"sibling":`+tc.sibling+`,"`+digest+`":`+valid+`}}`)
			for tier, isOpen := range map[string]func() bool{"per-user default": open, "strict": closed} {
				got, err := newHermesManifestPolicy(data, nil).byPolicy(failingManifestLoader, isOpen)(protectedManifests)
				if err != nil || !slices.Equal(got, []string{cachedProtected}) {
					t.Errorf("%s: %q, %v, want the valid answer", tier, got, err)
				}
			}
		})
	}
}

// The same in the watcher, per-user default tier: the declared cache file
// written during the outage is scanned although an unrelated record is damaged.
func TestHermesManifestOutageDamagedSiblingInPerUserWatcher(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), string(protectedManifests["plugin.yaml"]))
	f.pinVendor("web/ddgs", path)
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	digest := hermesManifestDigest(protectedManifests)
	writePluginFile(t, filepath.Join(f.w.cfg.DataDir, hermesStoreFileName),
		`{"answers":{"sibling":{"entrypoints":"x","seen":"y"},"`+digest+`":{"entrypoints":["`+cachedProtected+`"],"seen":123}}}`)
	f.w.hermesManifests = failingManifestLoader
	writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedGenerated)), "two")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 0 {
		t.Fatalf("an ordinary cache write during the outage caused %d scans", got)
	}
	writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedProtected)), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got == 0 {
		t.Fatal("the declared cache file written during the outage was not scanned")
	}
}

// An answer given again is the most recent, so the bound drops the manifests
// unseen for longest, and an active manifest keeps its answer.
func TestHermesManifestStoreKeepsAnswersGivenAgain(t *testing.T) {
	data := t.TempDir()
	open := func() bool { return true }
	live := newHermesManifestPolicy(data, nil).byPolicy(healthyManifestLoader, open)
	if _, err := live(protectedManifests); err != nil {
		t.Fatal(err)
	}
	for i := range hermesStoreMaxEntries - 1 {
		if _, err := live(map[string][]byte{"plugin.yaml": []byte(fmt.Sprintf("name: distinct-%d\n", i))}); err != nil {
			t.Fatal(err)
		}
	}
	// protectedManifests is now the oldest; it is given again, then one more
	// manifest is added past the bound.
	if _, err := live(protectedManifests); err != nil {
		t.Fatal(err)
	}
	if _, err := live(map[string][]byte{"plugin.yaml": []byte("name: last\n")}); err != nil {
		t.Fatal(err)
	}
	got, err := newHermesManifestPolicy(data, nil).byPolicy(failingManifestLoader, open)(protectedManifests)
	if err != nil || !slices.Equal(got, []string{cachedProtected}) {
		t.Errorf("the manifest given again lost its answer: %q, %v", got, err)
	}
}
