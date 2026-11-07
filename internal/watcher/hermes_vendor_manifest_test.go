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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// hermesTestAnswer is one answer of the real scanner, kept for a test run.
type hermesTestAnswer struct {
	entrypoints []string
	err         error
}

var (
	hermesPythonOnce sync.Once
	hermesPythonPath string
	hermesPythonErr  error
	hermesAnswers    sync.Map // manifest digest -> hermesTestAnswer
	// hermesTestPath is the PATH at process start: the plugin fixtures empty
	// PATH for their own test.
	hermesTestPath = os.Getenv("PATH")
)

// hermesManifestKey is the digest of the names and bytes of manifests.
func hermesManifestKey(manifests map[string][]byte) string {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		fmt.Fprintf(digest, "%s\x00%d\x00", name, len(manifests[name]))
		_, _ = digest.Write(manifests[name])
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// hermesLookPython finds python3 on the PATH the process started with.
func hermesLookPython() (string, error) {
	for _, dir := range filepath.SplitList(hermesTestPath) {
		candidate := filepath.Join(dir, "python3")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("python3 not found")
}

// hermesScannerLoader returns the loader the watcher uses in production,
// answered by the real command of the Python CLI (defenseclaw plugin
// manifest-entrypoints), one python3 run per distinct set of manifests. The
// test skips where Python or the CLI is absent.
func hermesScannerLoader(t *testing.T) hermesManifestLoader {
	t.Helper()
	hermesPythonOnce.Do(func() {
		hermesPythonPath, hermesPythonErr = hermesLookPython()
		if hermesPythonErr == nil {
			_, hermesPythonErr = runHermesManifestCommand(map[string][]byte{"plugin.yaml": []byte("name: p\n")})
		}
	})
	if hermesPythonErr != nil {
		t.Skipf("the plugin scanner CLI is not available: %v", hermesPythonErr)
	}
	return func(manifests map[string][]byte) ([]string, error) {
		key := hermesManifestKey(manifests)
		if cached, ok := hermesAnswers.Load(key); ok {
			answer := cached.(hermesTestAnswer)
			return answer.entrypoints, answer.err
		}
		entrypoints, err := runHermesManifestCommand(manifests)
		hermesAnswers.Store(key, hermesTestAnswer{entrypoints: entrypoints, err: err})
		return entrypoints, err
	}
}

func runHermesManifestCommand(manifests map[string][]byte) ([]string, error) {
	cli, err := filepath.Abs(filepath.Join("..", "..", "cli"))
	if err != nil {
		return nil, err
	}
	encoded := map[string]string{}
	for name, data := range manifests {
		encoded[name] = base64.StdEncoding.EncodeToString(data)
	}
	request, err := json.Marshal(map[string]any{"manifests": encoded})
	if err != nil {
		return nil, err
	}
	const script = `import sys
sys.path.insert(0, sys.argv[1])
from defenseclaw.commands.cmd_plugin import plugin
plugin.main(["manifest-entrypoints"], standalone_mode=False)`
	cmd := exec.Command(hermesPythonPath, "-I", "-c", script, cli)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(request)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(strings.TrimSpace(err.Error() + ": " + stderr.String()))
	}
	var reply struct {
		Entrypoints []string `json:"entrypoints"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return nil, err
	}
	return reply.Entrypoints, nil
}

// GAP-0645 review 18: manifests the plugin scanner accepts and the Go side
// once could not read (a YAML 1.2 directive, a binary key with data after its
// padding, a mapping that merges itself) are decided by the scanner loader
// itself. Benign: with a declared entrypoint that is an ordinary file, cache
// rewrites cause no scan, no admission and nothing is hashed. Protected: the
// same spelling declaring a cache entrypoint still binds that file, and an
// edit of it is seen.
func TestHermesScannerAcceptedManifestsKeepCacheOutOfScansAndBindDeclared(t *testing.T) {
	spellings := map[string]string{
		"yaml-1.2-directive":      "%YAML 1.2\n---\nname: p\nENTRY",
		"yaml-1.2-binary-padding": "%YAML 1.2\n---\nname: p\nx: !!binary YQ==abc\nENTRY",
		"recursive-merge":         "name: p\nr: &r\n  <<: *r\n  a: 1\nENTRY",
		"binary-padding":          "name: p\nx: !!binary YQ==abc\nENTRY",
		"plain":                   "name: p\nENTRY",
	}
	for name, template := range spellings {
		t.Run(name, func(t *testing.T) {
			benign := strings.Replace(template, "ENTRY", "main: lib/run.js\n", 1)
			protected := strings.Replace(template, "ENTRY", "main: __pycache__/provider.cpython-312.pyc\n", 1)

			f := newHermesPluginFixture(t)
			path := f.plugin(f.bundledRoot, "web/ddgs")
			writePluginFile(t, filepath.Join(path, "plugin.yaml"), benign)
			writePluginFile(t, filepath.Join(path, "lib", "run.js"), "safe()\n")
			f.pinVendor("web/ddgs", path)
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			admitted := len(f.admitted[path])
			cache := filepath.Join(path, "__pycache__", "provider.cpython-312.pyc")
			for _, body := range []string{"generated one", "generated two"} {
				writePluginFile(t, cache, body)
				f.w.runRescanCycle(context.Background())
			}
			if got := f.scan.scans(path); got != 0 {
				t.Errorf("ordinary cache writes caused %d scans", got)
			}
			if got := len(f.admitted[path]); got != admitted {
				t.Errorf("ordinary cache writes caused %d admissions", got-admitted)
			}
			if extra := skippedTreeHash(path, hermesScannerLoader(t)); extra != "" {
				t.Errorf("ordinary cache write was hashed: %q", extra)
			}

			bound := t.TempDir()
			writePluginFile(t, filepath.Join(bound, "plugin.yaml"), protected)
			entry := filepath.Join(bound, "__pycache__", "provider.cpython-312.pyc")
			writePluginFile(t, entry, "safe()\n")
			first := skippedTreeHash(bound, hermesScannerLoader(t))
			if first == "" {
				t.Fatal("declared cache entrypoint was not hashed")
			}
			writePluginFile(t, entry, "exec()\n")
			if skippedTreeHash(bound, hermesScannerLoader(t)) == first {
				t.Fatal("edit of a declared cache entrypoint was not seen")
			}
		})
	}
}

// When the scanner cannot answer, every cache file counts as declared: more is
// hashed, never less, and an edit of a cache entrypoint is still seen.
func TestHermesManifestLoaderFailureBindsEveryCacheFile(t *testing.T) {
	failing := func(map[string][]byte) ([]string, error) { return nil, errors.New("scanner unavailable") }
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nmain: lib/run.js\n")
	cache := filepath.Join(dir, "__pycache__", "a.cpython-312.pyc")
	writePluginFile(t, cache, "one")
	first := skippedTreeHash(dir, failing)
	if first == "" {
		t.Fatal("cache file not hashed while the scanner cannot answer")
	}
	writePluginFile(t, cache, "two")
	if skippedTreeHash(dir, failing) == first {
		t.Fatal("cache edit not seen while the scanner cannot answer")
	}
	// No manifest, no question: the scanner is never asked.
	bare := t.TempDir()
	writePluginFile(t, filepath.Join(bare, "__pycache__", "a.cpython-312.pyc"), "one")
	if got := skippedTreeHash(bare, func(map[string][]byte) ([]string, error) {
		t.Error("the scanner was asked about a plugin without a manifest")
		return nil, nil
	}); got != "" {
		t.Fatalf("cache file hashed without a manifest: %q", got)
	}
}

// Nothing is remembered, neither an answer nor a failure (what the scanner
// declares, and whether it can run, change while its launcher and the manifest
// stay the same), so each request starts the scanner.
func TestHermesManifestLoaderAsksTheScannerEveryTime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	script := filepath.Join(dir, "defenseclaw")
	body := fmt.Sprintf("#!/bin/sh\necho x >> %q\ncat >/dev/null\nprintf %s\n", count, "{\\\"entrypoints\\\":[\\\"lib/run.js\\\"]}")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	load := hermesManifestsFrom(&scanner.PluginScanner{BinaryPath: script})
	runs := func() int {
		data, _ := os.ReadFile(count)
		return strings.Count(string(data), "x")
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	for range 3 {
		got, err := load(manifests)
		if err != nil || !slices.Equal(got, []string{"lib/run.js"}) {
			t.Fatalf("answer = %q, %v", got, err)
		}
	}
	if got := runs(); got != 3 {
		t.Fatalf("scanner started %d times for three requests", got)
	}

	failCount := filepath.Join(dir, "failures")
	failScript := filepath.Join(dir, "failing", "defenseclaw")
	if err := os.MkdirAll(filepath.Dir(failScript), 0o755); err != nil {
		t.Fatal(err)
	}
	failBody := fmt.Sprintf("#!/bin/sh\necho x >> %q\ncat >/dev/null\nexit 1\n", failCount)
	if err := os.WriteFile(failScript, []byte(failBody), 0o755); err != nil {
		t.Fatal(err)
	}
	failing := hermesManifestsFrom(&scanner.PluginScanner{BinaryPath: failScript})
	for range 3 {
		if _, err := failing(manifests); err == nil {
			t.Fatal("a failing scanner gave an answer")
		}
	}
	data, _ := os.ReadFile(failCount)
	if got := strings.Count(string(data), "x"); got != 3 {
		t.Errorf("a failing scanner was started %d times for three requests, want 3", got)
	}
}

// hermesReplyScript writes a launcher named defenseclaw that prints reply
// (or fails when reply is empty) and returns its path.
func hermesReplyScript(t *testing.T, reply string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "defenseclaw")
	body := "#!/bin/sh\ncat >/dev/null\nexit 1\n"
	if reply != "" {
		body = fmt.Sprintf("#!/bin/sh\ncat >/dev/null\nprintf %%s %q\n", reply)
	}
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// GAP-0645 review 19: a reply that carries no entrypoints list is not the
// answer "declares nothing". Only an explicit empty list is.
func TestHermesManifestReplyWithoutEntrypointsListIsNotAnAnswer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	for _, reply := range []string{"{}", `{"entrypoints":null}`, "null", "[]", `{"entry":["a"]}`, "", "not json"} {
		reply := reply
		t.Run(reply, func(t *testing.T) {
			ps := &scanner.PluginScanner{BinaryPath: hermesReplyScript(t, reply)}
			if got, err := ps.DeclaredEntrypoints(context.Background(), manifests); err == nil {
				t.Fatalf("reply %q accepted as %q", reply, got)
			}
		})
	}
	ps := &scanner.PluginScanner{BinaryPath: hermesReplyScript(t, `{"entrypoints":[]}`)}
	if got, err := ps.DeclaredEntrypoints(context.Background(), manifests); err != nil || len(got) != 0 {
		t.Fatalf("an explicit empty list = %q, %v", got, err)
	}
}

// The incomplete reply binds a cache file a manifest names directly, in the
// full tree hash, whatever the policy: strict binds every cache file, the
// per-user default binds the named one.
func TestHermesManifestIncompleteReplyStillBindsNamedCacheFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nmain: __pycache__/entry.cpython-312.pyc\n")
	named := filepath.Join(dir, "__pycache__", "entry.cpython-312.pyc")
	other := filepath.Join(dir, "__pycache__", "other.cpython-312.pyc")
	writePluginFile(t, named, "one")
	writePluginFile(t, other, "one")
	for _, open := range []bool{true, false} {
		ps := &scanner.PluginScanner{BinaryPath: hermesReplyScript(t, "{}")}
		cache := newHermesManifestPolicy()
		load := cache.byPolicy(hermesManifestsFrom(ps), func() bool { return open })
		first := skippedTreeHash(dir, load)
		writePluginFile(t, named, "two")
		if skippedTreeHash(dir, load) == first {
			t.Errorf("open=%v: an edit of the named cache file was not seen", open)
		}
		writePluginFile(t, named, "one")
	}
}

// GAP-0645 review 19: while the scanner cannot answer, the per-user default
// and permissive tiers warn and leave an ordinary generated cache file alone,
// and a strict or managed policy counts every cache file as declared.
func TestHermesManifestFailureFollowsThePolicyTier(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nmain: lib/run.js\n")
	writePluginFile(t, filepath.Join(dir, "package.json"), `{"main": "__pycache__/named.cpython-312.pyc"}`)
	named := filepath.Join(dir, "__pycache__", "named.cpython-312.pyc")
	ordinary := filepath.Join(dir, "__pycache__", "generated.cpython-312.pyc")
	writePluginFile(t, named, "one")
	writePluginFile(t, ordinary, "one")
	failing := func(map[string][]byte) ([]string, error) {
		return nil, fmt.Errorf("%w: scanner unavailable", errHermesManifestFailOpen)
	}
	base := skippedTreeHash(dir, failing)
	if base == "" {
		t.Fatal("the cache file a manifest names was not hashed while the scanner cannot answer")
	}
	writePluginFile(t, ordinary, "two")
	if skippedTreeHash(dir, failing) != base {
		t.Error("an ordinary cache write changed the hash under a fail-open policy")
	}
	writePluginFile(t, named, "two")
	if skippedTreeHash(dir, failing) == base {
		t.Error("an edit of a named cache file was not seen under a fail-open policy")
	}
}

// The watcher chooses the fallback from the policy of the current
// configuration, and follows a reload of the scanner it points at.
func TestHermesManifestLoaderFollowsPolicyAndConfigurationReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	older := hermesReplyScript(t, `{"entrypoints":[]}`)
	newer := hermesReplyScript(t, `{"entrypoints":["__pycache__/x.pyc"]}`)
	broken := hermesReplyScript(t, "")

	cfg := &config.Config{}
	cfg.Scanners.PluginScanner = older
	w := &InstallWatcher{cfg: cfg}
	if got, err := w.manifestLoader()(manifests); err != nil || len(got) != 0 {
		t.Fatalf("older scanner = %q, %v", got, err)
	}
	cfg.Scanners.PluginScanner = newer
	if got, err := w.manifestLoader()(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/x.pyc"}) {
		t.Fatalf("after a reload the watcher still reads the older answer: %q, %v", got, err)
	}

	cfg.Scanners.PluginScanner = broken
	if _, err := w.manifestLoader()(manifests); !errors.Is(err, errHermesManifestFailOpen) {
		t.Fatalf("per-user default: error %v is not the fail-open fallback", err)
	}
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	if _, err := w.manifestLoader()(manifests); err == nil || errors.Is(err, errHermesManifestFailOpen) {
		t.Fatalf("managed: error %v must stay closed", err)
	}
}

// GAP-0645 review 19, through the watcher: while the manifest reader fails, an
// ordinary generated cache write of a shipped plugin is not a scan or an
// admission under the per-user default, and is scanned under a managed policy.
func TestHermesManifestFailureInWatcherFollowsThePolicyTier(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		wantScans int
	}{
		{"per-user default", "", 0},
		{"managed", managed.DeploymentModeManagedEnterprise, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.plugin(f.bundledRoot, "web/ddgs")
			writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\nmain: lib/run.js\n")
			writePluginFile(t, filepath.Join(path, "lib", "run.js"), "safe()\n")
			f.pinVendor("web/ddgs", path)
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			admitted := len(f.admitted[path])
			f.w.cfg.DeploymentMode = tc.mode
			f.w.hermesManifests = func(map[string][]byte) ([]string, error) { return nil, errors.New("manifest command unavailable") }
			writePluginFile(t, filepath.Join(path, "__pycache__", "run.pyc"), "generated cache")
			f.w.runRescanCycle(context.Background())
			if got := f.scan.scans(path); got != tc.wantScans {
				t.Errorf("ordinary cache rewrite caused %d scans, want %d", got, tc.wantScans)
			}
			if got := len(f.admitted[path]); tc.wantScans == 0 && got != admitted {
				t.Errorf("an ordinary cache rewrite caused %d admissions", got-admitted)
			}
		})
	}
}

// failingManifestLoader is a manifest reader that cannot answer.
func failingManifestLoader(map[string][]byte) ([]string, error) {
	return nil, errors.New("manifest command unavailable")
}

// GAP-0645 review 20: while the reader cannot answer under the per-user
// default, a cache file that any string of a manifest resolves to stays
// bound however the manifest spells it, and a cache file that only shares a
// base name with a string is not bound. Each manifest below declares the
// entrypoint __pycache__/run.pyc (the scanner agrees, see the differential
// test) except the two that do not.
func TestHermesManifestOutageBindsNamedCacheFileWhateverTheSpelling(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, text string
		declares             bool
	}{
		{"json unicode escape", "package.json", `{"name":"p","main":"__pycache__/r\u0075n.pyc"}`, true},
		{"json escaped slash", "package.json", `{"main":"__pycache__\/run.pyc"}`, true},
		{"json surrogate pair beside it", "package.json", `{"x":"\ud83d\ude00","main":"__pycache__/run.pyc"}`, true},
		{"yaml hex escape", "plugin.yaml", "name: p\nmain: \"__pycache__/r\\x75n.pyc\"\n", true},
		{"yaml long escape", "plugin.yaml", "name: p\nmain: \"__pycache__/\\U00000072un.pyc\"\n", true},
		{"yaml alias of an escaped value", "plugin.yaml", "name: p\nnote: &entry \"__pycache__/r\\x75n.pyc\"\nmain: *entry\n", true},
		{"yaml line continuation", "plugin.yaml", "main: \"__pycache__/ru\\\n      n.pyc\"\n", true},
		{"yaml single quoted", "plugin.yaml", "main: '__pycache__/run.pyc'\n", true},
		{"plural key, plain list item (the scanner reads no file from it)", "plugin.yaml", "entrypoints:\n  - __pycache__/run.pyc\n", false},
		{"plural key, flow list (the scanner reads no file from it)", "plugin.yaml", "entrypoints: [lib/a.js, __pycache__/run.pyc]\n", false},
		{"bin as a list (the scanner reads no file from it)", "plugin.yaml", "bin: [__pycache__/run.pyc]\n", false},
		{"yaml anchored plain value", "plugin.yaml", "main: &m __pycache__/run.pyc\n", true},
		{"dot segments and a leading slash", "plugin.json", `{"main":"/./lib/../__pycache__/run.pyc"}`, true},
		{"prose that only holds the base name", "plugin.yaml", "name: p\nmain: lib/a.js\ndescription: run.pyc\n", false},
		{"the same base name in another folder", "plugin.yaml", "name: p\nmain: lib/run.pyc\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writePluginFile(t, filepath.Join(dir, tc.manifest), tc.text)
			writePluginFile(t, filepath.Join(dir, "lib", "a.js"), "safe()\n")
			writePluginFile(t, filepath.Join(dir, "lib", "run.pyc"), "safe()\n")
			cache := filepath.Join(dir, "__pycache__", "run.pyc")
			writePluginFile(t, cache, "one")
			load := func(map[string][]byte) ([]string, error) {
				return nil, fmt.Errorf("%w: reader unavailable", errHermesManifestFailOpen)
			}
			first := skippedTreeHash(dir, load)
			writePluginFile(t, cache, "two")
			second := skippedTreeHash(dir, load)
			if tc.declares && (first == "" || first == second) {
				t.Errorf("the declared cache file is not bound during the outage (hash %q then %q)", first, second)
			}
			if !tc.declares && (first != "" || second != "") {
				t.Errorf("an ordinary cache file is bound during the outage (hash %q then %q)", first, second)
			}
		})
	}
}

// Through the watcher, with the default policy: the escaped and aliased
// spellings of a protected cache entrypoint are scanned when the file is
// added during an outage, and a cache write that only shares a base name with
// a manifest string is neither a scan nor an admission.
func TestHermesManifestOutageInWatcherScansDeclaredAndLeavesOrdinaryCache(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, text string
		wantScans            int
	}{
		{"json unicode escape", "package.json", `{"name":"p","main":"__pycache__/r\u0075n.pyc"}`, 1},
		{"yaml hex escape", "plugin.yaml", "name: p\nmain: \"__pycache__/r\\x75n.pyc\"\n", 1},
		{"yaml alias of an escaped value", "plugin.yaml", "name: p\nnote: &entry \"__pycache__/r\\x75n.pyc\"\nmain: *entry\n", 1},
		{"prose mention", "plugin.yaml", "name: p\nmain: lib/a.js\ndescription: run.pyc\n", 0},
		{"same base name in another folder", "plugin.yaml", "name: p\nmain: lib/run.pyc\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.plugin(f.bundledRoot, "web/ddgs")
			writePluginFile(t, filepath.Join(path, tc.manifest), tc.text)
			writePluginFile(t, filepath.Join(path, "lib", "a.js"), "safe()\n")
			writePluginFile(t, filepath.Join(path, "lib", "run.pyc"), "safe()\n")
			f.pinVendor("web/ddgs", path)
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			admitted := len(f.admitted[path])
			f.w.hermesManifests = failingManifestLoader
			writePluginFile(t, filepath.Join(path, "__pycache__", "run.pyc"), "exec()\n")
			f.w.runRescanCycle(context.Background())
			if got := f.scan.scans(path); got != tc.wantScans {
				t.Errorf("cache file added during the outage caused %d scans, want %d", got, tc.wantScans)
			}
			if got := len(f.admitted[path]); tc.wantScans == 0 && got != admitted {
				t.Errorf("an ordinary cache write caused %d admissions", got-admitted)
			}
		})
	}
}

// The candidates are a superset of what the plugin scanner reads: for each
// manifest the real scanner reports an entrypoint, the same string is among
// the candidates. The test skips where the scanner CLI is absent.
func TestHermesManifestCandidatesHoldEveryEntrypointTheScannerReads(t *testing.T) {
	load := hermesScannerLoader(t)
	for _, tc := range []struct{ name, manifest, text string }{
		{"json escape", "package.json", `{"name":"p","main":"__pycache__/r\u0075n.pyc"}`},
		{"yaml escape", "plugin.yaml", "name: p\nmain: \"__pycache__/r\\x75n.pyc\"\n"},
		{"yaml alias", "plugin.yaml", "name: p\nnote: &entry \"__pycache__/r\\x75n.pyc\"\nmain: *entry\n"},
		{"yaml bin map", "plugin.yaml", "name: p\nbin:\n  a: lib/a.js\n  b: __pycache__/run.pyc\n"},
		{"yaml flow bin map", "plugin.yaml", "name: p\nbin: {a: lib/a.js, b: '__pycache__/run.pyc'}\n"},
		{"yaml entrypoint", "plugin.yaml", "name: p\nentrypoint: \"./__pycache__/\\x72un.pyc\"\n"},
		{"json bin map", "plugin.json", `{"bin":{"a":"lib/a.js","b":"./__pycache__/run.pyc"}}`},
		{"json entry", "manifest.json", `{"entry":"__pycache__\/run.pyc"}`},
		{"openclaw", "openclaw.plugin.json", `{"id":"p","main":"dist/\u0069ndex.js"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifests := map[string][]byte{tc.manifest: []byte(tc.text)}
			got, err := load(manifests)
			if err != nil || len(got) == 0 {
				t.Fatalf("scanner entrypoints = %q, %v", got, err)
			}
			candidates, _ := hermesManifestCandidates(manifests)
			for _, entrypoint := range got {
				if !slices.Contains(candidates, entrypoint) {
					t.Errorf("scanner entrypoint %q is not among the candidates %q", entrypoint, candidates)
				}
			}
		})
	}
}

// GAP-0645 review 20: the answer follows the scanner executable. Replacing
// the file at the configured path, in place with another size or by another
// file of the same size and time, asks the new scanner again.
func TestHermesManifestAnswerFollowsExecutableReplacementAtOnePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\nmain: __pycache__/run.pyc\n")}
	script := filepath.Join(t.TempDir(), "defenseclaw")
	install := func(answer string, replaceFile bool) {
		t.Helper()
		body := []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.0.9\\n'; exit 0; fi\ncat >/dev/null\nprintf '%s' '" + answer + "'\n")
		target := script
		if replaceFile {
			target = script + ".new"
		}
		if err := os.WriteFile(target, body, 0o755); err != nil {
			t.Fatal(err)
		}
		if replaceFile {
			old, err := os.Stat(script)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(target, old.ModTime(), old.ModTime()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(target, script); err != nil {
				t.Fatal(err)
			}
		}
	}
	cfg := &config.Config{}
	cfg.Scanners.PluginScanner = script
	w := &InstallWatcher{cfg: cfg}
	install(`{"entrypoints":[]}`, false)
	if got, err := w.manifestLoader()(manifests); err != nil || len(got) != 0 {
		t.Fatalf("first scanner = %q, %v", got, err)
	}
	install(`{"entrypoints":["__pycache__/run.pyc"]}`, false)
	if got, err := w.manifestLoader()(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/run.pyc"}) {
		t.Errorf("after an in-place replacement the watcher answers %q, %v", got, err)
	}
	// Another file of the same size and time: the answer text keeps its length.
	install(`{"entrypoints":["__pycache__/run.pyd"]}`, true)
	if got, err := w.manifestLoader()(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/run.pyd"}) {
		t.Errorf("after a replacement by another file the watcher answers %q, %v", got, err)
	}
}

// The scanner answer the watcher uses is the one for the executable now at
// the path, so a protected cache entrypoint declared by a replaced scanner is
// scanned when it appears.
func TestHermesManifestScannerReplacementReachesTheRescan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\nmain: __pycache__/run.pyc\n")
	f.pinVendor("web/ddgs", path)
	script := filepath.Join(t.TempDir(), "defenseclaw")
	install := func(answer string) {
		t.Helper()
		body := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.0.9\\n'; exit 0; fi\ncat >/dev/null\nprintf '%s' '" + answer + "'\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	install(`{"entrypoints":[]}`)
	f.w.hermesManifests = nil
	f.cfg.Scanners.PluginScanner = script
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	install(`{"entrypoints":["__pycache__/run.pyc"]}`)
	writePluginFile(t, filepath.Join(path, "__pycache__", "run.pyc"), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 1 {
		t.Errorf("a cache entrypoint declared by the replaced scanner caused %d scans, want 1", got)
	}
}

// GAP-0645 review 20: a strict tier and a managed install take the closed
// fallback on a manifest reader failure, whatever hook outage mode was saved.
func TestHermesManifestFailureStaysClosedForStrictAndManagedWhateverModeWasSaved(t *testing.T) {
	manifests := map[string][]byte{"plugin.yaml": []byte("main: __pycache__/run.pyc\n")}
	for _, tc := range []struct {
		name, mode, tier, saved string
		open                    bool
	}{
		{"strict, saved open", "", "strict", "open", false},
		{"managed, saved open", managed.DeploymentModeManagedEnterprise, "", "open", false},
		{"strict, nothing saved", "", "strict", "", false},
		{"default, saved closed", "", "", "closed", false},
		{"default, saved open", "", "", "open", true},
		{"default, nothing saved", "", "", "", true},
		{"permissive, nothing saved", "", "permissive", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{DeploymentMode: tc.mode}
			cfg.Guardrail.RulePack = tc.tier
			cfg.Guardrail.HookFailMode = tc.saved
			w := &InstallWatcher{cfg: cfg, hermesManifests: failingManifestLoader}
			_, err := w.manifestLoader()(manifests)
			if err == nil {
				t.Fatal("a failing reader gave an answer")
			}
			if got := errors.Is(err, errHermesManifestFailOpen); got != tc.open {
				t.Errorf("fail-open marker = %v, want %v", got, tc.open)
			}
		})
	}
}

// GAP-0645 review 20: a null element is a malformed list, not an empty
// entrypoint; with the strict fallback the declared cache file is bound.
func TestHermesManifestNullListElementIsNotAnAnswer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	ps := &scanner.PluginScanner{BinaryPath: hermesReplyScript(t, `{"entrypoints":[null]}`)}
	manifests := map[string][]byte{"plugin.yaml": []byte("main: __pycache__/run.pyc\n")}
	if got, err := ps.DeclaredEntrypoints(context.Background(), manifests); err == nil {
		t.Fatalf("a null list element was accepted as %q", got)
	}
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "main: __pycache__/run.pyc\n")
	writePluginFile(t, filepath.Join(dir, "__pycache__", "run.pyc"), "exec()\n")
	cache := newHermesManifestPolicy()
	load := cache.byPolicy(hermesManifestsFrom(ps), func() bool { return false })
	if skippedTreeHash(dir, load) == "" {
		t.Error("the closed fallback left a declared cache file unhashed after an invalid reply")
	}
}

// While the reader cannot answer, the candidates hold the whole name a
// manifest declares, whatever punctuation the name holds and however the
// value is written. Each row declares the entrypoint in the last column.
func TestHermesManifestOutageCandidatesKeepPunctuationOfDeclaredNames(t *testing.T) {
	for _, tc := range []struct{ name, manifest, text, entry string }{
		{"yaml double quoted brackets", "plugin.yaml", "name: p\nmain: \"__pycache__/run[1].pyc\"\n", "__pycache__/run[1].pyc"},
		{"yaml single quoted comma", "plugin.yaml", "name: p\nmain: '__pycache__/run,1.pyc'\n", "__pycache__/run,1.pyc"},
		{"yaml single quoted doubled quote", "plugin.yaml", "main: '__pycache__/it''s.pyc'\n", "__pycache__/it's.pyc"},
		{"yaml plain comma", "plugin.yaml", "main: __pycache__/run,1.pyc\n", "__pycache__/run,1.pyc"},
		{"yaml flow bin map quoted comma", "plugin.yaml", "bin: {a: lib/a.js, b: \"__pycache__/run,1.pyc\"}\n", "__pycache__/run,1.pyc"},
		{"yaml bin map braces", "plugin.yaml", "bin: {a: lib/a.js, b: '__pycache__/run{1}.pyc'}\n", "__pycache__/run{1}.pyc"},
		{"yaml bin block map comma", "plugin.yaml", "bin:\n  a: lib/a.js\n  b: \"__pycache__/r,un.pyc\"\n", "__pycache__/r,un.pyc"},
		{"yaml quoted key", "plugin.yaml", "\"main\": \"__pycache__/run[1].pyc\"\n", "__pycache__/run[1].pyc"},
		{"yaml escaped key", "plugin.yaml", "\"m\\u0061in\": \"__pycache__/run[1].pyc\"\n", "__pycache__/run[1].pyc"},
		{"yaml explicit key", "plugin.yaml", "? main\n: \"__pycache__/run[1].pyc\"\n", "__pycache__/run[1].pyc"},
		{"yaml alias of a punctuated value", "plugin.yaml", "note: &entry '__pycache__/run,1.pyc'\nmain: *entry\n", "__pycache__/run,1.pyc"},
		{"yaml merge key", "plugin.yaml", "base: &base\n  main: \"__pycache__/run[1].pyc\"\n<<: *base\n", "__pycache__/run[1].pyc"},
		{"yaml value on the next line", "plugin.yaml", "main:\n  \"__pycache__/run[1].pyc\"\n", "__pycache__/run[1].pyc"},
		{"json braces", "package.json", `{"name":"p","main":"__pycache__/run{1}.pyc"}`, "__pycache__/run{1}.pyc"},
		{"json bin map brackets", "package.json", `{"bin":{"a":"lib/a.js","b":"__pycache__/run[1].pyc"}}`, "__pycache__/run[1].pyc"},
		{"json value on the next line", "package.json", "{\n\"main\":\n\"__pycache__/run,1.pyc\"}", "__pycache__/run,1.pyc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidates, _ := hermesManifestCandidates(map[string][]byte{tc.manifest: []byte(tc.text)})
			if !slices.Contains(candidates, tc.entry) {
				t.Errorf("candidates omit the declared entrypoint %q: %q", tc.entry, candidates)
			}
		})
	}
}

// Prose is not an entrypoint: a cache path named under any key the scanner
// does not read as code (a description, a title, a keyword list, a block
// scalar) binds nothing during an outage, so the ordinary cache write that
// matches it is neither bound by the tree hash nor scanned nor admitted. The
// declared entrypoint of the same manifest stays bound.
func TestHermesManifestOutageProseNamingCachePathBindsNothing(t *testing.T) {
	for _, tc := range []struct{ name, manifest, text string }{
		{"description", "plugin.yaml", "name: p\nmain: lib/run.js\ndescription: __pycache__/generated.pyc\n"},
		{"quoted description", "plugin.yaml", "name: p\nmain: lib/run.js\ndescription: \"writes __pycache__/generated.pyc, sometimes\"\n"},
		{"title and keywords", "plugin.yaml", "main: lib/run.js\ntitle: __pycache__/generated.pyc\nkeywords: [a, __pycache__/generated.pyc]\n"},
		{"block scalar description", "plugin.yaml", "main: lib/run.js\ndescription: |\n  see\n  __pycache__/generated.pyc\nversion: 1\n"},
		{"json description", "package.json", `{"main":"lib/run.js","description":"__pycache__/generated.pyc","keywords":["__pycache__/generated.pyc"]}`},
		{"comment", "plugin.yaml", "main: lib/run.js # __pycache__/generated.pyc\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if candidates, _ := hermesManifestCandidates(map[string][]byte{tc.manifest: []byte(tc.text)}); slices.Contains(candidates, "__pycache__/generated.pyc") {
				t.Errorf("prose is among the candidates: %q", candidates)
			}
			dir := t.TempDir()
			writePluginFile(t, filepath.Join(dir, tc.manifest), tc.text)
			writePluginFile(t, filepath.Join(dir, "lib", "run.js"), "safe()\n")
			cache := filepath.Join(dir, "__pycache__", "generated.pyc")
			writePluginFile(t, cache, "one")
			load := func(map[string][]byte) ([]string, error) {
				return nil, fmt.Errorf("%w: reader unavailable", errHermesManifestFailOpen)
			}
			first := skippedTreeHash(dir, load)
			writePluginFile(t, cache, "two")
			if second := skippedTreeHash(dir, load); first != "" || second != "" {
				t.Errorf("an ordinary cache file is bound by prose (hash %q then %q)", first, second)
			}

			f := newHermesPluginFixture(t)
			path := f.plugin(f.bundledRoot, "web/ddgs")
			writePluginFile(t, filepath.Join(path, tc.manifest), tc.text)
			writePluginFile(t, filepath.Join(path, "lib", "run.js"), "safe()\n")
			f.pinVendor("web/ddgs", path)
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			admitted := len(f.admitted[path])
			f.w.hermesManifests = failingManifestLoader
			writePluginFile(t, filepath.Join(path, "__pycache__", "generated.pyc"), "ordinary cache")
			f.w.runRescanCycle(context.Background())
			if got := f.scan.scans(path); got != 0 {
				t.Errorf("a cache write named only in prose caused %d scans", got)
			}
			if got := len(f.admitted[path]); got != admitted {
				t.Errorf("a cache write named only in prose caused %d admissions", got-admitted)
			}
		})
	}
}

// A protected cache entrypoint whose name holds punctuation is bound through
// the watcher during an outage: a baseline made while the reader is down
// still sees the edit as a change that reaches a scan.
func TestHermesManifestOutageEditOfPunctuatedEntrypointReachesScan(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\nmain: \"__pycache__/run[1].pyc\"\n")
	entry := filepath.Join(path, "__pycache__", "run[1].pyc")
	writePluginFile(t, entry, "safe()\n")
	f.pinVendor("web/ddgs", path)
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	f.w.hermesManifests = failingManifestLoader
	findings := f.scan.findings[path]
	f.scan.findings[path] = nil
	f.w.runRescanCycle(context.Background()) // a baseline while the reader is down
	firstScans := f.scan.scans(path)
	f.scan.findings[path] = findings
	writePluginFile(t, entry, "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != firstScans+1 {
		t.Errorf("an edit of the protected entrypoint caused %d additional scans during the outage, want 1", got-firstScans)
	}
}

// An executable rewritten in place keeps its inode, size and modification
// time when the writer restores them; the answer still follows the bytes.
func TestHermesManifestAnswerFollowsRewriteThatKeepsExecutableMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	script := filepath.Join(t.TempDir(), "defenseclaw")
	body := func(entry string) []byte {
		return []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.0.9\\n'; exit 0; fi\ncat >/dev/null\nprintf '%s' '{\"entrypoints\":[\"" + entry + "\"]}'\n")
	}
	first, second := body("__pycache__/a.pyc"), body("__pycache__/b.pyc")
	if len(first) != len(second) {
		t.Fatal("test scripts differ in size")
	}
	if err := os.WriteFile(script, first, 0o700); err != nil {
		t.Fatal(err)
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	load := hermesManifestsFrom(&scanner.PluginScanner{BinaryPath: script})
	if got, err := load(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/a.pyc"}) {
		t.Fatalf("first answer = %q, %v", got, err)
	}
	// A benign twin: nothing changed, the answer is the same.
	if got, err := load(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/a.pyc"}) {
		t.Fatalf("repeated answer = %q, %v", got, err)
	}
	old, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, second, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(script, old.ModTime(), old.ModTime()); err != nil {
		t.Fatal(err)
	}
	now, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(old, now) || old.Size() != now.Size() || !old.ModTime().Equal(now.ModTime()) {
		t.Fatal("rewrite did not preserve inode, size and mtime")
	}
	if got, err := load(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/b.pyc"}) {
		t.Errorf("after a rewrite that kept the metadata the watcher answers %q, %v", got, err)
	}
}

// The same rewrite, through the watcher: the cache entrypoint that only the
// new scanner declares is scanned when it appears.
func TestHermesManifestRewriteThatKeepsExecutableMetadataReachesTheRescan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\nmain: __pycache__/b.pyc\n")
	f.pinVendor("web/ddgs", path)
	script := filepath.Join(t.TempDir(), "defenseclaw")
	body := func(entry string) []byte {
		return []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.0.9\\n'; exit 0; fi\ncat >/dev/null\nprintf '%s' '{\"entrypoints\":[\"" + entry + "\"]}'\n")
	}
	if err := os.WriteFile(script, body("__pycache__/a.pyc"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.w.hermesManifests = nil
	f.cfg.Scanners.PluginScanner = script
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	// The old scanner's answer for this manifest is the one remembered.
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\nmain: __pycache__/b.pyc\n")}
	if got, err := f.w.manifestLoader()(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/a.pyc"}) {
		t.Fatalf("old scanner answer = %q, %v", got, err)
	}
	old, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, body("__pycache__/b.pyc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(script, old.ModTime(), old.ModTime()); err != nil {
		t.Fatal(err)
	}
	writePluginFile(t, filepath.Join(path, "__pycache__", "b.pyc"), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 1 {
		t.Errorf("a cache entrypoint declared by the rewritten scanner caused %d scans, want 1", got)
	}
}

// A declared entrypoint above the size the scanner reads from a skipped
// folder is bound by content: a same-size edit of it is a change, while the
// same edit of a large cache file that no manifest declares is not.
func TestHermesLargeDeclaredEntrypointIsBoundByContent(t *testing.T) {
	big := func(first string) string { return first + strings.Repeat("x", hermesScannerReadBytes) }
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nmain: __pycache__/large.pyc\n")
	declared := filepath.Join(dir, "__pycache__", "large.pyc")
	ordinary := filepath.Join(dir, "__pycache__", "other.pyc")
	nodeModules := filepath.Join(dir, "node_modules", "dep", "index.js")
	writePluginFile(t, declared, big("A"))
	writePluginFile(t, ordinary, big("A"))
	writePluginFile(t, nodeModules, big("A"))
	load := hermesScannerLoader(t)
	before := skippedTreeHash(dir, load)
	writePluginFile(t, ordinary, big("B"))
	if after := skippedTreeHash(dir, load); after != before {
		t.Errorf("an edit of an undeclared large cache file changed the hash")
	}
	writePluginFile(t, declared, big("B"))
	if after := skippedTreeHash(dir, load); after == before {
		t.Errorf("a same-size edit of the declared large entrypoint left the hash unchanged")
	}

	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nmain: node_modules/dep/index.js\n")
	before = skippedTreeHash(dir, load)
	writePluginFile(t, nodeModules, big("B"))
	if after := skippedTreeHash(dir, load); after == before {
		t.Errorf("a same-size edit of a large declared entrypoint in node_modules left the hash unchanged")
	}
}

// Through the watcher: after a clean admission, a same-size edit of the large
// declared cache entrypoint reaches a scan.
func TestHermesLargeDeclaredEntrypointEditReachesAdmission(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\nmain: __pycache__/large.pyc\n")
	entry := filepath.Join(path, "__pycache__", "large.pyc")
	big := func(first string) string { return first + strings.Repeat("x", hermesScannerReadBytes) }
	writePluginFile(t, entry, big("A"))
	f.pinVendor("web/ddgs", path)
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	findings := f.scan.findings[path]
	f.scan.findings[path] = nil
	writePluginFile(t, filepath.Join(path, "provider.py"), "VENDOR = False\n")
	f.w.runRescanCycle(context.Background())
	firstScans := f.scan.scans(path)
	if firstScans != 1 {
		t.Fatalf("benign admission caused %d scans, want 1", firstScans)
	}
	f.scan.findings[path] = findings
	writePluginFile(t, entry, big("B"))
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != firstScans+1 {
		t.Errorf("a same-size edit of the large declared entrypoint caused %d additional scans, want 1", got-firstScans)
	}
}

// GAP-0645 review 23: a scanner that could not run is asked again. Its
// remembered failure must not hide the protected entrypoint the same launcher
// declares once it runs, whatever the manifest and settings did in between.
func TestHermesManifestRecoveredScannerDeclarationIsScanned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "defenseclaw")
	answer := filepath.Join(dir, "answer")
	body := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.0.9\\n'; exit 0; fi\ncat >/dev/null\nIFS= read -r value < \"${0%/*}/answer\"\nif [ \"$value\" = fail ]; then exit 1; fi\nprintf '{\"entrypoints\":[\"%s\"]}' \"$value\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	say := func(text string) {
		t.Helper()
		if err := os.WriteFile(answer, []byte(text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	say("fail")
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	writePluginFile(t, filepath.Join(path, "plugin.yaml"), "name: p\nmain: lib/run.js\n")
	f.pinVendor("web/ddgs", path)
	f.w.hermesManifests = nil
	f.cfg.Scanners.PluginScanner = script
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	// The outage: an ordinary cache write is neither scanned nor refused.
	writePluginFile(t, filepath.Join(path, "__pycache__", "old.pyc"), "ordinary\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 0 {
		t.Fatalf("an ordinary cache write during the outage caused %d scans", got)
	}
	// The scanner recovers and declares a cache file.
	say(cachedProtected)
	writePluginFile(t, filepath.Join(path, filepath.FromSlash(cachedProtected)), "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 1 {
		t.Errorf("the entrypoint the recovered scanner declares caused %d scans, want 1", got)
	}
}

// A manifest too deeply nested to read within the reader's bounds is neither
// refused nor read: what it declares is unknown, and the caller binds every
// cache file. A manifest nested within the bounds is decided.
func TestHermesManifestCandidatesUndecidedBeyondTheBounds(t *testing.T) {
	nested := func(depth int) string {
		return "main: " + cachedProtected + "\nx: " + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "\n"
	}
	if got, decided := hermesManifestCandidates(map[string][]byte{"plugin.yaml": []byte(nested(10))}); !decided || !slices.Equal(got, []string{cachedProtected}) {
		t.Errorf("a manifest nested ten deep = %q, decided %v", got, decided)
	}
	if got, decided := hermesManifestCandidates(map[string][]byte{"plugin.yaml": []byte(nested(hermesYAMLMaxDepth + 10))}); decided {
		t.Errorf("a manifest nested past the bound was decided as %q", got)
	}

	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), nested(hermesYAMLMaxDepth+10))
	cache := filepath.Join(dir, "__pycache__", "generated.pyc")
	writePluginFile(t, cache, "one")
	failing := func(map[string][]byte) ([]string, error) {
		return nil, fmt.Errorf("%w: scanner unavailable", errHermesManifestFailOpen)
	}
	first := skippedTreeHash(dir, failing)
	writePluginFile(t, cache, "two")
	if skippedTreeHash(dir, failing) == first {
		t.Error("an edit of a cache file was not seen beside a manifest the reader could not read")
	}
}
