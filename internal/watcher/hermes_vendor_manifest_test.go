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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
		key := hermesManifestDigest(manifests)
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
		"binary-block":            "name: p\nx: !!binary |\n  YQ==\nENTRY",
		"plain":                   "name: p\nENTRY",
	}
	// Whether the scanner loader accepts data after the padding of a binary
	// value depends on the Python it runs on (accepted up to 3.12, refused
	// from 3.13), so for these spellings the loader own answer decides what
	// the manifest declares. Every other spelling is accepted by every
	// supported Python and must bind its declared entrypoint.
	interpreterDependent := map[string]bool{"binary-padding": true, "yaml-1.2-binary-padding": true}
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
			if interpreterDependent[name] {
				declared, err := hermesScannerLoader(t)(map[string][]byte{"plugin.yaml": []byte(protected)})
				if err == nil && !slices.Contains(declared, "__pycache__/provider.cpython-312.pyc") {
					// Text the loader refuses declares nothing, as in a scan:
					// the scanner reads no cache file, so none is bound.
					if len(declared) != 0 {
						t.Fatalf("the loader declared %q, not the cache entrypoint", declared)
					}
					if first != "" {
						t.Fatalf("a manifest the loader refuses declares nothing, yet a cache file was hashed: %q", first)
					}
					return
				}
			}
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

// The loader remembers nothing, neither an answer nor a failure (what the
// scanner declares, and whether it can run, change while its launcher and the
// manifest stay the same), so each request starts the scanner. Only the outage
// policy keeps the last answer, and reads it only after a failure.
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

// A reply without an entrypoints list is not an answer. With no earlier
// answer the manifests are unknown: a strict or managed policy binds every
// cache file, and the per-user default binds none, so the cache file a
// manifest names is not rejected for the outage (the policy warned and audited
// it).
func TestHermesManifestIncompleteReplyFollowsTheOutageRule(t *testing.T) {
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
		cache := newHermesManifestPolicy("", nil)
		load := cache.byPolicy(hermesManifestsFrom(ps), func() bool { return open })
		first := skippedTreeHash(dir, load)
		writePluginFile(t, named, "two")
		second := skippedTreeHash(dir, load)
		if open && (first != "" || second != "") {
			t.Errorf("a cache file is bound while the manifests are unknown under a fail-open policy (hash %q then %q)", first, second)
		}
		if !open && first == second {
			t.Error("an edit of a cache file was not seen under a closed policy")
		}
		writePluginFile(t, named, "one")
	}
}

// GAP-0645 review 19: while the scanner has no answer for the manifests, the
// per-user default and permissive tiers leave every cache file alone (the
// policy warns and audits), and a strict or managed policy counts every cache
// file as declared.
func TestHermesManifestFailureFollowsThePolicyTier(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nmain: lib/run.js\n")
	writePluginFile(t, filepath.Join(dir, "package.json"), `{"main": "__pycache__/named.cpython-312.pyc"}`)
	named := filepath.Join(dir, "__pycache__", "named.cpython-312.pyc")
	ordinary := filepath.Join(dir, "__pycache__", "generated.cpython-312.pyc")
	writePluginFile(t, named, "one")
	writePluginFile(t, ordinary, "one")
	open := func(map[string][]byte) ([]string, error) {
		return nil, fmt.Errorf("%w: scanner unavailable", errHermesManifestFailOpen)
	}
	if got := skippedTreeHash(dir, open); got != "" {
		t.Errorf("a cache file was bound while the manifests are unknown under a fail-open policy: %q", got)
	}
	writePluginFile(t, ordinary, "two")
	writePluginFile(t, named, "two")
	if got := skippedTreeHash(dir, open); got != "" {
		t.Errorf("a cache write was bound under a fail-open policy: %q", got)
	}
	closed := func(map[string][]byte) ([]string, error) { return nil, errors.New("scanner unavailable") }
	base := skippedTreeHash(dir, closed)
	if base == "" {
		t.Fatal("no cache file was bound under a closed policy")
	}
	writePluginFile(t, ordinary, "three")
	if skippedTreeHash(dir, closed) == base {
		t.Error("a cache write was not seen under a closed policy")
	}
}

// The watcher chooses the outage rule from the policy of the current
// configuration, and follows a reload of the scanner it points at. The last
// answer for the same manifest bytes is applied in any policy; manifests with
// no earlier answer are unknown and follow the tier.
func TestHermesManifestLoaderFollowsPolicyAndConfigurationReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	manifests := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	changed := map[string][]byte{"plugin.yaml": []byte("name: q\n")}
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
	if got, err := w.manifestLoader()(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/x.pyc"}) {
		t.Fatalf("an outage did not apply the last answer for the same manifests: %q, %v", got, err)
	}
	if _, err := w.manifestLoader()(changed); !errors.Is(err, errHermesManifestFailOpen) {
		t.Fatalf("per-user default: error %v is not the fail-open outage rule", err)
	}
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	if got, err := w.manifestLoader()(manifests); err != nil || !slices.Equal(got, []string{"__pycache__/x.pyc"}) {
		t.Fatalf("managed: the last answer for the same manifests is not applied: %q, %v", got, err)
	}
	if _, err := w.manifestLoader()(changed); err == nil || errors.Is(err, errHermesManifestFailOpen) {
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
	cache := newHermesManifestPolicy("", nil)
	load := cache.byPolicy(hermesManifestsFrom(ps), func() bool { return false })
	if skippedTreeHash(dir, load) == "" {
		t.Error("the closed fallback left a declared cache file unhashed after an invalid reply")
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
