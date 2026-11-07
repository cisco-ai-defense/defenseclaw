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

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var (
	hermesPythonOnce sync.Once
	hermesPythonPath string
	hermesPythonErr  error
	hermesAnswers    sync.Map
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
		key := hermesManifestKey(manifests)
		if cached, ok := hermesAnswers.Load(key); ok {
			answer := cached.(hermesManifestAnswer)
			return answer.entrypoints, answer.err
		}
		entrypoints, err := runHermesManifestCommand(manifests)
		hermesAnswers.Store(key, hermesManifestAnswer{entrypoints: entrypoints, err: err})
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

// The scanner is started once for the same manifest bytes, and again when they
// change.
func TestHermesManifestLoaderAsksTheScannerOncePerManifest(t *testing.T) {
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
	load := newHermesManifestLoader(&scanner.PluginScanner{BinaryPath: script})
	runs := func() int {
		data, _ := os.ReadFile(count)
		return strings.Count(string(data), "x")
	}
	first := map[string][]byte{"plugin.yaml": []byte("name: p\n")}
	for range 3 {
		got, err := load(first)
		if err != nil || !slices.Equal(got, []string{"lib/run.js"}) {
			t.Fatalf("answer = %q, %v", got, err)
		}
	}
	if got := runs(); got != 1 {
		t.Fatalf("scanner started %d times for one manifest", got)
	}
	if _, err := load(map[string][]byte{"plugin.yaml": []byte("name: q\n")}); err != nil || runs() != 2 {
		t.Fatalf("changed manifest: err %v, %d runs", err, runs())
	}
}
