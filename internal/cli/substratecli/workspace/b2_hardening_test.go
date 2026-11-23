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

// The fixtures (hcActor) are unix-only, like the host copy tests.
//go:build unix

package workspace

import (
	"context"
	"net"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const hardeningPointer = "version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\nsize 12345\n"

// hardeningServer serves an app repository with one submodule and one LFS
// pointer file over smart http on the loopback.
func hardeningServer(t *testing.T) (*hcEnv, *httptest.Server) {
	t.Helper()
	return hardeningServerWith(t, nil)
}

// hardeningServerWith is hardeningServer with mod run on the app source
// (the server is already up at srvURL) before the app is committed.
func hardeningServerWith(t *testing.T, mod func(o *hcEnv, src, srvURL string)) (*hcEnv, *httptest.Server) {
	return hardeningServerWithLib(t, nil, mod)
}

// hardeningServerWithLib also permits a test to put LFS files in the submodule.
func hardeningServerWithLib(t *testing.T, modLib, modApp func(o *hcEnv, src, srvURL string)) (*hcEnv, *httptest.Server) {
	t.Helper()
	git := b2NeedGit(t)
	out, _ := exec.Command(git, "--exec-path").Output()
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not installed")
	}
	o := newHCEnv(t)
	served := t.TempDir()
	srv := httptest.NewServer(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + served, "GIT_HTTP_EXPORT_ALL=1"}})
	t.Cleanup(srv.Close)
	lib := filepath.Join(t.TempDir(), "lib")
	_ = os.MkdirAll(lib, 0o755)
	o.git(lib, "init", "-q", "-b", "main")
	hcWrite(t, lib, "lib.txt", "from the submodule\n")
	if modLib != nil {
		modLib(o, lib, srv.URL)
	}
	o.git(lib, "add", ".")
	o.git(lib, "commit", "-qm", "lib")
	o.git(served, "clone", "-q", "--bare", lib, filepath.Join(served, "lib.git"))
	src := filepath.Join(t.TempDir(), "app")
	_ = os.MkdirAll(src, 0o755)
	o.git(src, "init", "-q", "-b", "main")
	o.git(src, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "lib")
	o.git(src, "config", "--file", ".gitmodules", "submodule.lib.url", "../lib.git")
	hcWrite(t, src, ".gitattributes", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
	hcWrite(t, src, "model.bin", hardeningPointer)
	if modApp != nil {
		modApp(o, src, srv.URL)
	}
	o.git(src, "add", ".")
	o.git(src, "commit", "-qm", "app")
	o.git(served, "clone", "-q", "--bare", src, filepath.Join(served, "app.git"))
	return o, srv
}

// gitEnv sets git config through the environment for the relay's git calls.
// The system git config is left out: a host with git-lfs installed sets
// filter.lfs.process there, which would bypass the test filters.
func gitEnv(t *testing.T, kv ...string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", itoa(len(kv)/2))
	for i := 0; i < len(kv); i += 2 {
		t.Setenv("GIT_CONFIG_KEY_"+itoa(i/2), kv[i])
		t.Setenv("GIT_CONFIG_VALUE_"+itoa(i/2), kv[i+1])
	}
}

func itoa(n int) string { return string(rune('0' + n)) }

// RV3 F6: an http submodule url (from the repository's .gitmodules, not the
// person's) is refused unless the remote is loopback, while the top-level
// clone over http still works.
func TestSyncCloneSubmoduleHTTPRefused(t *testing.T) {
	o, srv := hardeningServer(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	// A name that is not loopback, resolved to the test server.
	gitEnv(t, "http.curloptResolve", "hs-remote.test:"+port+":127.0.0.1")
	remote := "http://hs-remote.test:" + port + "/app.git"

	t.Run("top-level http with submodules off", func(t *testing.T) {
		_, c := hcActor(t)
		if _, err := Clone(context.Background(), c, o.data, "off", remote, "", CloneOptions{}); err != nil {
			t.Fatalf("Clone: %v", err)
		}
	})
	t.Run("http submodule refused", func(t *testing.T) {
		_, c := hcActor(t)
		_, err := Clone(context.Background(), c, o.data, "on", remote, "", CloneOptions{Submodules: true})
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("Clone err = %v, want the http transport refused for the submodule", err)
		}
	})
	t.Run("http submodule refused after a ref checkout", func(t *testing.T) {
		_, c := hcActor(t)
		_, err := Clone(context.Background(), c, o.data, "ref", remote, "main", CloneOptions{Submodules: true})
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("Clone err = %v, want the http transport refused for the submodule", err)
		}
	})
	t.Run("loopback keeps http submodules", func(t *testing.T) {
		wd, c := hcActor(t)
		res, err := Clone(context.Background(), c, o.data, "loop", srv.URL+"/app.git", "", CloneOptions{Submodules: true})
		if err != nil {
			t.Fatalf("Clone: %v", err)
		}
		if _, err := os.Stat(filepath.Join(res.Dir, "lib", "lib.txt")); err != nil {
			t.Errorf("submodule file missing in %s: %v", wd, err)
		}
	})
}

func TestCloneHTTPLoopback(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://127.0.0.1:8080/a.git":    true,
		"http://localhost/a.git":         true,
		"http://[::1]:3000/a.git":        true,
		"https://git.example.test/a.git": false,
		"http://10.0.0.5/a.git":          false,
		"git@github.com:org/a.git":       false,
		"http://127.0.0.1.evil.test/a":   false,
		"ssh://127.0.0.1/a.git":          false,
		"file:///tmp/a.git":              false,
		"../lib.git":                     false,
	} {
		if got := cloneHTTPLoopback(raw); got != want {
			t.Errorf("cloneHTTPLoopback(%q) = %v, want %v", raw, got, want)
		}
	}
}

// RV3 F6: with substrate.git.lfs on, a failed LFS fetch is a warning and the
// files stay pointers; the clone itself works. git here has an LFS filter
// that fails whenever it is asked to smudge, like a media host egress does
// not allow.
func TestSyncCloneLFSFailureIsWarning(t *testing.T) {
	o, srv := hardeningServer(t)
	bin := t.TempDir()
	shim := "#!/bin/sh\ncase \"$1\" in\nversion) echo 'git-lfs/0.0 (test shim)';;\n" +
		"env) echo 'Endpoint=https://media.example.test/lfs (auth=none)';;\n" +
		"smudge) if [ \"$GIT_LFS_SKIP_SMUDGE\" = 1 ]; then cat; else echo 'media host not allowed' >&2; exit 1; fi;;\n" +
		"pull) echo 'batch response: media host not allowed' >&2; exit 2;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "git-lfs"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	gitEnv(t, "filter.lfs.smudge", "git-lfs smudge -- %f", "filter.lfs.required", "true")

	for _, sub := range []bool{false, true} {
		_, c := hcActor(t)
		res, err := Clone(context.Background(), c, o.data, "lfs", srv.URL+"/app.git", "", CloneOptions{LFS: true, Submodules: sub})
		if err != nil {
			t.Fatalf("submodules=%v: a failed LFS fetch failed the clone: %v", sub, err)
		}
		if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "LFS files were not fetched") ||
			!strings.Contains(res.Warnings[0], "media host not allowed") {
			t.Errorf("submodules=%v: warnings %q, want one LFS fetch warning", sub, res.Warnings)
		}
		got, err := os.ReadFile(filepath.Join(res.Dir, "model.bin"))
		if err != nil || string(got) != hardeningPointer {
			t.Errorf("submodules=%v: model.bin = %q (%v), want the pointer", sub, got, err)
		}
	}
}
