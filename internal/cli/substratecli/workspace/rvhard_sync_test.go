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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// rvhardCreds is a credential helper that answers like the actor image's.
const rvhardCreds = "!f() { echo username=x-access-token; echo password=placeholder-not-a-secret; }; f"

// lfsRecorder answers every request 401 until it carries credentials and
// records each request's host and Authorization header. Used as an http
// proxy, it sees what git-lfs would send to any http host.
type lfsRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (l *lfsRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	l.seen = append(l.seen, r.Host+" "+r.Header.Get("Authorization"))
	l.mu.Unlock()
	if r.Header.Get("Authorization") == "" {
		w.Header().Set("LFS-Authenticate", `Basic realm="lfs"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (l *lfsRecorder) requests() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

// GAP-0905: an LFS endpoint the repository's .lfsconfig names over plain
// http (not loopback) never gets the credential helper's placeholder; the
// files stay pointers with a warning and the clone works.
func TestRVHARDCloneLFSHTTPEndpointRefused(t *testing.T) {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		t.Skip("git-lfs not installed")
	}
	rec := &lfsRecorder{}
	proxy := httptest.NewServer(rec)
	t.Cleanup(proxy.Close)
	o, srv := hardeningServerWith(t, func(o *hcEnv, src, _ string) {
		hcWrite(t, src, ".lfsconfig", "[lfs]\n\turl = http://lfs-media.test/lfs\n")
	})
	// git (curl) ignores HTTP_PROXY; git-lfs sends every http request there.
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	gitEnv(t, "credential.helper", rvhardCreds,
		"filter.lfs.smudge", "git-lfs smudge -- %f", "filter.lfs.process", "git-lfs filter-process",
		"filter.lfs.required", "true")

	for _, sub := range []bool{false, true} {
		_, c := hcActor(t)
		res, err := Clone(context.Background(), c, o.data, "lfs", srv.URL+"/app.git", "", CloneOptions{LFS: true, Submodules: sub})
		if err != nil {
			t.Fatalf("submodules=%v: Clone: %v", sub, err)
		}
		for _, r := range rec.requests() {
			if strings.Contains(r, "Basic ") {
				t.Errorf("submodules=%v: credentials went over plain http: %q", sub, r)
			}
		}
		if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, "\n"), "not https") {
			t.Errorf("submodules=%v: warnings %q, want the http LFS endpoint left out", sub, res.Warnings)
		}
		got, err := os.ReadFile(filepath.Join(res.Dir, "model.bin"))
		if err != nil || string(got) != hardeningPointer {
			t.Errorf("submodules=%v: model.bin = %q (%v), want the pointer", sub, got, err)
		}
	}
}

// GAP-0905: an LFS endpoint on the loopback (a test or local mirror) is
// still fetched from.
func TestRVHARDCloneLFSLoopbackEndpointFetched(t *testing.T) {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		t.Skip("git-lfs not installed")
	}
	rec := &lfsRecorder{}
	lfs := httptest.NewServer(rec)
	t.Cleanup(lfs.Close)
	o, srv := hardeningServerWith(t, func(o *hcEnv, src, _ string) {
		hcWrite(t, src, ".lfsconfig", "[lfs]\n\turl = "+lfs.URL+"/lfs\n")
	})
	gitEnv(t, "credential.helper", rvhardCreds,
		"filter.lfs.smudge", "git-lfs smudge -- %f", "filter.lfs.process", "git-lfs filter-process",
		"filter.lfs.required", "true")
	_, c := hcActor(t)
	if _, err := Clone(context.Background(), c, o.data, "lfs", srv.URL+"/app.git", "", CloneOptions{LFS: true}); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if len(rec.requests()) == 0 {
		t.Errorf("git lfs pull never asked the loopback LFS endpoint")
	}
}

// GAP-0907: a loopback top-level clone does not open plain http for a
// submodule whose own url is not on the loopback.
func TestRVHARDCloneLoopbackTopHTTPSubmoduleRefused(t *testing.T) {
	var port string
	o, srv := hardeningServerWith(t, func(o *hcEnv, src, srvURL string) {
		_, port, _ = net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
		o.git(src, "config", "--file", ".gitmodules", "submodule.lib.url", "http://hs-sub.test:"+port+"/lib.git")
	})
	// A name that is not loopback, resolved to the test server.
	gitEnv(t, "http.curloptResolve", "hs-sub.test:"+port+":127.0.0.1")
	_, c := hcActor(t)
	_, err := Clone(context.Background(), c, o.data, "sub", srv.URL+"/app.git", "", CloneOptions{Submodules: true})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("Clone err = %v, want the http transport refused for the non-loopback submodule", err)
	}
}
