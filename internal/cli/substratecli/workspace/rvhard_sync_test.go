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
	"encoding/json"
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

// rvhardImageHelper stands in for the actor image's root-owned helper.
func rvhardImageHelper(t *testing.T) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "git-credential-defenseclaw")
	if err := os.WriteFile(p, []byte(`#!/bin/sh
cat >/dev/null
if [ "$1" = get ]; then printf 'username=x-access-token\npassword=placeholder-not-a-secret\n'; fi
`), 0o700); err != nil {
		t.Fatal(err)
	}
	old := cloneImageCredHelper
	cloneImageCredHelper = p
	t.Cleanup(func() { cloneImageCredHelper = old })
}

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
	count := len(l.seen)
	l.mu.Unlock()
	if r.Header.Get("Authorization") == "" && count == 1 {
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
	rvhardImageHelper(t)
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
	rvhardImageHelper(t)
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

// GAP-0927: the helper guard also applies to LFS in a checked-out submodule.
func TestRVHARDSubmoduleLFSHTTPHrefDoesNotGetCredential(t *testing.T) {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		t.Skip("git-lfs not installed")
	}
	rec := &lfsRecorder{}
	proxy := httptest.NewServer(rec)
	t.Cleanup(proxy.Close)
	batch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"transfer": "basic", "objects": []any{
			map[string]any{"oid": "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", "size": 12345,
				"actions": map[string]any{"download": map[string]string{"href": "http://lfs-media.test/obj"}}},
		}})
	}))
	t.Cleanup(batch.Close)
	o, srv := hardeningServerWithLib(t, func(o *hcEnv, lib, _ string) {
		hcWrite(t, lib, ".gitattributes", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
		hcWrite(t, lib, "model.bin", hardeningPointer)
		hcWrite(t, lib, ".lfsconfig", "[lfs]\n\turl = "+batch.URL+"/lfs\n")
	}, nil)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	rvhardImageHelper(t)
	gitEnv(t, "credential.helper", rvhardCreds,
		"filter.lfs.smudge", "git-lfs smudge -- %f", "filter.lfs.process", "git-lfs filter-process",
		"filter.lfs.required", "true", "lfs.transfer.maxretries", "1", "lfs.transfer.maxretrydelay", "0")
	_, c := hcActor(t)
	res, err := Clone(context.Background(), c, o.data, "sub-lfs", srv.URL+"/app.git", "", CloneOptions{Submodules: true, LFS: true})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if len(rec.requests()) == 0 {
		t.Fatal("the submodule LFS object href was not requested")
	}
	for _, request := range rec.requests() {
		if strings.Contains(request, "Basic ") {
			t.Errorf("credential sent to the submodule's plain-http object href: %q", request)
		}
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "lib") {
		t.Errorf("submodule LFS warning missing: %q", res.Warnings)
	}
	got, err := os.ReadFile(filepath.Join(res.Dir, "lib", "model.bin"))
	if err != nil || string(got) != hardeningPointer {
		t.Errorf("submodule LFS file = %q (%v), want pointer", got, err)
	}
}

// GAP-0927 probe: an allowed (loopback here; https behaves the same in
// git-lfs) batch endpoint answers with a plain-http object href on another
// host, which answers 401. Does git-lfs send the helper placeholder there?
func TestRVHARD2LFSHTTPHrefAfter401(t *testing.T) {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		t.Skip("git-lfs not installed")
	}
	for _, batchAuth := range []bool{false, true} {
		rec := &lfsRecorder{}
		proxy := httptest.NewServer(rec)
		batch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if batchAuth && r.Header.Get("Authorization") == "" {
				w.Header().Set("LFS-Authenticate", `Basic realm="lfs"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var in struct {
				Objects []struct {
					Oid  string `json:"oid"`
					Size int64  `json:"size"`
				} `json:"objects"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			type act struct {
				Href string `json:"href"`
			}
			var objs []map[string]any
			for _, o := range in.Objects {
				objs = append(objs, map[string]any{"oid": o.Oid, "size": o.Size,
					"actions": map[string]any{"download": act{Href: "http://lfs-media.test/obj/" + o.Oid}}})
			}
			w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
			_ = json.NewEncoder(w).Encode(map[string]any{"transfer": "basic", "objects": objs})
		}))
		o, srv := hardeningServerWith(t, func(o *hcEnv, src, _ string) {
			hcWrite(t, src, ".lfsconfig", "[lfs]\n\turl = "+batch.URL+"/lfs\n")
		})
		t.Setenv("HTTP_PROXY", proxy.URL)
		t.Setenv("NO_PROXY", "")
		rvhardImageHelper(t)
		gitEnv(t, "credential.helper", rvhardCreds,
			"filter.lfs.smudge", "git-lfs smudge -- %f", "filter.lfs.process", "git-lfs filter-process",
			"filter.lfs.required", "true", "lfs.transfer.maxretries", "1", "lfs.transfer.maxretrydelay", "0")
		_, c := hcActor(t)
		res, err := Clone(context.Background(), c, o.data, "lfs", srv.URL+"/app.git", "", CloneOptions{LFS: true})
		if err != nil {
			t.Fatalf("batchAuth=%v: Clone: %v", batchAuth, err)
		}
		if len(res.Warnings) == 0 {
			t.Errorf("batchAuth=%v: want an LFS warning", batchAuth)
		}
		leaked := false
		for _, r := range rec.requests() {
			if strings.Contains(r, "Basic ") {
				leaked = true
			}
		}
		if leaked {
			t.Errorf("batchAuth=%v: credential placeholder went to plain-http object href", batchAuth)
		}
		proxy.Close()
		batch.Close()
	}
}
