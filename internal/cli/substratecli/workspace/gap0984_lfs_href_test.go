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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// GAP-0984: an allowed (loopback) LFS batch endpoint names a plain-http
// object address on another host. git-lfs may fetch it there without
// credentials (the helper guard never answers plain http outside the
// loopback); whatever it does, a file that stays a pointer after an
// apparently successful git lfs pull is named in a warning, never silent.
func TestGAP0984LFSHTTPHrefPointerIsWarned(t *testing.T) {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		t.Skip("git-lfs not installed")
	}
	body := []byte("an lfs object body for the GAP-0984 test\n")
	sum := sha256.Sum256(body)
	oid := hex.EncodeToString(sum[:])
	pointer := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oid, len(body))

	var mu sync.Mutex
	var seen []string
	media := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write(body)
	}))
	t.Cleanup(media.Close)
	batch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Objects []struct {
				Oid  string `json:"oid"`
				Size int64  `json:"size"`
			} `json:"objects"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		var objs []map[string]any
		for _, o := range in.Objects {
			objs = append(objs, map[string]any{"oid": o.Oid, "size": o.Size,
				"actions": map[string]any{"download": map[string]string{"href": "http://lfs-media.test/obj/" + o.Oid}}})
		}
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"transfer": "basic", "objects": objs})
	}))
	t.Cleanup(batch.Close)
	o, srv := hardeningServerWith(t, func(o *hcEnv, src, _ string) {
		hcWrite(t, src, "model.bin", pointer)
		hcWrite(t, src, ".lfsconfig", "[lfs]\n\turl = "+batch.URL+"/lfs\n")
	})
	// git (curl) ignores HTTP_PROXY; git-lfs sends every http request
	// there, so the media server answers for lfs-media.test.
	t.Setenv("HTTP_PROXY", media.URL)
	t.Setenv("NO_PROXY", "")
	rvhardImageHelper(t)
	gitEnv(t, "credential.helper", rvhardCreds,
		"filter.lfs.smudge", "git-lfs smudge -- %f", "filter.lfs.process", "git-lfs filter-process",
		"filter.lfs.required", "true", "lfs.transfer.maxretries", "1", "lfs.transfer.maxretrydelay", "0")
	_, c := hcActor(t)
	res, err := Clone(context.Background(), c, o.data, "lfs", srv.URL+"/app.git", "", CloneOptions{LFS: true})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	mu.Lock()
	for _, r := range seen {
		if strings.Contains(r, "Basic ") {
			t.Errorf("credential sent to the plain-http object address: %q", r)
		}
	}
	mu.Unlock()
	got, err := os.ReadFile(filepath.Join(res.Dir, "model.bin"))
	if err != nil {
		t.Fatal(err)
	}
	warned := strings.Contains(strings.Join(res.Warnings, "\n"), "pointer")
	t.Logf("model.bin fetched=%v warnings=%q", string(got) == string(body), res.Warnings)
	if string(got) != string(body) && !warned {
		t.Errorf("model.bin stayed a pointer and no warning says so: %q", res.Warnings)
	}
}
