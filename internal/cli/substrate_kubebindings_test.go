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

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// fakeConfigMap serves one ConfigMap with get and update only, the verbs
// the gateway's Role grants.
type fakeConfigMap struct {
	mu      sync.Mutex
	exists  bool
	version int
	labels  map[string]any
	data    map[string]any
	methods []string
}

func (f *fakeConfigMap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, r.Method)
	if r.URL.Path != "/api/v1/namespaces/dc/configmaps/defenseclaw-secret-bindings" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !f.exists {
		http.NotFound(w, r)
		return
	}
	obj := func() map[string]any {
		return map[string]any{"metadata": map[string]any{"name": "defenseclaw-secret-bindings", "resourceVersion": strconv.Itoa(f.version), "labels": f.labels}, "data": f.data}
	}
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(obj())
	case http.MethodPut:
		raw, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(raw, &in)
		if objVersion(in) != strconv.Itoa(f.version) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		md, _ := in["metadata"].(map[string]any)
		f.labels, _ = md["labels"].(map[string]any)
		f.data, _ = in["data"].(map[string]any)
		f.version++
		_ = json.NewEncoder(w).Encode(obj())
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func newFakeBindings(t *testing.T, f *fakeConfigMap) kubeBindings {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	return kubeBindings{k: &kubeSecrets{server: srv.URL, tokenFile: tok, http: srv.Client()}, ns: "dc", name: "defenseclaw-secret-bindings"}
}

func TestKubeBindingsStoreRoundTripKeepsChartLabels(t *testing.T) {
	f := &fakeConfigMap{exists: true, version: 7, labels: map[string]any{"app.kubernetes.io/managed-by": "Helm"}}
	s := secretbind.New(newFakeBindings(t, f))
	b := secretbind.Binding{ID: secretbind.NewID(), Name: "gl-work", Owner: "pk-eng2-0002", Template: "gitlab",
		Hosts: []string{"git.corp.example"}, State: secretbind.Active, Created: time.Now().UTC()}
	if err := s.Update(context.Background(), func(d *secretbind.Doc) error { d.Bindings = append(d.Bindings, b); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := s.ForOwner("pk-eng2-0002"); len(got) != 1 || got[0].Name != "gl-work" {
		t.Fatalf("read back %+v", got)
	}
	if f.labels["app.kubernetes.io/managed-by"] != "Helm" {
		t.Fatal("update dropped the chart's labels")
	}
	for _, m := range f.methods {
		if m != http.MethodGet && m != http.MethodPut {
			t.Fatalf("used %s; the Role grants get and update only", m)
		}
	}
}

func TestKubeBindingsMissingConfigMapIsNoStore(t *testing.T) {
	s := secretbind.New(newFakeBindings(t, &fakeConfigMap{}))
	if err := s.Refresh(context.Background()); !errors.Is(err, secretbind.ErrNoStore) {
		t.Fatalf("missing ConfigMap: %v", err)
	}
	if err := s.Update(context.Background(), func(*secretbind.Doc) error { return nil }); !errors.Is(err, secretbind.ErrNoStore) {
		t.Fatalf("write to missing ConfigMap: %v", err)
	}
}

func TestKubeBindingsStaleVersionIsConflict(t *testing.T) {
	f := &fakeConfigMap{exists: true, version: 3}
	b := newFakeBindings(t, f)
	if err := b.Put(context.Background(), []byte(`{"version":1,"bindings":[]}`), "2"); !errors.Is(err, secretbind.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
}
