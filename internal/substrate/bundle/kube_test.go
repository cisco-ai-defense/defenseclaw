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

package bundle

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// fakeAPI is a ConfigMap REST endpoint with resource-version preconditions.
type fakeAPI struct {
	mu  sync.Mutex
	cms map[string]cmObject
	rv  int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const base = "/api/v1/namespaces/dc/configmaps"
	name := r.URL.Path[len(base):]
	if len(name) > 0 {
		name = name[1:]
	}
	switch r.Method {
	case http.MethodGet:
		obj, ok := f.cms[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodPost, http.MethodPut:
		var obj cmObject
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cur, exists := f.cms[obj.Metadata.Name]
		if r.Method == http.MethodPost && exists || r.Method == http.MethodPut && (!exists || cur.Metadata.ResourceVersion != obj.Metadata.ResourceVersion) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"conflict"}`))
			return
		}
		f.rv++
		obj.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.cms[obj.Metadata.Name] = obj
		_ = json.NewEncoder(w).Encode(obj)
	}
}

func TestKubeConfigMaps(t *testing.T) {
	api := &fakeAPI{cms: map[string]cmObject{}}
	srv := httptest.NewTLSServer(api)
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tok, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := NewKube(srv.URL, "dc", tok, ca)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if cm, err := k.Get(ctx, "x"); cm != nil || err != nil {
		t.Fatalf("missing: %v %v", cm, err)
	}
	if err := k.Create(ctx, &ConfigMap{Name: "x", Data: map[string]string{"a": "1"}, BinaryData: map[string][]byte{"b": {0, 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := k.Create(ctx, &ConfigMap{Name: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create: %v", err)
	}
	cm, err := k.Get(ctx, "x")
	if err != nil || cm.Data["a"] != "1" || string(cm.BinaryData["b"]) != "\x00\x01" || cm.ResourceVersion == "" {
		t.Fatalf("get: %+v %v", cm, err)
	}
	stale := *cm
	cm.Data["a"] = "2"
	if err := k.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := k.Update(ctx, &stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	// The whole store works over REST.
	e := newEnv(t)
	e.store.CM = k
	if _, err := e.store.Apply(ctx, buildBundle(t, e.key, 1, policyYAML("paste.example.com")), "canary", []string{"team-a"}, SourceCLI); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.load(t); r.For("team-a") == nil {
		t.Fatal("no bundle over REST")
	}
	if _, err := NewKube(srv.URL, "", tok, ca); err == nil {
		t.Fatal("no namespace accepted")
	}
}
