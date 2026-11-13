// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestKubeSecretsSetExistsRemove(t *testing.T) {
	var mu sync.Mutex
	data := map[string]map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kube-token" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"), "/")
		ns := parts[0]
		name := ""
		if len(parts) > 2 {
			name = parts[2]
		}
		body, _ := io.ReadAll(r.Body)
		switch r.Method {
		case http.MethodGet:
			d, ok := data[ns+"/"+name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": d})
		case http.MethodPatch:
			d, ok := data[ns+"/"+name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			var p struct {
				Data map[string]*string `json:"data"`
			}
			_ = json.Unmarshal(body, &p)
			for k, v := range p.Data {
				if v == nil {
					delete(d, k)
				} else {
					d[k] = *v
				}
			}
			w.WriteHeader(200)
		case http.MethodPost:
			var obj struct {
				Metadata struct{ Name string } `json:"metadata"`
				Data     map[string]string     `json:"data"`
			}
			_ = json.Unmarshal(body, &obj)
			data[ns+"/"+obj.Metadata.Name] = obj.Data
			w.WriteHeader(201)
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("kube-token\n"), 0o600)
	k := &kubeSecrets{server: srv.URL, tokenFile: tok, http: srv.Client()}
	ctx := context.Background()
	if ok, err := k.Exists(ctx, "dc-people", "p-1-npm", "token"); err != nil || ok {
		t.Fatalf("missing %v %v", ok, err)
	}
	if err := k.Set(ctx, "dc-people", "p-1-npm", "token", []byte("npm-value")); err != nil {
		t.Fatal(err)
	}
	if data["dc-people/p-1-npm"]["token"] != base64.StdEncoding.EncodeToString([]byte("npm-value")) {
		t.Fatalf("stored %v", data)
	}
	if ok, _ := k.Exists(ctx, "dc-people", "p-1-npm", "token"); !ok {
		t.Fatal("not found after set")
	}
	if err := k.Set(ctx, "dc-people", "p-1-npm", "other", []byte("v2")); err != nil || len(data["dc-people/p-1-npm"]) != 2 {
		t.Fatalf("second key %v %v", err, data)
	}
	if err := k.Remove(ctx, "dc-people", "p-1-npm", "token"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := k.Exists(ctx, "dc-people", "p-1-npm", "token"); ok {
		t.Fatal("found after remove")
	}
	if err := k.Set(ctx, "../x", "p", "token", []byte("v")); err == nil {
		t.Fatal("bad namespace accepted")
	}
}
