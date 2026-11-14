// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// fakeKubeSecret is one Secret of fakeKubeAPI.
type fakeKubeSecret struct {
	labels map[string]string
	rv     int
	data   map[string]string
}

// fakeKubeAPI is the Secrets part of the Kubernetes API: labels,
// resourceVersion (a merge patch naming a stale one is 409) and data.
type fakeKubeAPI struct {
	mu      sync.Mutex
	secrets map[string]*fakeKubeSecret
	patches int
}

func (f *fakeKubeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer kube-token" {
		w.WriteHeader(401)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"), "/")
	ns, name := parts[0], ""
	if len(parts) > 2 {
		name = parts[2]
	}
	body, _ := io.ReadAll(r.Body)
	s := f.secrets[ns+"/"+name]
	switch r.Method {
	case http.MethodGet:
		if s == nil {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"labels": s.labels, "resourceVersion": strconv.Itoa(s.rv)}, "data": s.data})
	case http.MethodPatch:
		if s == nil {
			w.WriteHeader(404)
			return
		}
		var p struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
			Data map[string]*string `json:"data"`
		}
		_ = json.Unmarshal(body, &p)
		if p.Metadata.ResourceVersion != "" && p.Metadata.ResourceVersion != strconv.Itoa(s.rv) {
			w.WriteHeader(409)
			return
		}
		f.patches++
		for k, v := range p.Data {
			if v == nil {
				delete(s.data, k)
			} else {
				s.data[k] = *v
			}
		}
		s.rv++
		w.WriteHeader(200)
	case http.MethodPost:
		var obj struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		}
		_ = json.Unmarshal(body, &obj)
		if f.secrets[ns+"/"+obj.Metadata.Name] != nil {
			w.WriteHeader(409)
			return
		}
		f.secrets[ns+"/"+obj.Metadata.Name] = &fakeKubeSecret{labels: obj.Metadata.Labels, rv: 1, data: obj.Data}
		w.WriteHeader(201)
	}
}

func newFakeKube(t *testing.T) (*fakeKubeAPI, *kubeSecrets) {
	t.Helper()
	f := &fakeKubeAPI{secrets: map[string]*fakeKubeSecret{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("kube-token\n"), 0o600)
	return f, &kubeSecrets{server: srv.URL, tokenFile: tok, http: srv.Client()}
}

func TestKubeSecretsSetExistsRemove(t *testing.T) {
	f, k := newFakeKube(t)
	ctx := context.Background()
	if ok, err := k.Exists(ctx, "dc-people", "p-1-npm", "token"); err != nil || ok {
		t.Fatalf("missing %v %v", ok, err)
	}
	if err := k.Set(ctx, "dc-people", "p-1-npm", "token", []byte("npm-value")); err != nil {
		t.Fatal(err)
	}
	s := f.secrets["dc-people/p-1-npm"]
	if s == nil || s.data["token"] != base64.StdEncoding.EncodeToString([]byte("npm-value")) || s.labels[kubeManagedByLabel] != kubeManagedBy {
		t.Fatalf("stored %+v", s)
	}
	if ok, _ := k.Exists(ctx, "dc-people", "p-1-npm", "token"); !ok {
		t.Fatal("not found after set")
	}
	if err := k.Set(ctx, "dc-people", "p-1-npm", "other", []byte("v2")); err != nil || len(s.data) != 2 {
		t.Fatalf("second key %v %+v", err, s)
	}
	if err := k.Remove(ctx, "dc-people", "p-1-npm", "token"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := k.Exists(ctx, "dc-people", "p-1-npm", "token"); ok {
		t.Fatal("found after remove")
	}
	if err := k.Remove(ctx, "dc-people", "absent", "token"); err != nil {
		t.Fatalf("remove from a missing Secret: %v", err)
	}
	if err := k.Set(ctx, "../x", "p", "token", []byte("v")); err == nil {
		t.Fatal("bad namespace accepted")
	}
}

// GAP-0183: RBAC cannot select by label, so the writer changes only Secrets
// it created (managed-by defenseclaw) and patches at the resourceVersion it
// checked.
func TestGAP0183KubeSecretsChangeOnlyTheirOwnSecrets(t *testing.T) {
	f, k := newFakeKube(t)
	ctx := context.Background()
	f.secrets["dc-people/team-db"] = &fakeKubeSecret{labels: map[string]string{"app": "db"}, rv: 7, data: map[string]string{"token": "c2VjcmV0"}}
	if err := k.Set(ctx, "dc-people", "team-db", "token", []byte("mine")); !errors.Is(err, gateway.ErrSubstrateSecretNotOwned) {
		t.Fatalf("set on a Secret DefenseClaw does not own: %v", err)
	}
	if err := k.Remove(ctx, "dc-people", "team-db", "token"); !errors.Is(err, gateway.ErrSubstrateSecretNotOwned) {
		t.Fatalf("remove on a Secret DefenseClaw does not own: %v", err)
	}
	if f.patches != 0 || f.secrets["dc-people/team-db"].data["token"] != "c2VjcmV0" {
		t.Fatalf("the foreign Secret was changed: %d patches %+v", f.patches, f.secrets["dc-people/team-db"])
	}
	// Every patch names the resourceVersion of the ownership check.
	if err := k.Set(ctx, "dc-people", "p-2-npm", "token", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := k.Set(ctx, "dc-people", "p-2-npm", "token", []byte("b")); err != nil || f.patches != 1 {
		t.Fatalf("owned update: %v (%d patches)", err, f.patches)
	}
}
