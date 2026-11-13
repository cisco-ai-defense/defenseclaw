// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// login --kube sends the kube credential to the Kubernetes API server only,
// and only to an admin address the cluster's own endpoint record names
// (GAP-0130).
func TestSubstrateLoginKubeIsPinnedToTheClustersEndpointRecord(t *testing.T) {
	var adminHits atomic.Int32
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"actors":[]}`))
	}))
	defer admin.Close()
	record := admin.URL
	var sawBearer atomic.Value
	kapi := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawBearer.Store(r.Header.Get("Authorization"))
		// No --kube-namespace: the launcher finds the record (GAP-0192).
		if r.URL.Path == "/api/v1/configmaps" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{
				"metadata": map[string]any{"name": "defenseclaw-launcher-endpoint", "namespace": "defenseclaw-system"},
				"data":     map[string]string{"admin_url": record}}}})
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/namespaces/defenseclaw-system/configmaps/defenseclaw-launcher-endpoint") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"admin_url": record}})
	}))
	defer kapi.Close()

	dir := t.TempDir()
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kapi.Certificate().Raw}))
	kubeconfig := filepath.Join(dir, "kubeconfig")
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: c
  cluster: {server: %s, certificate-authority-data: %s}
users:
- name: dev-user
  user: {token: kube-secret-token}
contexts:
- name: dev
  context: {cluster: c, user: dev-user}
`, kapi.URL, ca)
	if err := os.WriteFile(kubeconfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	adminCA := filepath.Join(dir, "admin-ca.pem")
	if err := os.WriteFile(adminCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: admin.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", dir)

	run := func(adminURL string) (string, error) {
		out, _, err := runSubstrate(t, newSubstrateLoginCmd(), "--name", "k", "--admin-url", adminURL, "--admin-ca-file", adminCA,
			"--kube", "--kubeconfig", kubeconfig)
		return out, err
	}
	// An admin address the record does not name gets no credential at all.
	if _, err := run("https://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "no Kubernetes credential is sent") {
		t.Fatalf("a different admin address must be refused, got %v", err)
	}
	if adminHits.Load() != 0 {
		t.Fatal("the admin listener was contacted before the record was checked")
	}
	// The record's own address works, and the bearer went to the API server.
	out, err := run(record)
	if err != nil || !strings.Contains(out, "Signed in as dev-user") {
		t.Fatalf("login = %q, %v", out, err)
	}
	if got, _ := sawBearer.Load().(string); got != "Bearer kube-secret-token" {
		t.Errorf("the API server saw %q", got)
	}
	cf, err := auth.LoadContexts()
	if err != nil {
		t.Fatal(err)
	}
	c := cf.Contexts["k"]
	if !c.Kube || c.KubePinAdminURL == "" || c.KubePinServer == "" {
		t.Errorf("the pin was not saved: %+v", c)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "substrate", "contexts.json"))
	if strings.Contains(string(raw), "kube-secret-token") {
		t.Error("the token is in the contexts file")
	}
	// The env override cannot point a verified context somewhere else.
	t.Setenv("DEFENSECLAW_SUBSTRATE_ADMIN_URL", "https://127.0.0.1:1")
	if _, _, err := runSubstrate(t, newSubstrateListCmd(), "--context", "k"); err == nil || !strings.Contains(err.Error(), "run: defenseclaw substrate login --kube again") {
		t.Errorf("the override must be refused, got %v", err)
	}
}

// Live on bm (GAP-0192): doctor said a Kubernetes sign-in signs in "with a
// workload token only".
func TestSubstrateDoctorSignInServerNamesAKubeSignIn(t *testing.T) {
	got := doctorSignInServer(context.Background(), auth.Context{Kube: true})
	if got.Status != doctorSkip || !strings.Contains(got.Summary, "Kubernetes credentials") {
		t.Fatalf("kube context: %+v", got)
	}
	if got := doctorSignInServer(context.Background(), auth.Context{}); !strings.Contains(got.Summary, "workload token") {
		t.Fatalf("workload context: %+v", got)
	}
}
