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

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// certAPI is a kind-like API server: it requires a client certificate and
// serves the endpoint record (namespace dc) and TokenRequest for the
// ServiceAccount dc/defenseclaw-launcher. It records what each request
// carried.
type certAPI struct {
	srv       *httptest.Server
	ca        []byte // the server's CA, for the kubeconfig
	cert, key []byte // the client certificate and key, PEM
	admin     string
	mu        sync.Mutex
	bearers   []string
	audiences []string
	minted    int
	saMissing bool
}

func newCertAPI(t *testing.T, admin string) *certAPI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kind-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	clKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "kubernetes-admin", Organization: []string{"kubeadm:cluster-admins"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	clDER, err := x509.CreateCertificate(rand.Reader, clTpl, caCert, &clKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(clKey)
	a := &certAPI{admin: admin, cert: certPEM(clDER), key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(a.serve))
	a.srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	a.ca = certPEM(a.srv.Certificate().Raw)
	return a
}

func (a *certAPI) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.bearers = append(a.bearers, r.Header.Get("Authorization"))
	a.mu.Unlock()
	record := map[string]any{"kind": "ConfigMap", "metadata": map[string]any{"name": KubeEndpointConfigMap, "namespace": "dc"},
		"data": map[string]string{"admin_url": a.admin}}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/configmaps" && r.URL.Query().Get("fieldSelector") == "metadata.name="+KubeEndpointConfigMap:
		other := map[string]any{"metadata": map[string]any{"name": KubeEndpointConfigMap, "namespace": "elsewhere"},
			"data": map[string]string{"admin_url": "https://other.example.test:8445"}}
		writeJSON(w, 200, map[string]any{"kind": "ConfigMapList", "items": []any{other, record}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/dc/configmaps/"+KubeEndpointConfigMap:
		writeJSON(w, 200, record)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/dc/serviceaccounts/defenseclaw-launcher/token":
		if a.saMissing {
			writeJSON(w, 404, map[string]any{"kind": "Status", "reason": "NotFound"})
			return
		}
		var in struct {
			Spec struct {
				Audiences         []string `json:"audiences"`
				ExpirationSeconds int      `json:"expirationSeconds"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		a.mu.Lock()
		a.minted++
		a.audiences = append(a.audiences, in.Spec.Audiences...)
		a.mu.Unlock()
		writeJSON(w, 201, map[string]any{"kind": "TokenRequest", "status": map[string]any{
			"token": "minted-sa-token", "expirationTimestamp": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)}})
	default:
		writeJSON(w, 404, map[string]any{"kind": "Status", "reason": "NotFound"})
	}
}

func (a *certAPI) kubeconfig() string {
	b64 := base64.StdEncoding.EncodeToString
	return "current-context: kind-bm\nclusters:\n- name: kind-bm\n  cluster:\n    server: " + a.srv.URL +
		"\n    certificate-authority-data: " + b64(a.ca) + "\ncontexts:\n- {name: kind-bm, context: {cluster: kind-bm, user: kind-bm}}\n" +
		"users:\n- name: kind-bm\n  user:\n    client-certificate-data: " + b64(a.cert) + "\n    client-key-data: " + b64(a.key) + "\n"
}

// GAP-0192: the kind quickstart's kubeconfig signs in with a client
// certificate. The launcher finds the endpoint record without a namespace
// flag, uses the certificate only toward the API server, and hands the
// gateway a short-lived ServiceAccount token minted for DefenseClaw.
func TestKubeClientCertificateSignIn(t *testing.T) {
	admin := "https://dc-admin.example.test:8445"
	a := newCertAPI(t, admin)
	dir := t.TempDir()
	writeFile(t, dir, "config", a.kubeconfig())
	o := KubeOptions{Kubeconfig: dir + "/config"}
	ctx := context.Background()

	pin, err := KubeVerifyEndpoint(ctx, o, admin, "")
	if err != nil {
		t.Fatalf("endpoint record without --kube-namespace: %v", err)
	}
	if pin.AdminURL != admin {
		t.Fatalf("pin %+v", pin)
	}
	c := Context{AdminURL: admin, Kube: true, Kubeconfig: dir + "/config", KubeNamespace: "dc"}.WithKubePin(pin)
	tok, err := KubeLogin(ctx, c.KubeOptions())
	if err != nil {
		t.Fatalf("login with a client certificate: %v", err)
	}
	if tok.AccessToken != "minted-sa-token" || tok.Expiry.IsZero() {
		t.Fatalf("token %+v", tok)
	}
	a.mu.Lock()
	for _, b := range a.bearers {
		if b != "" {
			t.Errorf("the API server got a bearer %q; the certificate user sends none", b)
		}
	}
	if a.minted != 1 || len(a.audiences) != 1 || a.audiences[0] != "defenseclaw-substrate" {
		t.Errorf("minted %d, audiences %v", a.minted, a.audiences)
	}
	a.mu.Unlock()

	// No ServiceAccount set up: one line that says what to do.
	a.saMissing = true
	_, err = KubeLogin(ctx, c.KubeOptions())
	if err == nil || strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), "--kube-service-account") ||
		!strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("missing ServiceAccount: %v", err)
	}
}

// GAP-0192: with no --kube-namespace the launcher finds the one endpoint
// record that names the admin URL; two such records, or no right to list
// them, ask for --kube-namespace. A token user (bearer) is shown here.
func TestKubeEndpointDiscovery(t *testing.T) {
	dir := t.TempDir()
	api, admin := newRecorder(t), newRecorder(t)
	ca := certPEM(api.srv.Certificate().Raw)
	cfg := writeFile(t, dir, "config", apiKubeconfig(api.srv.URL, "    certificate-authority-data: "+base64.StdEncoding.EncodeToString(ca)+"\n"))
	o := KubeOptions{Kubeconfig: cfg, Env: emptyEnv}
	rec := func(ns, url string) map[string]any {
		return map[string]any{"metadata": map[string]any{"name": KubeEndpointConfigMap, "namespace": ns}, "data": map[string]string{"admin_url": url}}
	}
	list := func(items ...any) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/configmaps":
				writeJSON(w, 200, map[string]any{"items": items})
			case "/api/v1/namespaces/dc/configmaps/" + KubeEndpointConfigMap:
				configMap(admin.srv.URL)(w, r)
			default:
				http.Error(w, "no", 404)
			}
		}
	}
	api.fn = list(rec("other", "https://other.example.test:8445"), rec("dc", admin.srv.URL))
	pin, err := KubeVerifyEndpoint(context.Background(), o, admin.srv.URL, "")
	if err != nil || pin.Namespace != "dc" {
		t.Fatalf("found: %+v %v", pin, err)
	}
	if c := (Context{}).WithKubePin(pin); c.KubeNamespace != "dc" {
		t.Fatalf("the found namespace is not recorded: %+v", c)
	}
	if c := (Context{KubeNamespace: "mine"}).WithKubePin(pin); c.KubeNamespace != "mine" {
		t.Fatalf("a named namespace was replaced: %+v", c)
	}
	api.fn = list(rec("dc", admin.srv.URL), rec("dc2", admin.srv.URL))
	if _, err := KubeVerifyEndpoint(context.Background(), o, admin.srv.URL, ""); err == nil || !strings.Contains(err.Error(), "dc, dc2") || !strings.Contains(err.Error(), "--kube-namespace") {
		t.Fatalf("two records: %v", err)
	}
	api.fn = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) }
	if _, err := KubeVerifyEndpoint(context.Background(), o, admin.srv.URL, ""); err == nil || !strings.Contains(err.Error(), "may not list ConfigMaps in every namespace") {
		t.Fatalf("list forbidden: %v", err)
	}
	if admin.count() != 0 {
		t.Fatal("the admin listener was contacted during discovery")
	}
}

// --kube-service-account also works for a token user whose own bearer is
// not one the gateway takes (a plain ServiceAccount token of the API
// server's audience): the launcher mints a DefenseClaw one with it.
func TestKubeNamedServiceAccountFromAToken(t *testing.T) {
	dir := t.TempDir()
	api := newRecorder(t)
	ca := certPEM(api.srv.Certificate().Raw)
	cfg := writeFile(t, dir, "config", apiKubeconfig(api.srv.URL, "    certificate-authority-data: "+base64.StdEncoding.EncodeToString(ca)+"\n"))
	api.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/namespaces/team/serviceaccounts/dev1/token" {
			http.Error(w, "no", 404)
			return
		}
		writeJSON(w, 201, map[string]any{"status": map[string]any{"token": "minted-dev1", "expirationTimestamp": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)}})
	}
	tok, err := KubeLogin(context.Background(), KubeOptions{Kubeconfig: cfg, Env: emptyEnv, ServiceAccount: "team/dev1"})
	if err != nil || tok.AccessToken != "minted-dev1" || tok.Principal != "system:serviceaccount:team:dev1" {
		t.Fatalf("named ServiceAccount: %+v %v", tok, err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.auth) != 1 || api.auth[0] != "Bearer "+kubeBearer {
		t.Fatalf("the mint did not use the user's own bearer: %q", api.auth)
	}
	for _, bad := range []string{"Team/x", "a/b/c", "-x", ""} {
		if CheckKubeServiceAccount(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
