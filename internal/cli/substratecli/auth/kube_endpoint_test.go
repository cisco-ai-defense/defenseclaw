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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const kubeBearer = "kube-bearer-marker"

// recorder is a TLS test server that records what it was sent.
type recorder struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls int
	auth  []string
	paths []string
	fn    func(w http.ResponseWriter, r *http.Request)
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	rc := &recorder{}
	rc.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		rc.calls++
		rc.auth = append(rc.auth, r.Header.Get("Authorization"))
		rc.paths = append(rc.paths, r.URL.Path)
		fn := rc.fn
		rc.mu.Unlock()
		if fn != nil {
			fn(w, r)
		}
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *recorder) count() int { rc.mu.Lock(); defer rc.mu.Unlock(); return rc.calls }

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// otherCA is a self-signed CA that did not sign the test server.
func otherCA(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "other-ca.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM(der)
}

func configMap(adminURL string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"kind": "ConfigMap", "data": map[string]string{"admin_url": adminURL}})
	}
}

// apiKubeconfig points a kubeconfig at the API server; cluster is extra
// YAML for the cluster entry (the CA, by default the server's own).
func apiKubeconfig(server, cluster string) string {
	return "current-context: e1\nclusters:\n- name: c1\n  cluster:\n    server: " + server + "\n" + cluster +
		"contexts:\n- {name: e1, context: {cluster: c1, user: alice}}\nusers:\n- {name: alice, user: {token: " + kubeBearer + "}}\n"
}

func TestKubeVerifyEndpoint(t *testing.T) {
	dir := t.TempDir()
	api, admin := newRecorder(t), newRecorder(t)
	ca := certPEM(api.srv.Certificate().Raw)
	caData := "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca) + "\n"
	writeFile(t, dir, "ca.pem", string(ca))
	adminNorm, _ := normEndpoint(admin.srv.URL)
	apiNorm, _ := normEndpoint(api.srv.URL)
	wantPath := "/api/v1/namespaces/defenseclaw-system/configmaps/" + KubeEndpointConfigMap
	tests := []struct {
		name      string
		cluster   string
		server    string
		namespace string
		fn        func(w http.ResponseWriter, r *http.Request)
		timeout   time.Duration
		wantPath  string
		wantErr   string
		noRequest bool
	}{
		{name: "matching record", fn: configMap(strings.Replace(admin.srv.URL, "https://", "HTTPS://", 1) + "/"), wantPath: wantPath},
		{name: "CA file from the kubeconfig", cluster: "    certificate-authority: ca.pem\n", fn: configMap(admin.srv.URL), wantPath: wantPath},
		{name: "other namespace", namespace: "dc-ns", fn: configMap(admin.srv.URL), wantPath: "/api/v1/namespaces/dc-ns/configmaps/" + KubeEndpointConfigMap},
		{name: "mismatch", fn: configMap("https://other.example.test"), wantErr: "publishes the launcher endpoint https://other.example.test:443, not " + adminNorm + ", so no Kubernetes credential is sent to " + adminNorm + "; use --admin-url https://other.example.test:443, or ask your administrator to fix the endpoint record"},
		{name: "no record", fn: func(w http.ResponseWriter, r *http.Request) { http.Error(w, r.Header.Get("Authorization"), 404) }, wantErr: "the cluster at " + apiNorm + " has no launcher endpoint record (ConfigMap defenseclaw-launcher-endpoint in namespace defenseclaw-system), so no Kubernetes credential is sent to " + adminNorm + "; ask your administrator to publish the endpoint record"},
		{name: "forbidden", fn: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden "+r.Header.Get("Authorization"), 403)
		}, wantErr: `the kubeconfig user "alice" may not read the endpoint record (ConfigMap defenseclaw-launcher-endpoint in namespace defenseclaw-system) on ` + apiNorm + " (HTTP 403); check you may read ConfigMaps in that namespace"},
		{name: "unauthorized", fn: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) }, wantErr: "did not accept the credential of the kubeconfig user \"alice\" (HTTP 401)"},
		{name: "redirect refused", fn: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, admin.srv.URL+wantPath, http.StatusFound)
		}, wantErr: "answered with a redirect (HTTP 302), which the launcher does not follow"},
		{name: "record without admin_url", fn: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"data": map[string]string{}})
		}, wantErr: "has no admin_url; ask your administrator to publish the endpoint record"},
		{name: "record with credentials", fn: configMap("https://u:pw@admin.example.test"), wantErr: "must not carry a user name or password"},
		{name: "not a ConfigMap", fn: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }, wantErr: "is not a ConfigMap"},
		{name: "wrong CA refused", cluster: "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(otherCA(t)) + "\n", wantErr: "presented a certificate the kubeconfig's certificate authority does not trust, so no credential was sent", noRequest: true},
		{name: "insecure-skip-tls-verify refused", cluster: "    insecure-skip-tls-verify: true\n", wantErr: `the kube cluster "c1" sets insecure-skip-tls-verify; the launcher does not send a Kubernetes credential`, noRequest: true},
		{name: "plain http server refused", server: "http://k8s.example.test:6443", wantErr: `the server of the kube cluster "c1" must be an https URL`, noRequest: true},
		{name: "bad namespace", namespace: "Bad_NS", wantErr: `kube_namespace "Bad_NS" is not a valid Kubernetes namespace name`, noRequest: true},
		{name: "API server too slow", timeout: 50 * time.Millisecond, fn: func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, wantErr: "did not answer within 50ms"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api.mu.Lock()
			api.calls, api.auth, api.paths, api.fn = 0, nil, nil, tc.fn
			api.mu.Unlock()
			server, cluster := api.srv.URL, caData
			if tc.server != "" {
				server = tc.server
			}
			if tc.cluster != "" {
				cluster = tc.cluster
			}
			cfg := writeFile(t, dir, "config", apiKubeconfig(server, cluster))
			pin, err := KubeVerifyEndpoint(context.Background(), KubeOptions{Kubeconfig: cfg, Env: emptyEnv, apiTimeoutT: tc.timeout}, admin.srv.URL, tc.namespace)
			if admin.count() != 0 {
				t.Fatal("the admin listener was contacted during the endpoint check")
			}
			if tc.noRequest && api.count() != 0 {
				t.Fatalf("API server got %d requests", api.count())
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v\nwant %q", err, tc.wantErr)
				}
				noSecret(t, err, kubeBearer, "pw@", "Bearer")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if pin != (KubePin{Server: apiNorm, AdminURL: adminNorm, Principal: "alice"}) {
				t.Fatalf("pin = %+v", pin)
			}
			api.mu.Lock()
			seen, auth, paths := api.calls, append([]string(nil), api.auth...), append([]string(nil), api.paths...)
			api.mu.Unlock()
			if seen != 1 || auth[0] != "Bearer "+kubeBearer || paths[0] != tc.wantPath {
				t.Fatalf("API server saw %d %q", seen, paths)
			}
			// The pinned context hands out the bearer.
			c := Context{AdminURL: admin.srv.URL, Kube: true}.WithKubePin(pin)
			got, err := NewSource("e1", c, nil, SourceOptions{Kube: &KubeOptions{Kubeconfig: cfg, Env: emptyEnv}}).Token(context.Background())
			if err != nil || got != kubeBearer {
				t.Fatalf("pinned source: %v", err)
			}
		})
	}
}

func TestKubePinAtUse(t *testing.T) {
	setHome(t)
	dir := t.TempDir()
	two := func(current string) string {
		return "current-context: " + current + "\nclusters:\n- {name: c1, cluster: {server: \"https://k8s.example.test:6443\"}}\n- {name: c2, cluster: {server: \"https://k8s-other.example.test\"}}\n" +
			"contexts:\n- {name: e1, context: {cluster: c1, user: plug}}\n- {name: e2, context: {cluster: c2, user: plug}}\n" +
			"users:\n- name: plug\n  user:\n    exec: {apiVersion: " + kubeExecV1 + ", command: /opt/example/get-token}\n"
	}
	cfg := writeFile(t, dir, "config", two("e1"))
	pinned := Context{AdminURL: "https://admin.example.test", Kube: true, KubePinAdminURL: "https://admin.example.test:443", KubePinServer: "https://k8s.example.test:6443"}
	f, _ := LoadContexts()
	f.Contexts["k"], f.Current = pinned, "k"
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	verified := "this sign-in was verified for https://admin.example.test:443 on https://k8s.example.test:6443, not for "
	tests := []struct {
		name    string
		env     map[string]string
		ctx     func(Context) Context
		current string
		wantErr string
	}{
		{name: "pinned", ctx: func(c Context) Context { return c }},
		{name: "admin URL spelled differently", ctx: func(c Context) Context { c.AdminURL = "HTTPS://Admin.Example.test:443/"; return c }},
		{name: "env override of admin_url", env: map[string]string{EnvAdminURL: "https://elsewhere.example.test"}, wantErr: verified + "https://elsewhere.example.test:443 on https://k8s.example.test:6443, so no Kubernetes credential is sent; run: defenseclaw substrate login --kube again"},
		{name: "context edited", ctx: func(c Context) Context { c.AdminURL = "https://admin.example.test:8443"; return c }, wantErr: verified + "https://admin.example.test:8443 on"},
		{name: "kubeconfig switched cluster", current: "e2", wantErr: verified + "https://admin.example.test:443 on https://k8s-other.example.test:443"},
		{name: "no pin", ctx: func(c Context) Context { c.KubePinServer, c.KubePinAdminURL = "", ""; return c }, wantErr: "this kube context was not verified against the cluster's launcher endpoint record, so no Kubernetes credential is sent; run: defenseclaw substrate login --kube again; there is no override"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, dir, "config", two("e1"))
			_, c, err := resolveContext("", func(k string) string { return tc.env[k] })
			if err != nil {
				t.Fatal(err)
			}
			if tc.ctx != nil {
				c = tc.ctx(c)
			}
			fe := &fakeExec{fn: answer(kubeExecV1, map[string]any{"token": "exec-tok-marker"})}
			src := NewSource("k", c, nil, SourceOptions{Kube: &KubeOptions{Kubeconfig: cfg, Env: emptyEnv, RunExec: fe.run}})
			got, err := src.Token(context.Background())
			if tc.current != "" {
				// A kept token is not handed out after the switch either.
				if err != nil || got != "exec-tok-marker" {
					t.Fatalf("before the switch: %v", err)
				}
				writeFile(t, dir, "config", two(tc.current))
				got, err = src.Token(context.Background())
			}
			if tc.wantErr == "" {
				if err != nil || got != "exec-tok-marker" {
					t.Fatalf("token handed out: %t, %v", got != "", err)
				}
				return
			}
			if err == nil || got != "" || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, ErrNotSignedIn) {
				t.Fatalf("token handed out: %t, err = %v\nwant %q", got != "", err, tc.wantErr)
			}
			if tc.current == "" && fe.calls != 0 {
				t.Fatal("the plugin ran for a refused context")
			}
			if cur, err := src.Current(context.Background()); cur != nil || err == nil {
				t.Fatal("Current handed out a token")
			}
			noSecret(t, err, "exec-tok-marker")
		})
	}
}

func TestNormEndpoint(t *testing.T) {
	tests := []struct{ in, want, wantErr string }{
		{in: "https://admin.example.test", want: "https://admin.example.test:443"},
		{in: "HTTPS://Admin.Example.TEST:443/", want: "https://admin.example.test:443"},
		{in: "https://admin.example.test:8443/dc/", want: "https://admin.example.test:8443/dc"},
		{in: "https://admin.example.test/DC", want: "https://admin.example.test:443/DC"},
		{in: "http://localhost", want: "http://localhost:80"},
		{in: "https://[::1]:9443", want: "https://[::1]:9443"},
		{in: "https://203.0.113.7", want: "https://203.0.113.7:443"},
		{in: "https://u:pw@admin.example.test", wantErr: "must not carry a user name or password"},
		{in: "https://admin.example.test/?x=1", wantErr: "must not have a query"},
		{in: "ftp://admin.example.test", wantErr: "must be an https URL"},
		{in: "https://", wantErr: "needs a host"},
	}
	for _, tc := range tests {
		got, err := normEndpoint(tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || strings.Contains(err.Error(), "pw") {
				t.Errorf("%q: err = %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	a, _ := normEndpoint("https://admin.example.test")
	b, _ := normEndpoint("https://admin.example.test:8443")
	if a == b {
		t.Error("different ports compare equal")
	}
}

func TestKubePinFields(t *testing.T) {
	c := Context{AdminURL: "https://admin.example.test", Kube: true, KubeNamespace: "dc-ns"}.WithKubePin(KubePin{Server: "https://k8s.example.test:443", AdminURL: "https://admin.example.test:443", Principal: "alice"})
	b, _ := json.Marshal(c)
	for _, k := range []string{`"kube_namespace":"dc-ns"`, `"kube_pin_server":"https://k8s.example.test:443"`, `"kube_pin_admin_url":"https://admin.example.test:443"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("%s missing in %s", k, b)
		}
	}
	if strings.Contains(string(b), "alice") || c.KubeNamespaceOrDefault() != "dc-ns" || (Context{}).KubeNamespaceOrDefault() != DefaultKubeNamespace {
		t.Errorf("pin fields: %s", b)
	}
	if err := (Context{AdminURL: "https://admin.example.test", Kube: true, KubeNamespace: "Bad_NS"}).Validate(false); err == nil {
		t.Error("bad namespace accepted")
	}
}
