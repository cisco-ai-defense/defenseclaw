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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func setHome(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", d)
	for _, k := range []string{EnvContext, EnvAdminURL, EnvIssuer, EnvClientID, EnvWorkloadAudience, EnvTokenStore, EnvKube} {
		t.Setenv(k, "")
	}
	return d
}

func TestContextFileRoundTrip(t *testing.T) {
	home := setHome(t)
	if StateDir() != home || ContextsPath() != filepath.Join(home, "substrate", "contexts.json") {
		t.Fatalf("paths: %s %s", StateDir(), ContextsPath())
	}
	f, err := LoadContexts()
	if err != nil || len(f.Contexts) != 0 || f.Current != "" {
		t.Fatalf("missing file: %v %+v", err, f)
	}
	want := Context{
		AdminURL: "https://admin.example.test:9443", AdminCAFile: "/ca.pem",
		Issuer: "https://idp.example.test:8443/realms/defenseclaw", IssuerCAFile: "/ca.pem", ClientID: "defenseclaw-launcher",
		Scopes: []string{"openid", "groups"}, WorkloadAudience: "defenseclaw", Profile: "dev", Template: "base",
	}
	f.Contexts["e1"] = want
	f.Current = "e1"
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := LoadContexts()
	if err != nil || got.Current != "e1" || !reflect.DeepEqual(got.Contexts["e1"], want) {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	raw, _ := os.ReadFile(ContextsPath())
	var keys map[string]map[string]map[string]any
	_ = json.Unmarshal(raw, &keys)
	for _, k := range []string{"admin_url", "admin_ca_file", "issuer", "issuer_ca_file", "client_id", "scopes", "workload_audience", "profile", "template"} {
		if _, ok := keys["contexts"]["e1"][k]; !ok {
			t.Errorf("json key %s missing", k)
		}
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(ContextsPath())
		di, _ := os.Stat(filepath.Dir(ContextsPath()))
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Errorf("modes: file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(ContextsPath()))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temp file left: %s", e.Name())
		}
	}
	f.Current = "missing"
	if err := f.Save(); err == nil {
		t.Error("saved a current context that does not exist")
	}
	if err := os.WriteFile(ContextsPath(), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadContexts(); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("bad file: %v", err)
	}
}

// TestContextFileDropsRouterKeys: a file from a build that still had the
// router fields loads, and the next save drops them.
func TestContextFileDropsRouterKeys(t *testing.T) {
	setHome(t)
	old := `{"current":"e1","contexts":{"e1":{"admin_url":"https://admin.example.test:9443",` +
		`"router_url":"https://router.example.test:8444","router_ca_file":"/r.pem","router_cert_file":"/c.pem",` +
		`"router_key_file":"/k.pem","relay_port":8080,"workload_audience":"dc-e1"}}}`
	if err := os.MkdirAll(filepath.Dir(ContextsPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ContextsPath(), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadContexts()
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Contexts["e1"]; f.Current != "e1" || got.AdminURL != "https://admin.example.test:9443" || got.WorkloadAudience != "dc-e1" {
		t.Fatalf("loaded %+v", f)
	}
	name, c, err := resolveContext("", emptyEnv)
	if err != nil || name != "e1" || c.AdminURL != "https://admin.example.test:9443" {
		t.Fatalf("resolve: %s %+v %v", name, c, err)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(ContextsPath())
	for _, k := range []string{"router_url", "router_ca_file", "router_cert_file", "router_key_file", "relay_port"} {
		if strings.Contains(string(raw), `"`+k+`"`) {
			t.Errorf("saved file still has %s", k)
		}
	}
}

func TestResolveContext(t *testing.T) {
	setHome(t)
	f, _ := LoadContexts()
	f.Contexts["a"] = Context{AdminURL: "https://a.example.test", Issuer: "https://idp.example.test/realms/a", ClientID: "c"}
	f.Contexts["b"] = Context{AdminURL: "https://b.example.test", WorkloadAudience: "dc-b"}
	f.Current = "a"
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, flag string
		env        map[string]string
		wantName   string
		wantAdmin  string
		wantIssuer string
		wantAud    string
		wantErr    string
	}{
		{name: "current", wantName: "a", wantAdmin: "https://a.example.test"},
		{name: "env beats current", env: map[string]string{EnvContext: "b"}, wantName: "b", wantAdmin: "https://b.example.test", wantAud: "dc-b"},
		{name: "flag beats env", flag: "a", env: map[string]string{EnvContext: "b"}, wantName: "a", wantAdmin: "https://a.example.test"},
		{name: "env overrides", env: map[string]string{EnvAdminURL: "https://ci.example.test", EnvIssuer: "https://idp2.example.test/r"}, wantName: "a", wantAdmin: "https://ci.example.test", wantIssuer: "https://idp2.example.test/r"},
		{name: "env audience", flag: "b", env: map[string]string{EnvWorkloadAudience: "dc-ci"}, wantName: "b", wantAdmin: "https://b.example.test", wantAud: "dc-ci"},
		{name: "unknown name", flag: "zz", wantErr: `there is no cluster named "zz" (from the --context flag); sign in to it with: defenseclaw substrate login --name zz --admin-url https://HOST:PORT`},
		{name: "unknown name with env admin", flag: "ci", env: map[string]string{EnvAdminURL: "https://ci.example.test", EnvWorkloadAudience: "dc-ci"}, wantName: "ci", wantAdmin: "https://ci.example.test", wantAud: "dc-ci"},
		{name: "bad override", env: map[string]string{EnvAdminURL: "http://ci.example.test"}, wantErr: "admin_url must use https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, c, err := resolveContext(tc.flag, func(k string) string { return tc.env[k] })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.wantName || c.AdminURL != tc.wantAdmin || (tc.wantIssuer != "" && c.Issuer != tc.wantIssuer) || c.WorkloadAudience != tc.wantAud {
				t.Errorf("got %s %+v", name, c)
			}
		})
	}
}

func TestResolveContextEmpty(t *testing.T) {
	setHome(t)
	_, _, err := ResolveContext("")
	if err == nil || !strings.Contains(err.Error(), "run: defenseclaw substrate login --admin-url https://HOST:PORT") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv(EnvAdminURL, "https://ci.example.test")
	name, c, err := ResolveContext("")
	if err != nil || name != "default" || c.AdminURL != "https://ci.example.test" {
		t.Fatalf("env-only: %s %+v %v", name, c, err)
	}
	if got := c.workloadAudience(); got != DefaultWorkloadAudience {
		t.Errorf("default audience = %q", got)
	}
}

func TestResolveContextKube(t *testing.T) {
	setHome(t)
	f, _ := LoadContexts()
	want := Context{AdminURL: "https://k.example.test", Kube: true, Kubeconfig: "/kube/config", KubeContext: "dev"}
	f.Contexts["k"] = want
	f.Contexts["o"] = Context{AdminURL: "https://o.example.test", Issuer: "https://idp.example.test/realms/o", ClientID: "c"}
	f.Current = "k"
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	name, c, err := resolveContext("", emptyEnv)
	if err != nil || name != "k" || !reflect.DeepEqual(c, want) {
		t.Fatalf("kube context: %s %+v %v", name, c, err)
	}
	if o := c.KubeOptions(); o.Kubeconfig != "/kube/config" || o.Context != "dev" {
		t.Errorf("KubeOptions = %+v", o)
	}
	b, _ := os.ReadFile(ContextsPath())
	if !strings.Contains(string(b), `"kube_context": "dev"`) || !strings.Contains(string(b), `"kube": true`) {
		t.Errorf("saved file: %s", b)
	}
	tests := []struct {
		name, flag, kube string
		want             bool
		wantErr          string
	}{
		{name: "env on", flag: "o", kube: "1", want: true},
		{name: "env off", flag: "k", kube: "0", want: false},
		{name: "env bad", flag: "k", kube: "maybe", wantErr: EnvKube + `="maybe" is not valid`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, c, err := resolveContext(tc.flag, func(k string) string { return map[string]string{EnvKube: tc.kube}[k] })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || c.Kube != tc.want {
				t.Fatalf("kube = %v, err %v", c.Kube, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	ok := Context{AdminURL: "https://admin.example.test", Issuer: "https://idp.example.test/realms/r", ClientID: "c"}
	mod := func(f func(*Context)) Context { c := ok; f(&c); return c }
	tests := []struct {
		name       string
		c          Context
		needIssuer bool
		wantErr    string
	}{
		{name: "ok", c: ok, needIssuer: true},
		{name: "loopback http", c: mod(func(c *Context) { c.AdminURL = "http://127.0.0.1:9000"; c.Issuer = "http://localhost:8080/r" }), needIssuer: true},
		{name: "ipv6 loopback", c: mod(func(c *Context) { c.AdminURL = "http://[::1]:9000" })},
		{name: "no admin", c: mod(func(c *Context) { c.AdminURL = "" }), wantErr: "admin_url is not set"},
		{name: "http admin", c: mod(func(c *Context) { c.AdminURL = "http://admin.example.test" }), wantErr: "admin_url must use https"},
		{name: "credentials", c: mod(func(c *Context) { c.AdminURL = "https://u:pw-marker@admin.example.test" }), wantErr: "must not carry a user name or password"},
		{name: "ftp", c: mod(func(c *Context) { c.AdminURL = "ftp://admin.example.test" }), wantErr: "admin_url must be an https URL"},
		{name: "no host", c: mod(func(c *Context) { c.AdminURL = "https://" }), wantErr: "needs a host"},
		{name: "query", c: mod(func(c *Context) { c.Issuer = "https://idp.example.test/r?x=1" }), wantErr: "must not have a query"},
		{name: "need issuer", c: mod(func(c *Context) { c.Issuer = "" }), needIssuer: true, wantErr: "issuer is not set"},
		{name: "issuer optional", c: mod(func(c *Context) { c.Issuer = ""; c.ClientID = "" })},
		{name: "need client", c: mod(func(c *Context) { c.ClientID = "" }), needIssuer: true, wantErr: "client_id is not set"},
		{name: "audience url", c: mod(func(c *Context) { c.WorkloadAudience = "https://dc-e1.example.test" })},
		{name: "audience with space", c: mod(func(c *Context) { c.WorkloadAudience = "dc e1" }), wantErr: `workload_audience "dc e1" is not valid`},
		{name: "audience blank", c: mod(func(c *Context) { c.WorkloadAudience = "  " }), wantErr: "workload_audience"},
		{name: "bad scope", c: mod(func(c *Context) { c.Scopes = []string{"openid email"} }), wantErr: "scope"},
		{name: "kube admin only", c: Context{AdminURL: "https://admin.example.test", Kube: true}, needIssuer: true},
		{name: "kube ignores issuer fields", c: Context{AdminURL: "https://admin.example.test", Kube: true, Issuer: "not a url", Scopes: []string{"a b"}}, needIssuer: true},
		{name: "kube needs admin", c: Context{Kube: true}, wantErr: "admin_url is not set"},
		{name: "kube context name", c: Context{AdminURL: "https://admin.example.test", Kube: true, KubeContext: "dev\nx"}, wantErr: "kube_context"},
		{name: "kubeconfig one path", c: Context{AdminURL: "https://admin.example.test", Kube: true, Kubeconfig: "/a\n/b"}, wantErr: "kubeconfig must be one file path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate(tc.needIssuer)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			noSecret(t, err, "pw-marker")
		})
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"e1", "prod.us-east_1", "A"} {
		if ValidName(n) != nil {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "-x", "a b", "a/b", "..", strings.Repeat("a", 64), "a\"b"} {
		if ValidName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
}
