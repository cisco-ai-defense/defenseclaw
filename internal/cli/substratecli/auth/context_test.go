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
	for _, k := range []string{EnvContext, EnvAdminURL, EnvIssuer, EnvClientID, EnvRouterURL, EnvTokenStore} {
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
		Scopes: []string{"openid", "groups"}, RouterURL: "https://router.example.test:8444", RouterCAFile: "/r.pem",
		RouterCertFile: "/c.pem", RouterKeyFile: "/k.pem", RelayPort: 8080, WorkloadAudience: "defenseclaw",
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
	for _, k := range []string{"admin_url", "admin_ca_file", "issuer", "issuer_ca_file", "client_id", "scopes", "router_url", "router_ca_file", "router_cert_file", "router_key_file", "relay_port", "workload_audience"} {
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

func TestResolveContext(t *testing.T) {
	setHome(t)
	f, _ := LoadContexts()
	f.Contexts["a"] = Context{AdminURL: "https://a.example.test", Issuer: "https://idp.example.test/realms/a", ClientID: "c"}
	f.Contexts["b"] = Context{AdminURL: "https://b.example.test"}
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
		wantErr    string
	}{
		{name: "current", wantName: "a", wantAdmin: "https://a.example.test"},
		{name: "env beats current", env: map[string]string{EnvContext: "b"}, wantName: "b", wantAdmin: "https://b.example.test"},
		{name: "flag beats env", flag: "a", env: map[string]string{EnvContext: "b"}, wantName: "a", wantAdmin: "https://a.example.test"},
		{name: "env overrides", env: map[string]string{EnvAdminURL: "https://ci.example.test", EnvIssuer: "https://idp2.example.test/r"}, wantName: "a", wantAdmin: "https://ci.example.test", wantIssuer: "https://idp2.example.test/r"},
		{name: "unknown name", flag: "zz", wantErr: `substrate context "zz" (from the --context flag) does not exist; run: defenseclaw substrate login --context zz --admin-url URL`},
		{name: "unknown name with env admin", flag: "ci", env: map[string]string{EnvAdminURL: "https://ci.example.test"}, wantName: "ci", wantAdmin: "https://ci.example.test"},
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
			if name != tc.wantName || c.AdminURL != tc.wantAdmin || (tc.wantIssuer != "" && c.Issuer != tc.wantIssuer) {
				t.Errorf("got %s %+v", name, c)
			}
		})
	}
}

func TestResolveContextEmpty(t *testing.T) {
	setHome(t)
	_, _, err := ResolveContext("")
	if err == nil || !strings.Contains(err.Error(), "run: defenseclaw substrate login --admin-url URL") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv(EnvAdminURL, "https://ci.example.test")
	name, c, err := ResolveContext("")
	if err != nil || name != "default" || c.AdminURL != "https://ci.example.test" {
		t.Fatalf("env-only: %s %+v %v", name, c, err)
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
		{name: "ftp", c: mod(func(c *Context) { c.RouterURL = "ftp://r.example.test" }), wantErr: "router_url must be an https URL"},
		{name: "no host", c: mod(func(c *Context) { c.AdminURL = "https://" }), wantErr: "needs a host"},
		{name: "query", c: mod(func(c *Context) { c.Issuer = "https://idp.example.test/r?x=1" }), wantErr: "must not have a query"},
		{name: "need issuer", c: mod(func(c *Context) { c.Issuer = "" }), needIssuer: true, wantErr: "issuer is not set"},
		{name: "issuer optional", c: mod(func(c *Context) { c.Issuer = ""; c.ClientID = "" })},
		{name: "need client", c: mod(func(c *Context) { c.ClientID = "" }), needIssuer: true, wantErr: "client_id is not set"},
		{name: "port", c: mod(func(c *Context) { c.RelayPort = 70000 }), wantErr: "relay_port 70000"},
		{name: "cert without key", c: mod(func(c *Context) { c.RouterCertFile = "/c.pem" }), wantErr: "must be set together"},
		{name: "bad scope", c: mod(func(c *Context) { c.Scopes = []string{"openid email"} }), wantErr: "scope"},
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
