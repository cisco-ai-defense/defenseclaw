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
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Markers that must never reach an error.
var kubeSecrets = []string{"static-tok-marker", "file-tok-marker", "exec-tok-marker", "exec-out-marker", "pw-marker", "legacy-id-marker", "S0VZLW1hcmtlcg", "yaml-leak-marker", "eyJ"}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeExec records the plugin runs and answers with fn.
type fakeExec struct {
	mu    sync.Mutex
	calls int
	name  string
	args  []string
	env   []string
	fn    func(ctx context.Context, n int) ([]byte, error)
}

func (f *fakeExec) run(ctx context.Context, name string, args, env []string, stdin []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.name, f.args, f.env = name, args, env
	fn := f.fn
	f.mu.Unlock()
	if stdin != nil {
		return nil, errors.New("stdin given to a non-interactive plugin")
	}
	return fn(ctx, n)
}

func (f *fakeExec) execInfo(t *testing.T) execInfo {
	t.Helper()
	var info execInfo
	n := 0
	for _, kv := range f.env {
		if v, ok := strings.CutPrefix(kv, kubeExecInfoEnv+"="); ok {
			n++
			if err := json.Unmarshal([]byte(v), &info); err != nil {
				t.Fatalf("KUBERNETES_EXEC_INFO is not JSON: %v", err)
			}
		}
	}
	if n != 1 {
		t.Fatalf("KUBERNETES_EXEC_INFO set %d times", n)
	}
	return info
}

func answer(api string, status map[string]any) func(context.Context, int) ([]byte, error) {
	return func(context.Context, int) ([]byte, error) {
		m := map[string]any{"kind": "ExecCredential", "status": status}
		if api != "" {
			m["apiVersion"] = api
		}
		return json.Marshal(m)
	}
}

const kubeBase = `apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: c1
  cluster:
    server: https://k8s.example.test:6443
    certificate-authority-data: Q0EtREFUQQ==
contexts:
- {name: dev, context: {cluster: c1, user: alice}}
- {name: ops, context: {cluster: c1, user: filer}}
- {name: both, context: {cluster: c1, user: both}}
- {name: cert, context: {cluster: c1, user: certy}}
- {name: certfile, context: {cluster: c1, user: certf}}
- {name: legacy, context: {cluster: c1, user: old}}
- {name: basic, context: {cluster: c1, user: bob}}
- {name: none, context: {cluster: c1, user: empty}}
- {name: ghost, context: {cluster: c1, user: nobody}}
- {name: nouser, context: {cluster: c1}}
- {name: lost, context: {cluster: c1, user: lostfile}}
users:
- {name: alice, user: {token: static-tok-marker}}
- {name: filer, user: {tokenFile: tok.txt}}
- {name: both, user: {token: static-tok-marker, tokenFile: missing.txt}}
- {name: certy, user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZLW1hcmtlcg==}}
- {name: certf, user: {client-certificate: c.pem, client-key: k.pem}}
- name: old
  user:
    auth-provider: {name: oidc, config: {id-token: legacy-id-marker}}
- {name: bob, user: {username: bob, password: pw-marker}}
- {name: empty, user: {}}
- {name: lostfile, user: {tokenFile: missing.txt}}
`

func TestKubeLogin(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config", kubeBase)
	writeFile(t, dir, "tok.txt", "file-tok-marker\n")
	noCurrent := writeFile(t, dir, "nocurrent", "contexts:\n- {name: a, context: {user: alice}}\nusers:\n- {name: alice, user: {token: static-tok-marker}}\n")
	badYAML := writeFile(t, dir, "bad", "users: [ {name: a, user: {token: yaml-leak-marker}\n")
	badType := writeFile(t, dir, "badtype", "clusters:\n- name: c\n  cluster: {insecure-skip-tls-verify: yaml-leak-marker}\n")
	tests := []struct {
		name, file, ctx string
		wantTok, wantP  string
		wantErr         string
	}{
		{name: "token user", file: cfg, wantTok: "static-tok-marker", wantP: "alice"},
		{name: "named context tokenFile", file: cfg, ctx: "ops", wantTok: "file-tok-marker", wantP: "filer"},
		{name: "token when tokenFile is gone", file: cfg, ctx: "both", wantTok: "static-tok-marker", wantP: "both"},
		{name: "tokenFile missing", file: cfg, ctx: "lost", wantErr: `the tokenFile of the kubeconfig user "lostfile" (` + filepath.Join(dir, "missing.txt") + `) does not exist`},
		{name: "cert data refused", file: cfg, ctx: "cert", wantErr: `the kubeconfig user "certy" signs in with a client certificate; ` + kubeCertRefusal},
		{name: "cert file refused", file: cfg, ctx: "certfile", wantErr: kubeCertRefusal},
		{name: "legacy auth-provider refused", file: cfg, ctx: "legacy", wantErr: `legacy auth-provider "oidc", which the launcher does not support`},
		{name: "basic refused", file: cfg, ctx: "basic", wantErr: "does not support basic sign-in"},
		{name: "no credential", file: cfg, ctx: "none", wantErr: `the kubeconfig user "empty" has no token, tokenFile or exec plugin`},
		{name: "user not defined", file: cfg, ctx: "ghost", wantErr: `names the user "nobody", which the kubeconfig ` + cfg + ` does not define`},
		{name: "context without user", file: cfg, ctx: "nouser", wantErr: `the kube context "nouser" names no user`},
		{name: "context missing", file: cfg, ctx: "zz", wantErr: `has no context "zz" (named by kube_context)`},
		{name: "current-context missing", file: noCurrent, wantErr: "has no current-context; pick one with: kubectl config use-context NAME"},
		{name: "file missing", file: filepath.Join(dir, "nope"), wantErr: "does not exist; point KUBECONFIG"},
		{name: "invalid YAML", file: badYAML, wantErr: "is not a valid kubeconfig (at line"},
		{name: "wrong type", file: badType, wantErr: "is not a valid kubeconfig"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := KubeLogin(context.Background(), KubeOptions{Kubeconfig: tc.file, Context: tc.ctx, Env: emptyEnv})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				noSecret(t, err, kubeSecrets...)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tok.AccessToken != tc.wantTok || tok.Principal != tc.wantP || tok.Kind != KindKube || tok.Subject != "" || tok.RefreshToken != "" {
				t.Fatalf("token = %v (access %t)", tok, tok.AccessToken == tc.wantTok)
			}
			if strings.Contains(tok.String(), tc.wantTok) {
				t.Fatal("String shows the token")
			}
		})
	}
}

func TestKubeconfigMerge(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", `current-context: one
contexts:
- {name: one, context: {user: u1}}
- {name: shared, context: {user: u1}}
users:
- {name: u1, user: {token: tok-from-a}}
`)
	b := writeFile(t, dir, "b.yaml", `current-context: two
contexts:
- {name: two, context: {user: u2}}
- {name: shared, context: {user: u2}}
users:
- {name: u1, user: {token: tok-from-b}}
- {name: u2, user: {token: tok2-from-b}}
`)
	missing := filepath.Join(dir, "missing.yaml")
	list := strings.Join([]string{missing, a, "", b}, string(filepath.ListSeparator))
	home := t.TempDir()
	writeFile(t, home, filepath.Join(".kube", "config"), "current-context: h\ncontexts:\n- {name: h, context: {user: hu}}\nusers:\n- {name: hu, user: {token: tok-from-home}}\n")
	tests := []struct {
		name    string
		env     map[string]string
		file    string
		ctx     string
		want    string
		wantErr string
	}{
		{name: "first current-context wins", env: map[string]string{"KUBECONFIG": list}, want: "tok-from-a"},
		{name: "context only in the second file", env: map[string]string{"KUBECONFIG": list}, ctx: "two", want: "tok2-from-b"},
		{name: "first definition wins", env: map[string]string{"KUBECONFIG": list}, ctx: "shared", want: "tok-from-a"},
		{name: "explicit file beats KUBECONFIG", env: map[string]string{"KUBECONFIG": list}, file: b, want: "tok2-from-b"},
		{name: "home default", env: map[string]string{"HOME": home, "USERPROFILE": home}, want: "tok-from-home"},
		{name: "tilde path", env: map[string]string{"HOME": home, "USERPROFILE": home}, file: "~/.kube/config", want: "tok-from-home"},
		{name: "none of the list exists", env: map[string]string{"KUBECONFIG": missing}, wantErr: "none of the kubeconfig files in KUBECONFIG exist"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := KubeLogin(context.Background(), KubeOptions{Kubeconfig: tc.file, Context: tc.ctx, Env: func(k string) string { return tc.env[k] }})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || tok.AccessToken != tc.want {
				t.Fatalf("got %v, %v; want %s", tok, err, tc.want)
			}
		})
	}
}

func execKubeconfig(api, extra string) string {
	return `current-context: x
clusters:
- name: c1
  cluster: {server: "https://k8s.example.test:6443", certificate-authority-data: Q0EtREFUQQ==, tls-server-name: k8s.example.test}
contexts:
- {name: x, context: {cluster: c1, user: plug}}
users:
- name: plug
  user:
    exec:
      apiVersion: ` + api + `
      command: /opt/example/get-token
      args: ["--cluster", "e1"]
      env: [{name: PLUGIN_MODE, value: test}, {name: KUBERNETES_EXEC_INFO, value: overridden}]
      provideClusterInfo: true
      installHint: "install get-token from the vendor"
` + extra
}

func TestKubeExec(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	exp := clk.Now().Add(time.Hour).UTC().Truncate(time.Second)
	expS := exp.Format(time.RFC3339)
	jwtish := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	tests := []struct {
		name      string
		api       string
		extra     string
		fn        func(context.Context, int) ([]byte, error)
		timeout   time.Duration
		wantExp   time.Time
		wantErr   string
		notCalled bool
	}{
		{name: "v1 with expiry", api: kubeExecV1, fn: answer(kubeExecV1, map[string]any{"token": "exec-tok-marker", "expirationTimestamp": expS}), wantExp: exp},
		{name: "v1beta1 without expiry", api: kubeExecV1beta1, fn: answer("", map[string]any{"token": "exec-tok-marker"})},
		{name: "plugin fails", api: kubeExecV1, fn: func(context.Context, int) ([]byte, error) {
			return nil, errors.New("error: refresh failed for " + jwtish + " and abcdefghijklmnopqrstuvwxyz0123\nsecond line exec-out-marker")
		}, wantErr: `the exec plugin "/opt/example/get-token" of the kubeconfig user "plug" failed: error: refresh failed for [hidden] and [hidden]`},
		{name: "plugin times out", api: kubeExecV1, timeout: 20 * time.Millisecond, fn: func(ctx context.Context, _ int) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, wantErr: "did not answer within 20ms"},
		{name: "plugin not found", api: kubeExecV1, fn: func(context.Context, int) ([]byte, error) {
			return nil, &exec.Error{Name: "get-token", Err: exec.ErrNotFound}
		}, wantErr: "was not found; install get-token from the vendor"},
		{name: "invalid JSON", api: kubeExecV1, fn: func(context.Context, int) ([]byte, error) { return []byte("not json exec-out-marker"), nil }, wantErr: "printed something that is not an ExecCredential JSON object"},
		{name: "certificate only", api: kubeExecV1, fn: answer(kubeExecV1, map[string]any{"clientCertificateData": "CERT", "clientKeyData": "S0VZLW1hcmtlcg=="}), wantErr: "returned only a client certificate; " + kubeCertRefusal},
		{name: "no token", api: kubeExecV1, fn: answer(kubeExecV1, map[string]any{}), wantErr: "returned no token"},
		{name: "no status", api: kubeExecV1, fn: func(context.Context, int) ([]byte, error) { return []byte(`{"kind":"ExecCredential"}`), nil }, wantErr: "without a status"},
		{name: "version mismatch", api: kubeExecV1, fn: answer(kubeExecV1beta1, map[string]any{"token": "exec-tok-marker"}), wantErr: `answered with apiVersion "client.authentication.k8s.io/v1beta1"`},
		{name: "already expired", api: kubeExecV1, fn: answer(kubeExecV1, map[string]any{"token": "exec-tok-marker", "expirationTimestamp": clk.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}), wantErr: "returned a token that expired at"},
		{name: "bad timestamp", api: kubeExecV1, fn: answer(kubeExecV1, map[string]any{"token": "exec-tok-marker", "expirationTimestamp": "tomorrow"}), wantErr: "not an RFC 3339 time"},
		{name: "two-line token", api: kubeExecV1, fn: answer(kubeExecV1, map[string]any{"token": "exec-tok-marker\nmore"}), wantErr: "not a single token"},
		{name: "v1alpha1 refused", api: "client.authentication.k8s.io/v1alpha1", wantErr: `uses apiVersion "client.authentication.k8s.io/v1alpha1", which the launcher does not support`, notCalled: true},
		{name: "no apiVersion", api: `""`, wantErr: "has no apiVersion", notCalled: true},
		{name: "interactive Always refused", api: kubeExecV1, extra: "      interactiveMode: Always\n", wantErr: "needs a terminal (interactiveMode: Always)", notCalled: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeFile(t, dir, strings.ReplaceAll(tc.name, " ", "-"), execKubeconfig(tc.api, tc.extra))
			fe := &fakeExec{fn: tc.fn}
			tok, err := KubeLogin(context.Background(), KubeOptions{Kubeconfig: cfg, Env: emptyEnv, RunExec: fe.run, Now: clk.Now, execTimeout: tc.timeout})
			if tc.notCalled != (fe.calls == 0) {
				t.Fatalf("plugin runs = %d", fe.calls)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				noSecret(t, err, append(kubeSecrets, "abcdefghijklmnopqrstuvwxyz", "second line", "--cluster", "PLUGIN_MODE")...)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tok.AccessToken != "exec-tok-marker" || tok.Principal != "plug" || tok.Kind != KindKube || !tok.Expiry.Equal(tc.wantExp) {
				t.Fatalf("token = %v", tok)
			}
			if fe.name != "/opt/example/get-token" || !reflect.DeepEqual(fe.args, []string{"--cluster", "e1"}) {
				t.Errorf("ran %q %q", fe.name, fe.args)
			}
			found := false
			for _, kv := range fe.env {
				found = found || kv == "PLUGIN_MODE=test"
			}
			if !found {
				t.Error("plugin env from the kubeconfig not passed")
			}
			info := fe.execInfo(t)
			if info.APIVersion != tc.api || info.Kind != "ExecCredential" || info.Spec.Interactive || info.Spec.Cluster == nil ||
				info.Spec.Cluster.Server != "https://k8s.example.test:6443" || info.Spec.Cluster.CertificateAuthorityData != "Q0EtREFUQQ==" || info.Spec.Cluster.TLSServerName != "k8s.example.test" {
				t.Errorf("exec info = %+v", info)
			}
		})
	}
}

func TestKubeExecCommandPath(t *testing.T) {
	dir := t.TempDir()
	body := strings.Replace(execKubeconfig(kubeExecV1, ""), "/opt/example/get-token", "CMD", 1)
	ok := answer(kubeExecV1, map[string]any{"token": "exec-tok-marker"})
	tests := []struct {
		name, cmd, want string
		mode            os.FileMode
		wantErr         string
	}{
		{name: "relative with a slash", cmd: "./bin/get-token", want: filepath.Join(dir, "bin", "get-token"), mode: 0o600},
		{name: "bare name uses PATH", cmd: "get-token", want: "get-token", mode: 0o600},
		{name: "writable kubeconfig refused", cmd: "./bin/get-token", mode: 0o666, wantErr: "is writable by other users, so it is not run"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr != "" && runtime.GOOS == "windows" {
				t.Skip("mode bits do not apply on Windows")
			}
			cfg := writeFile(t, dir, "config", strings.Replace(body, "CMD", tc.cmd, 1))
			if err := os.Chmod(cfg, tc.mode); err != nil {
				t.Fatal(err)
			}
			fe := &fakeExec{fn: ok}
			_, err := KubeLogin(context.Background(), KubeOptions{Kubeconfig: cfg, Env: emptyEnv, RunExec: fe.run})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || fe.calls != 0 {
					t.Fatalf("err = %v, runs %d", err, fe.calls)
				}
				return
			}
			if err != nil || fe.name != tc.want {
				t.Fatalf("ran %q, err %v", fe.name, err)
			}
		})
	}
}

func TestKubeSource(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	st := newMemStore()

	// Exec: kept until refreshSkew before expiry, then run again.
	fe := &fakeExec{fn: func(_ context.Context, n int) ([]byte, error) {
		return answer(kubeExecV1, map[string]any{"token": "exec-tok-" + string(rune('0'+n)), "expirationTimestamp": clk.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})(nil, n)
	}}
	cfg := writeFile(t, dir, "exec", execKubeconfig(kubeExecV1, ""))
	src := NewSource("k", Context{AdminURL: "https://admin.example.test", Kube: true}, st, SourceOptions{Kube: &KubeOptions{Kubeconfig: cfg, Env: emptyEnv, RunExec: fe.run}, Now: clk.Now})
	step := func(advance time.Duration, want string, runs int) {
		t.Helper()
		clk.Add(advance)
		got, err := src.Token(context.Background())
		if err != nil || got != want || fe.calls != runs {
			t.Fatalf("after +%s: %q runs %d, err %v; want %q runs %d", advance, got, fe.calls, err, want, runs)
		}
	}
	step(0, "exec-tok-1", 1)
	step(time.Minute, "exec-tok-1", 1)
	step(7*time.Minute, "exec-tok-1", 1)
	step(time.Minute+time.Second, "exec-tok-2", 2)
	cur, err := src.Current(context.Background())
	if err != nil || cur.Kind != KindKube || cur.Principal != "plug" || cur.AccessToken != "exec-tok-2" || fe.calls != 2 {
		t.Fatalf("Current = %v, %v", cur, err)
	}

	// tokenFile: read on every call.
	tf := writeFile(t, dir, "tok.txt", "file-tok-1")
	fcfg := writeFile(t, dir, "file", "current-context: f\ncontexts:\n- {name: f, context: {user: fu}}\nusers:\n- {name: fu, user: {tokenFile: "+tf+"}}\n")
	fsrc := NewSource("k", Context{}, st, SourceOptions{Kube: &KubeOptions{Kubeconfig: fcfg, Env: emptyEnv}, Now: clk.Now})
	for _, want := range []string{"file-tok-1", "file-tok-2"} {
		writeFile(t, dir, "tok.txt", want)
		if got, err := fsrc.Token(context.Background()); err != nil || got != want {
			t.Fatalf("tokenFile: %q %v, want %q", got, err, want)
		}
	}

	// Static token without expiry: kept 5 minutes.
	scfg := writeFile(t, dir, "static", "current-context: s\ncontexts:\n- {name: s, context: {user: su}}\nusers:\n- {name: su, user: {token: static-1}}\n")
	ssrc := NewSource("k", Context{}, st, SourceOptions{Kube: &KubeOptions{Kubeconfig: scfg, Env: emptyEnv}, Now: clk.Now})
	sget := func(want string) {
		t.Helper()
		if got, err := ssrc.Token(context.Background()); err != nil || got != want {
			t.Fatalf("static: %q %v, want %q", got, err, want)
		}
	}
	sget("static-1")
	writeFile(t, dir, "static", "current-context: s\ncontexts:\n- {name: s, context: {user: su}}\nusers:\n- {name: su, user: {token: static-2}}\n")
	clk.Add(4 * time.Minute)
	sget("static-1")
	clk.Add(time.Minute + time.Second)
	sget("static-2")

	// A failure is returned and nothing stale is kept.
	if err := os.Remove(scfg); err != nil {
		t.Fatal(err)
	}
	clk.Add(6 * time.Minute)
	if _, err := ssrc.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("removed kubeconfig: %v", err)
	}
	if st.loads != 0 || st.saves != 0 || st.deletes != 0 {
		t.Fatalf("kube mode used the store: %d %d %d", st.loads, st.saves, st.deletes)
	}
}

func TestStderrLine(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"\n\n  error: denied  \nnext", "error: denied"},
		{"token eyJhbGciOi.x.y here", "token [hidden] here"},
		{"key ABCDEFGHIJKLMNOPQRSTUVWXYZ_- end", "key [hidden] end"},
		{"short abc-123 stays", "short abc-123 stays"},
	}
	for _, tc := range tests {
		if got := stderrLine(tc.in); got != tc.want {
			t.Errorf("stderrLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
