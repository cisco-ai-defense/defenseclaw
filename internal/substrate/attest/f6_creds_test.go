// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// authLog is a registry that challenges and records every Authorization
// header it sees, in order.
type authLog struct {
	mu   sync.Mutex
	seen []string
	srv  *httptest.Server
}

func newAuthLog(t *testing.T, challenge func(host string) string, ok func(auth string) bool) *authLog {
	t.Helper()
	a := &authLog{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		a.mu.Lock()
		a.seen = append(a.seen, auth)
		a.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"token":"tok"}`))
			return
		}
		if ok(auth) {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		w.Header().Set("Www-Authenticate", challenge(strings.TrimPrefix(a.srv.URL, "http://")))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *authLog) host() string { return strings.TrimPrefix(a.srv.URL, "http://") }

func (a *authLog) log() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

func basicOf(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestGAP0052CredentialsPerHost(t *testing.T) {
	const pw = "MARKER-PASSWORD-f6"
	basicChallenge := func(string) string { return `Basic realm="r"` }
	wantBasic := func(auth string) bool { return auth == basicOf("svc", pw) }

	t.Run("a host with no credential never gets one", func(t *testing.T) {
		home := newAuthLog(t, basicChallenge, wantBasic)
		other := newAuthLog(t, basicChallenge, wantBasic)
		reg := NewRegistry(RegistryOptions{Credentials: map[string]Credential{home.host(): {Username: "svc", Password: pw}}})
		_, _, _, err := reg.Manifest(context.Background(), Ref{Registry: other.host(), Repo: "a/b", Tag: "t"})
		if err == nil {
			t.Fatal("the challenge of a host without a login must fail")
		}
		for _, h := range other.log() {
			if h != "" {
				t.Fatalf("a host with no credential got %q", h)
			}
		}
	})
	t.Run("Basic only after the host's own challenge", func(t *testing.T) {
		home := newAuthLog(t, basicChallenge, wantBasic)
		reg := NewRegistry(RegistryOptions{Credentials: map[string]Credential{home.host(): {Username: "svc", Password: pw}}})
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		got := home.log()
		if len(got) != 2 || got[0] != "" || got[1] != basicOf("svc", pw) {
			t.Fatalf("want no auth, then Basic after the challenge: %q", got)
		}
		// Once asked, the host gets it up front (a streamed upload cannot be
		// replayed after a challenge).
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "u"})
		if got := home.log(); len(got) != 3 || got[2] != basicOf("svc", pw) {
			t.Fatalf("second call: %q", got)
		}
	})
	t.Run("a Bearer realm on the registry itself gets the login", func(t *testing.T) {
		home := newAuthLog(t, func(h string) string { return `Bearer realm="http://` + h + `/token",service="s"` },
			func(auth string) bool { return auth == "Bearer tok" })
		reg := NewRegistry(RegistryOptions{Credentials: map[string]Credential{home.host(): {Username: "svc", Password: pw}}})
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		got := home.log()
		if len(got) != 3 || got[0] != "" || got[1] != basicOf("svc", pw) || got[2] != "Bearer tok" {
			t.Fatalf("want anonymous, Basic to the token path, then the token: %q", got)
		}
	})
	t.Run("a Bearer realm on a listed token host gets it, an unlisted one does not", func(t *testing.T) {
		tokens := newAuthLog(t, basicChallenge, func(string) bool { return true })
		home := newAuthLog(t, func(string) string { return `Bearer realm="http://` + tokens.host() + `/token"` },
			func(auth string) bool { return auth == "Bearer tok" })
		reg := NewRegistry(RegistryOptions{Credentials: map[string]Credential{home.host(): {Username: "svc", Password: pw}}})
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		if got := tokens.log(); len(got) != 1 || got[0] != "" {
			t.Fatalf("an unlisted realm got %q", got)
		}
		reg = NewRegistry(RegistryOptions{Credentials: map[string]Credential{home.host(): {Username: "svc", Password: pw, TokenHosts: []string{tokens.host()}}}})
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		if got := tokens.log(); len(got) != 2 || got[1] != basicOf("svc", pw) {
			t.Fatalf("a listed realm should get the login: %q", got)
		}
	})
}
