// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// mapSource is a CredentialSource over a map, counting lookups per host.
type mapSource struct {
	logins map[string]Credential
	err    map[string]error
	asked  map[string]int
}

func (m *mapSource) Credential(_ context.Context, host string) (Credential, bool, error) {
	if m.asked == nil {
		m.asked = map[string]int{}
	}
	m.asked[host]++
	if err := m.err[host]; err != nil {
		return Credential{}, false, err
	}
	c, ok := m.logins[host]
	return c, ok, nil
}

// GAP-0190: a Source gives a login per host with the GAP-0052 rules: only
// the host it is for gets it, only after that host's challenge, and a
// token service the login does not name gets nothing.
func TestGAP0190SourceLoginsArePerHost(t *testing.T) {
	const pw = "MARKER-PASSWORD-f11"
	basicChallenge := func(string) string { return `Basic realm="r"` }
	wantBasic := func(auth string) bool { return auth == basicOf("svc", pw) }

	t.Run("the host the login is for gets it after its challenge", func(t *testing.T) {
		home := newAuthLog(t, basicChallenge, wantBasic)
		src := &mapSource{logins: map[string]Credential{home.host(): {Username: "svc", Password: pw}}}
		reg := NewRegistry(RegistryOptions{Source: src})
		_, _, _, err := reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("with the login the registry answers 404, got %v", err)
		}
		if got := home.log(); len(got) != 2 || got[0] != "" || got[1] != basicOf("svc", pw) {
			t.Fatalf("want no auth, then Basic after the challenge: %q", got)
		}
	})
	t.Run("another registry gets none", func(t *testing.T) {
		home := newAuthLog(t, basicChallenge, wantBasic)
		other := newAuthLog(t, basicChallenge, wantBasic)
		src := &mapSource{logins: map[string]Credential{home.host(): {Username: "svc", Password: pw}}}
		reg := NewRegistry(RegistryOptions{Source: src})
		if _, _, _, err := reg.Manifest(context.Background(), Ref{Registry: other.host(), Repo: "a/b", Tag: "t"}); err == nil {
			t.Fatal("the challenge of a host without a login must fail")
		}
		for _, h := range other.log() {
			if h != "" {
				t.Fatalf("a registry the login is not for got %q", h)
			}
		}
	})
	t.Run("a Bearer realm on another host gets none", func(t *testing.T) {
		tokens := newAuthLog(t, basicChallenge, func(string) bool { return true })
		home := newAuthLog(t, func(string) string { return `Bearer realm="http://` + tokens.host() + `/token"` },
			func(auth string) bool { return auth == "Bearer tok" })
		src := &mapSource{logins: map[string]Credential{home.host(): {Username: "svc", Password: pw}}}
		reg := NewRegistry(RegistryOptions{Source: src})
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		if got := tokens.log(); len(got) != 1 || got[0] != "" {
			t.Fatalf("a token service the login does not name got %q", got)
		}
	})
	t.Run("the static map wins and the source is not asked for its hosts", func(t *testing.T) {
		home := newAuthLog(t, basicChallenge, wantBasic)
		src := &mapSource{logins: map[string]Credential{home.host(): {Username: "wrong", Password: "wrong"}}}
		reg := NewRegistry(RegistryOptions{Credentials: map[string]Credential{home.host(): {Username: "svc", Password: pw}}, Source: src})
		_, _, _, _ = reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		if src.asked[home.host()] != 0 {
			t.Fatal("the source was asked for a host the static map names")
		}
		if got := home.log(); len(got) != 2 || got[1] != basicOf("svc", pw) {
			t.Fatalf("want the static login: %q", got)
		}
	})
	t.Run("a failing source fails the call, never anonymous", func(t *testing.T) {
		home := newAuthLog(t, basicChallenge, wantBasic)
		src := &mapSource{err: map[string]error{home.host(): errors.New("token service down")}}
		reg := NewRegistry(RegistryOptions{Source: src})
		_, _, _, err := reg.Manifest(context.Background(), Ref{Registry: home.host(), Repo: "a/b", Tag: "t"})
		if err == nil || !strings.Contains(err.Error(), "login for") {
			t.Fatalf("want a login error, got %v", err)
		}
		if got := home.log(); len(got) != 0 {
			t.Fatalf("the registry was called without its login: %q", got)
		}
	})
}

// GAP-0190: a login printed by mistake shows no password.
func TestGAP0190CredentialPrintsNoPassword(t *testing.T) {
	const pw = "MARKER-PASSWORD-f11"
	c := Credential{Username: "AWS", Password: pw}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(f, c); strings.Contains(s, pw) {
			t.Fatalf("%s printed the password: %s", f, s)
		}
	}
	if s := fmt.Sprintf("%v", map[string]Credential{"h": c}); strings.Contains(s, pw) {
		t.Fatalf("a map of logins printed the password: %s", s)
	}
}
