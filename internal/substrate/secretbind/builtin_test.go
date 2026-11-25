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

package secretbind

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
)

func TestB1TemplateCovers(t *testing.T) {
	exact := Template{Hosts: []string{"gitlab.com"}}
	wild := Template{Hosts: []string{"*.corp.example"}}
	none := Template{}
	cases := []struct {
		tpl  Template
		host string
		want bool
	}{
		{exact, "gitlab.com", true},
		{exact, "GitLab.com", true},
		{exact, "git.gitlab.com", false},
		{exact, "*.gitlab.com", false},
		{exact, "*", false},
		{wild, "git.corp.example", true},
		{wild, "a.b.corp.example", false}, // one label only
		{wild, "corp.example", false},
		{wild, "*.corp.example", true},
		{wild, "*.x.corp.example", false},
		{wild, "evilcorp.example", false},
		{none, "gitlab.com", false},
		{exact, "not a host", false},
	}
	for _, c := range cases {
		if got := c.tpl.Covers(c.host); got != c.want {
			t.Errorf("%v.Covers(%q) = %v, want %v", c.tpl.Hosts, c.host, got, c.want)
		}
	}
	// The generic built-ins cover no host, so every use is an admin ask.
	for _, name := range []string{"generic-bearer", "generic-basic"} {
		g, ok := Find(Builtin(), name)
		if !ok || g.Covers("api.example.com") {
			t.Fatalf("%s: found=%v, covers a host", name, ok)
		}
	}
}

func TestB1CatalogOverride(t *testing.T) {
	if got := Catalog(nil); len(got) != 7 {
		t.Fatalf("no admin list: %d templates, want the 7 built-ins", len(got))
	}
	cat := Catalog([]config.SubstrateSecretTemplate{
		{Name: "gitlab", Hosts: []string{"*.corp.example"}, Profiles: []string{"eng-*"}},
		{Name: "jira", Hosts: []string{"jira.corp.example"}},
	})
	if len(cat) != 2 {
		t.Fatalf("admin list replaces the built-ins: got %d", len(cat))
	}
	gl, _ := Find(cat, "gitlab")
	if gl.Form != FormBasic || gl.BasicUser != "oauth2" || gl.Header != "Authorization" {
		t.Fatalf("gitlab override lost the built-in's unset fields: %+v", gl)
	}
	if gl.Covers("gitlab.com") || !gl.Covers("git.corp.example") {
		t.Fatalf("gitlab override hosts not taken: %v", gl.Hosts)
	}
	if !gl.ForProfile("eng-web") || gl.ForProfile("sales") {
		t.Fatalf("profiles not taken: %v", gl.Profiles)
	}
	j, _ := Find(cat, "jira")
	if j.Form != FormBearer || j.Prefix() != "Bearer " || !j.ForProfile("anyone") {
		t.Fatalf("new admin template defaults wrong: %+v", j)
	}
	if _, ok := Find(cat, "github"); ok {
		t.Fatal("a built-in the admin did not list is still in the catalog")
	}
}

func TestB1SecretsActiveUnexpiredOnly(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	b := func(id string, st State, exp time.Time, tpl string) Binding {
		return Binding{ID: id, Name: "n" + id, Owner: "k1", Template: tpl, Hosts: []string{"gitlab.com"}, State: st, Expires: exp}
	}
	in := []Binding{
		b("a", Active, time.Time{}, "gitlab"),
		b("b", Waiting, time.Time{}, "gitlab"),
		b("c", Active, now.Add(-time.Minute), "gitlab"),
		b("d", Active, now.Add(time.Hour), "gitlab"),
		b("e", Active, time.Time{}, "gone"),
		b("f", Denied, time.Time{}, "gitlab"),
	}
	out := Secrets(Builtin(), "k8s-provider", "defenseclaw-user-secrets", in, false, now)
	var names []string
	for _, s := range out {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "na,nd" {
		t.Fatalf("rendered %v, want only the active unexpired bindings na,nd", names)
	}
	s := out[0]
	if s.Scope != egressspec.ScopePerPerson || s.Inject.Prefix != "Basic " || s.Inject.Header != "Authorization" {
		t.Fatalf("entry shape: %+v", s)
	}
	want := "ate-secret://k8s.io/k8s-provider/defenseclaw-user-secrets/dc-b-" + egressspec.PersonPlaceholder + "/a"
	if s.Source != want {
		t.Fatalf("source %q, want %q (keeps the person placeholder)", s.Source, want)
	}
}

func TestB1SecretForEchoNeedsBothSwitches(t *testing.T) {
	tpl, _ := Find(Builtin(), "generic-bearer")
	b := Binding{ID: "x", Name: "n", Hosts: []string{"httpbin.org"}, AllowEcho: true}
	if SecretFor(tpl, "p", "ns", b, false).Inject.AllowEcho {
		t.Fatal("binding allow_echo without allow_echo_bindings must not echo")
	}
	if !SecretFor(tpl, "p", "ns", b, true).Inject.AllowEcho {
		t.Fatal("both switches on: allow_echo expected")
	}
	b.AllowEcho = false
	if SecretFor(tpl, "p", "ns", b, true).Inject.AllowEcho {
		t.Fatal("allow_echo_bindings alone must not echo")
	}
}

func TestB1StoredValueBasicForm(t *testing.T) {
	cat := Catalog([]config.SubstrateSecretTemplate{{Name: "github"}, {Name: "generic-basic"}, {Name: "npm"}})
	gh, _ := Find(cat, "github")
	gb, _ := Find(cat, "generic-basic")
	npm, _ := Find(cat, "npm")
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, c := range []struct {
		name  string
		t     Template
		user  string
		want  string
		fails bool
	}{
		{"template user", gh, "", b64("x-access-token:tok"), false},
		{"binding user wins", gh, "octo", b64("octo:tok"), false},
		{"generic-basic needs a user", gb, "", "", true},
		{"generic-basic with a user", gb, "svc", b64("svc:tok"), false},
		{"user with a colon", gb, "a:b", "", true},
		{"bearer stores the token", npm, "", "tok", false},
	} {
		got, err := c.t.StoredValue(Binding{BasicUser: c.user}, "tok")
		if (err != nil) != c.fails || got != c.want {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
	b := Binding{ID: "b-0123456789", Name: "n", Owner: "owner-key-1", Template: "generic-basic", Hosts: []string{"a.example"},
		State: Active, Created: time.Now(), BasicUser: "a b"}
	if b.Check() == nil {
		t.Fatal("Check accepted a basic_user with a space")
	}
	b.BasicUser = "svc-ci@corp"
	if err := b.Check(); err != nil {
		t.Fatalf("Check refused %q: %v", b.BasicUser, err)
	}
}

// TestB1SecretsNarrowedTemplateRV3P22: an administrator narrows a template
// after bindings were made under it. A binding nobody approved keeps only
// the hosts the template covers now (none left: not rendered); a binding an
// administrator approved through an ask keeps its host.
func TestB1SecretsNarrowedTemplateRV3P22(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	catalog := Catalog([]config.SubstrateSecretTemplate{{Name: "github", Hosts: []string{"github.com"}}})
	in := []Binding{
		{ID: "a", Name: "api-only", Owner: "k1", Template: "github", Hosts: []string{"api.github.com"}, State: Active},
		{ID: "b", Name: "both", Owner: "k1", Template: "github", Hosts: []string{"github.com", "api.github.com"}, State: Active},
		{ID: "c", Name: "approved", Owner: "k1", Template: "github", Hosts: []string{"api.github.com"}, State: Active, AskID: "A-1"},
	}
	got := map[string][]string{}
	for _, s := range Secrets(catalog, "p", "ns", in, false, now) {
		got[s.Name] = s.Inject.Hosts
	}
	want := map[string][]string{"both": {"github.com"}, "approved": {"api.github.com"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rendered %v, want %v", got, want)
	}
	if in[1].Hosts[1] != "api.github.com" {
		t.Fatalf("Secrets changed its input: %v", in[1].Hosts)
	}
}

// TestStoredValueHeaderCapRV3P42: the stored form fits the proxy's header
// limit; a basic token is capped after its base64 growth.
func TestStoredValueHeaderCapRV3P42(t *testing.T) {
	bearer := Template{Name: "b", Form: FormBearer}
	basic := Template{Name: "c", Form: FormBasic, BasicUser: "x-token-auth"}
	cases := []struct {
		t    Template
		n    int
		want bool
	}{
		{bearer, MaxStoredValue, true}, {bearer, MaxStoredValue + 1, false},
		{basic, 40 << 10, true}, {basic, 43 << 10, false},
	}
	for _, c := range cases {
		_, err := c.t.StoredValue(Binding{}, strings.Repeat("a", c.n))
		if (err == nil) != c.want {
			t.Errorf("%s %d: %v", c.t.Form, c.n, err)
		}
	}
}
