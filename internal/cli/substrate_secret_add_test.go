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

package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// addAdmin answers POST secrets with code and records each request body.
func addAdmin(t *testing.T, code int, reply string) *[]map[string]any {
	t.Helper()
	var got []map[string]any
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST secrets": func(w http.ResponseWriter, r *http.Request) {
			in := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&in)
			got = append(got, in)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(reply))
		},
	}})
	return &got
}

func TestB1SecretsAddStoredAndWaiting(t *testing.T) {
	t.Setenv("B1_TOK", "glpat-plain")
	got := addAdmin(t, http.StatusCreated, `{"name":"gl-work","id":"b-0123456789","template":"gitlab","host":"git.corp.example","status":"set"}`)
	out, errOut, err := runSubstrate(t, newSubstrateSecretsAddCmd(), "gl-work", "--template", "gitlab", "--host", "git.corp.example",
		"--from-env", "B1_TOK", "--expires", "90d")
	if err != nil {
		t.Fatalf("add: %v %s", err, errOut)
	}
	want := "Stored gl-work for git.corp.example (template gitlab). Your agents use it from their next request.\n" +
		"Check it with: defenseclaw substrate secrets test gl-work\n"
	if out != want {
		t.Fatalf("stdout %q, want %q", out, want)
	}
	if len(*got) != 1 {
		t.Fatalf("requests: %v", *got)
	}
	req := (*got)[0]
	// The CLI sends the plain token; the gateway forms the basic credential.
	if req["value"] != "glpat-plain" || req["template"] != "gitlab" || req["host"] != "git.corp.example" || req["user"] != nil {
		t.Fatalf("request %v", req)
	}
	exp, _ := time.Parse(time.RFC3339, req["expires"].(string))
	if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("expires %v", req["expires"])
	}
	if strings.Contains(out+errOut, "glpat-plain") {
		t.Fatal("value printed")
	}

	t.Setenv("B1_TOK", "tok")
	got = addAdmin(t, http.StatusAccepted, `{"name":"nexus","id":"b-0123456789","template":"generic-basic","host":"nexus.corp.example","status":"waiting on admin","reason":"secret_binding_outside_templates"}`)
	out, errOut, err = runSubstrate(t, newSubstrateSecretsAddCmd(), "nexus", "--template", "generic-basic", "--host", "nexus.corp.example",
		"--user", "ci-bot", "--from-env", "B1_TOK")
	if err != nil {
		t.Fatalf("add waiting: %v %s", err, errOut)
	}
	want = "nexus.corp.example is not covered by the generic-basic template, so an administrator must approve it.\n" +
		"Your value is stored and is not used until then. See it with: defenseclaw substrate approvals\n"
	if out != want {
		t.Fatalf("stdout %q, want %q", out, want)
	}
	if req := (*got)[0]; req["user"] != "ci-bot" || req["value"] != "tok" || req["expires"] != nil {
		t.Fatalf("request %v", req)
	}
}

func TestB1SecretsAddRefusesBeforeSending(t *testing.T) {
	t.Setenv("B1_TOK", "v")
	got := addAdmin(t, http.StatusCreated, `{}`)
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"upper-case name", []string{"GL_WORK", "--template", "gitlab", "--host", "gitlab.com"}, "is not a secret name"},
		{"user with a colon", []string{"nx", "--template", "generic-basic", "--host", "a.example", "--user", "a:b"}, "colon or a space"},
		{"bad expiry", []string{"nx", "--template", "gitlab", "--host", "gitlab.com", "--expires", "soon"}, "--expires"},
		{"past date", []string{"nx", "--template", "gitlab", "--host", "gitlab.com", "--expires", "2020-01-01"}, "--expires"},
		{"no template", []string{"nx", "--host", "gitlab.com"}, "template"},
		{"no host", []string{"nx", "--template", "gitlab"}, "host"},
		{"two sources", []string{"nx", "--template", "gitlab", "--host", "gitlab.com", "--stdin"}, "use one source"},
	} {
		_, _, err := runSubstrate(t, newSubstrateSecretsAddCmd(), append(c.args, "--from-env", "B1_TOK")...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if len(*got) != 0 {
		t.Fatalf("a refused add reached the gateway: %v", *got)
	}
}

func TestB1SecretsTemplates(t *testing.T) {
	reply := `{"mode":"bindings","templates":[
		{"name":"github","hosts":["github.com","api.github.com"],"header":"Authorization","form":"basic","basic_user":"x-access-token"},
		{"name":"generic-basic","hosts":[],"header":"Authorization","form":"basic"},
		{"name":"npm","hosts":["registry.npmjs.org"],"header":"Authorization","form":"bearer"}]}`
	serve := func(body string) {
		useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
			"GET secret-templates": func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			},
		}})
	}
	serve(reply)
	out, _, err := runSubstrate(t, newSubstrateSecretsTemplatesCmd())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"NAME", "HOSTS", "HEADER", "github.com,api.github.com", "Authorization: Basic x-access-token:<token>",
		"(each host needs an admin)", "Authorization: Basic <--user>:<token>", "Authorization: Bearer <token>"} {
		if !strings.Contains(out, s) {
			t.Errorf("templates output lacks %q:\n%s", s, out)
		}
	}
	out, _, err = runSubstrate(t, newSubstrateSecretsTemplatesCmd(), "--json")
	if err != nil || !strings.Contains(out, `"mode": "bindings"`) || !strings.Contains(out, `"basic_user": "x-access-token"`) {
		t.Fatalf("json: %v\n%s", err, out)
	}
	serve(`{"mode":"values_only","templates":[]}`)
	out, _, err = runSubstrate(t, newSubstrateSecretsTemplatesCmd())
	if err != nil || !strings.Contains(out, "allows values only") {
		t.Fatalf("values_only: %v %q", err, out)
	}
}

func TestB1ParseExpiry(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		in   string
		want time.Time
		bad  bool
	}{
		{"", time.Time{}, false},
		{"90d", now.Add(90 * 24 * time.Hour), false},
		{"12h", now.Add(12 * time.Hour), false},
		{"2027-01-31", time.Date(2027, 1, 31, 23, 59, 59, 0, time.UTC), false},
		{"0d", time.Time{}, true},
		{"401d", time.Time{}, true},
		{"d", time.Time{}, true},
		{"2026-11-01", time.Time{}, true},
		{"tomorrow", time.Time{}, true},
	} {
		got, err := substrateParseExpiry(c.in, now)
		if (err != nil) != c.bad || !got.Equal(c.want) {
			t.Errorf("%q: %v %v", c.in, got, err)
		}
	}
}
